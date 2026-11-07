"""Realm KHÁCH (cổng khách hàng P1) — docs KIEN_TRUC_P1 §3, §4, §11.

Chỉ dữ liệu tổng hợp: SĐT +8490000000x, email @example.test.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import subprocess
import time
from urllib.parse import parse_qs, urlsplit

import pytest
from fastapi.testclient import TestClient

from cowork import config, db, khach
from cowork.main import app

from conftest import csrf_tu, dang_nhap as dang_nhap_nv

HOST_KHACH = "http://khach.localhost:8898"
MK = "Khach!Passw0rd-12"
MK_MOI = "Moi!Passw0rd-3456"


# ------------------------------------------------------------------ fixture
@pytest.fixture()
def crm(monkeypatch):
    """CRM giả: ghi lại mọi lần gọi; `crm.song=False` mô phỏng CRM không truy cập được."""
    class _CRM:
        song = True
        goi: list[dict] = []

    c = _CRM()
    c.goi = []

    def _post(url, body, headers):
        if not c.song:
            raise ConnectionError("CRM không truy cập được")
        c.goi.append({"url": url, "body": json.loads(body), "headers": dict(headers),
                      "raw": body})
        return 200, "ok"

    monkeypatch.setattr(khach, "_http_post", _post)
    return c


@pytest.fixture()
def bat(monkeypatch):
    monkeypatch.setattr(config, "KHACH_ENABLED", True)
    monkeypatch.setattr(config, "KHACH_HOSTS", ["khach.localhost:8898", "khach.localhost"])
    monkeypatch.setattr(config, "CRM_PORTAL_PUBLIC_URL", "http://crm.localhost:8897")
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL", "http://127.0.0.1:8897")
    monkeypatch.setattr(config, "KHACH_PUBLIC_URL", HOST_KHACH)


@pytest.fixture()
def kh(client, bat, crm):
    """TestClient trên host khách (realm bật). `client` là host nhân viên (testserver)."""
    return TestClient(app, base_url=HOST_KHACH)


def _ip(monkeypatch):
    monkeypatch.setattr(config, "TIN_PROXY", True)


# ------------------------------------------------------------------ trợ giúp
def _csrf(c: TestClient, path: str) -> str:
    r = c.get(path)
    assert r.status_code == 200, r.text[:300]
    return csrf_tu(r.text)


def dang_ky(c: TestClient, n: int = 1, *, email: str | None = None, sdt: str | None = None,
            mk: str = MK, mk2: str | None = None, dong_y: bool = True, headers=None):
    data = {"ho_ten": f"Khách Thử {n}", "sdt": sdt or f"090000000{n}",
            "email": email or f"khach{n}@example.test", "mat_khau": mk,
            "mat_khau_2": mk if mk2 is None else mk2, "_csrf": _csrf(c, "/tai-khoan/dang-ky")}
    if dong_y:
        data["dong_y"] = "1"
    return c.post("/tai-khoan/dang-ky", data=data, follow_redirects=False, headers=headers or {})


def outbox(kind: str | None = None, to: str | None = None) -> list[dict]:
    conn = db.connect()
    try:
        sql, p = "SELECT * FROM customer_outbox WHERE 1=1", []
        if kind:
            sql += " AND kind=?"
            p.append(kind)
        if to:
            sql += " AND to_email=?"
            p.append(to)
        return db.q(conn, sql + " ORDER BY id", p)
    finally:
        conn.close()


def token_tu(body: str, path: str) -> str:
    m = re.search(re.escape(path) + r"\?t=([A-Za-z0-9_\-]+)", body)
    assert m, body
    return m.group(1)


def acc_theo_sdt(phone: str) -> dict | None:
    conn = db.connect()
    try:
        return db.one(conn, "SELECT * FROM customer_accounts WHERE phone_e164=?", (phone,))
    finally:
        conn.close()


_lech = [0]


def ky_vao(body: bytes, ts: int | None = None) -> dict:
    # Mỗi lần ký một ts khác (CRM thật cũng ký lại mỗi lần gửi); cùng (ts, body) = phát lại.
    if ts is None:
        _lech[0] = (_lech[0] + 1) % 250
        ts = int(time.time()) - _lech[0]
    h = khach.ky_portal(khach.HUONG_VAO, body, ts)
    return {**h, "Content-Type": "application/json"}


def goi_noi_bo(c: TestClient, path: str, payload: dict, ts: int | None = None, headers=None):
    body = json.dumps(payload).encode()
    return c.post(path, content=body, headers=headers or ky_vao(body, ts))


def duyet(c: TestClient, subject: str, n: int = 1, **extra):
    payload = {"subject": subject, "decision": "approved", "crm_customer_id": f"crm-uuid-{n}",
               "customer_code": f"KH-{n}", "portal_code": f"VG00000{n}",
               "phone_verified_by": "nv-duyet", **extra}
    return goi_noi_bo(c, "/api/internal/khach/ket-qua-duyet", payload)


def tao_khach_hoat_dong(c: TestClient, n: int = 1) -> dict:
    assert dang_ky(c, n).status_code == 303
    mail = outbox("kich_hoat_email", f"khach{n}@example.test")[-1]
    t = token_tu(mail["body_text"], "/tai-khoan/xac-minh-email")
    assert c.get(f"/tai-khoan/xac-minh-email?t={t}").status_code == 200
    acc = acc_theo_sdt(f"+8490000000{n}")
    assert acc["status"] == "cho_duyet"
    r = duyet(c, acc["subject"], n)
    assert r.status_code == 200, r.text
    return acc_theo_sdt(f"+8490000000{n}")


def dang_nhap(c: TestClient, dinh_danh: str, mk: str = MK, headers=None):
    return c.post("/tai-khoan/dang-nhap", data={
        "dinh_danh": dinh_danh, "mat_khau": mk, "_csrf": _csrf(c, "/tai-khoan/dang-nhap"),
    }, follow_redirects=False, headers=headers or {})


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def crm_xac_minh_launch(token: str, secret: str, now: float | None = None) -> dict:
    """Bản sao tối giản phần kiểm HS256 phía CRM (ver/aud/exp/iat/nonce)."""
    h, p, s = token.split(".")
    header = json.loads(_b64d(h))
    assert header == {"alg": "HS256", "typ": "JWT"}
    mong = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    assert hmac.compare_digest(mong, _b64d(s)), "chữ ký sai"
    claims = json.loads(_b64d(p))
    now = time.time() if now is None else now
    assert claims["ver"] == 1 and claims["aud"] == "vip-crm-portal"
    assert claims["exp"] - claims["iat"] <= 60
    assert claims["iat"] - 5 <= now < claims["exp"], "hết hạn"
    assert claims["sub"].startswith("cust:") and claims["nonce"]
    return claims


def token_launch(resp) -> str:
    assert resp.status_code == 303, resp.text[:300]
    loc = resp.headers["location"]
    assert loc.startswith("http://crm.localhost:8897/portal/auth/launch?token=")
    return parse_qs(urlsplit(loc).query)["token"][0]


# ------------------------------------------------------------------ cờ & tách host
def test_co_tat_moi_thu_404(client, crm):
    assert config.KHACH_ENABLED is False
    c = TestClient(app, base_url=HOST_KHACH)
    r = c.get("/tai-khoan/dang-ky")
    assert "Đăng ký cổng khách hàng" not in r.text
    assert c.post("/api/internal/khach/ket-qua-duyet", content=b"{}").status_code == 404
    assert client.post("/api/internal/khach/tam-khoa", content=b"{}").status_code == 404
    # Không có route khách nào trên app nhân viên.
    assert c.get("/tai-khoan/static/khach.css").status_code == 404


def test_host_khach_chan_moi_route_nhan_vien(kh, owner):
    for path in ("/", "/dang-nhap", "/ho-so", "/cai-dat", "/nhat-ky", "/brain", "/api/me",
                 "/api/health", "/static/app.css", "/ha-tang", "/tai-khoan/anh-thanh"):
        assert kh.get(path, follow_redirects=False).status_code == 404, path
    assert kh.post("/dang-nhap", data={"userId": "anh-thanh"}).status_code == 404
    assert kh.post("/api/internal/brain/consume", content=b"{}").status_code == 404
    assert kh.post("/api/internal/hatang/bao-cao", content=b"{}").status_code == 404
    # Realm khách hoạt động bình thường.
    assert kh.get("/tai-khoan/dang-ky").status_code == 200
    assert kh.get("/tai-khoan/static/khach.css").status_code == 200


def test_host_nhan_vien_khong_co_realm_khach(client, bat, crm, owner):
    # Trang khách không tồn tại trên host nhân viên (/tai-khoan là quản trị tài khoản nhân viên,
    # cần đăng nhập nhân viên).
    r = client.get("/tai-khoan/dang-ky", follow_redirects=False)
    assert r.status_code in (303, 404) and "Đăng ký cổng khách hàng" not in r.text
    assert client.post("/api/internal/khach/ket-qua-duyet", content=b"{}").status_code == 404
    assert client.get("/tai-khoan/static/khach.css").status_code == 404
    # Nhân viên vẫn dùng được realm của mình khi cờ khách bật.
    assert dang_nhap_nv(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    assert client.get("/tai-khoan").status_code == 200


def test_csp_chat_va_khong_inline_script(kh):
    r = kh.get("/tai-khoan/dang-ky")
    csp = r.headers["content-security-policy"]
    assert "script-src 'none'" in csp and "unsafe-inline" not in csp
    assert "form-action 'self' http://crm.localhost:8897" in csp
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "<script" not in r.text and "style=" not in r.text


# ------------------------------------------------------------------ đăng ký
def test_chuan_hoa_sdt_email():
    for raw in ("0900000001", "090 000 0001", "+84900000001", "84900000001", "0084900000001",
                "090.000.0001"):
        assert khach.chuan_hoa_sdt(raw) == "+84900000001", raw
    for bad in ("", "123", "0200000001", "+1900000001", "09000000012", "abc"):
        assert khach.chuan_hoa_sdt(bad) is None, bad
    assert khach.chuan_hoa_email("  KHACH1@Example.TEST ") == "khach1@example.test"
    assert khach.chuan_hoa_email("khong-hop-le") is None
    assert khach.chuan_hoa_portal_code(" vg000123 ") == "VG000123"
    assert khach.chuan_hoa_portal_code("VG12345") is None


def test_dang_ky_kiem_tra_du_lieu(kh):
    assert dang_ky(kh, mk="Ngan!1").status_code == 400                       # < 12 ký tự
    assert dang_ky(kh, mk="aaaaaaaaaaaaaa").status_code == 400               # 1 nhóm ký tự
    assert dang_ky(kh, mk2="Khac!Passw0rd-12").status_code == 400            # không khớp
    assert dang_ky(kh, dong_y=False).status_code == 400                       # chưa đồng ý
    assert dang_ky(kh, sdt="12345").status_code == 400
    assert dang_ky(kh, email="x@").status_code == 400
    # CSRF sai/thiếu.
    r = kh.post("/tai-khoan/dang-ky", data={"ho_ten": "A B", "sdt": "0900000001",
                                            "email": "a@example.test", "mat_khau": MK,
                                            "mat_khau_2": MK, "dong_y": "1", "_csrf": "sai"})
    assert r.status_code == 403
    assert acc_theo_sdt("+84900000001") is None
    r = dang_ky(kh, 1)
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/da-gui-email"
    acc = acc_theo_sdt("+84900000001")
    assert acc["status"] == "cho_xac_minh_email" and acc["subject"] == "cust:" + acc["id"]
    assert acc["id"].startswith("kh_") and len(acc["id"]) == 29
    assert acc["email_norm"] == "khach1@example.test" and acc["password_hash"] != MK


def test_dang_ky_khong_lo_tai_khoan(kh):
    r1 = dang_ky(kh, 1)
    trung_sdt = dang_ky(kh, 1, email="nguoi-khac@example.test")
    trung_email = dang_ky(kh, 2, email="khach1@example.test")
    for r in (trung_sdt, trung_email):
        assert r.status_code == r1.status_code == 303
        assert r.headers["location"] == r1.headers["location"]
    # Không tạo thêm tài khoản; không gửi gì tới email lạ.
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_accounts") == 1
    finally:
        conn.close()
    assert outbox(to="nguoi-khac@example.test") == []
    # Email cũ nhận tối đa một thông báo/giờ (ở đây: gửi lại link kích hoạt vì đang chờ xác minh).
    assert len(outbox(to="khach1@example.test")) <= 3


def test_dang_ky_trung_tai_khoan_da_kich_hoat_bao_email_cu(kh):
    tao_khach_hoat_dong(kh, 1)
    assert dang_ky(kh, 1, email="ke-gia@example.test").status_code == 303
    assert outbox("dang_ky_trung", "khach1@example.test")
    assert outbox(to="ke-gia@example.test") == []


def test_dang_ky_gioi_han_tan_suat_ip(kh):
    for n in range(1, config.KHACH_SIGNUP_IP_PER_HOUR + 1):
        assert dang_ky(kh, n).status_code == 303
    assert dang_ky(kh, 9).status_code == 429


def test_giai_phong_dang_ky_giu_cho_qua_han(kh):
    dang_ky(kh, 1, email="ke-giu-cho@example.test")
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_accounts SET created_at='2020-01-01T00:00:00+07:00'")
        conn.commit()
    finally:
        conn.close()
    dang_ky(kh, 1)  # chủ thật của SĐT
    acc = acc_theo_sdt("+84900000001")
    assert acc["email_norm"] == "khach1@example.test"


# ------------------------------------------------------------------ xác minh email
def test_token_email_mot_lan_va_het_han(kh, crm):
    dang_ky(kh, 1)
    mail = outbox("kich_hoat_email")[-1]
    t = token_tu(mail["body_text"], "/tai-khoan/xac-minh-email")
    conn = db.connect()
    try:
        # Chỉ lưu sha256.
        row = db.one(conn, "SELECT * FROM customer_tokens")
        assert row["token_hash"] == hashlib.sha256(t.encode()).hexdigest()
        assert t not in json.dumps(db.q(conn, "SELECT * FROM customer_tokens"))
    finally:
        conn.close()
    assert kh.get(f"/tai-khoan/xac-minh-email?t={t}").status_code == 200
    acc = acc_theo_sdt("+84900000001")
    assert acc["status"] == "cho_duyet" and acc["email_verified_at"]
    # Signup đã gửi sang CRM, ký HMAC đúng chiều.
    goi = crm.goi[-1]
    assert goi["url"] == "http://127.0.0.1:8897/api/internal/portal/signups"
    assert goi["body"] == {"subject": acc["subject"], "display_name": "Khách Thử 1",
                           "phone_e164": "+84900000001", "email": "khach1@example.test"}
    assert goi["headers"]["Idempotency-Key"] == "signup:" + acc["subject"]
    from cowork import security
    assert security.xac_thuc_hmac("vipid->crm", goi["headers"]["X-Portal-Ts"],
                                  goi["headers"]["X-Portal-Sig"], goi["raw"],
                                  secret=khach.portal_secret())
    # Dùng lại ⇒ không hợp lệ.
    assert kh.get(f"/tai-khoan/xac-minh-email?t={t}").status_code == 400
    # Token hết hạn.
    dang_ky(kh, 2)
    t2 = token_tu(outbox("kich_hoat_email", "khach2@example.test")[-1]["body_text"],
                  "/tai-khoan/xac-minh-email")
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_tokens SET expires_at='2020-01-01T00:00:00+07:00' "
                     "WHERE used_at IS NULL")
        conn.commit()
    finally:
        conn.close()
    assert kh.get(f"/tai-khoan/xac-minh-email?t={t2}").status_code == 400
    assert acc_theo_sdt("+84900000002")["status"] == "cho_xac_minh_email"
    assert kh.get("/tai-khoan/xac-minh-email?t=bia-dat").status_code == 400


def test_crm_loi_thi_xep_hang_va_thu_lai(kh, crm):
    crm.song = False
    dang_ky(kh, 1)
    t = token_tu(outbox("kich_hoat_email")[-1]["body_text"], "/tai-khoan/xac-minh-email")
    assert kh.get(f"/tai-khoan/xac-minh-email?t={t}").status_code == 200
    conn = db.connect()
    try:
        row = db.one(conn, "SELECT * FROM crm_sync_pending")
        assert row["done_at"] is None and row["attempts"] == 1 and row["last_error"]
        crm.song = True
        kq = khach.dong_bo_crm(conn, tat_ca=True)
        assert kq == {"thu": 1, "thanh_cong": 1, "con_lai": 0}
        # Chạy lại không gửi trùng (idempotent).
        assert khach.dong_bo_crm(conn, tat_ca=True)["thu"] == 0
        khach.xep_hang_crm(conn, "signup", row["idem_key"], row["subject"], row["path"], {})
        assert db.scalar(conn, "SELECT COUNT(*) FROM crm_sync_pending") == 1
    finally:
        conn.close()
    assert len(crm.goi) == 1


# ------------------------------------------------------------------ đăng nhập theo trạng thái
def test_khong_dang_nhap_truoc_xac_minh_va_truoc_duyet(kh):
    dang_ky(kh, 1)
    r = dang_nhap(kh, "0900000001")
    assert r.status_code == 403 and "chưa xác minh email" in r.text
    t = token_tu(outbox("kich_hoat_email")[-1]["body_text"], "/tai-khoan/xac-minh-email")
    kh.get(f"/tai-khoan/xac-minh-email?t={t}")
    r = dang_nhap(kh, "0900000001")
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    # Sai mật khẩu ở trạng thái chờ ⇒ thông báo chung, không lộ trạng thái.
    r = dang_nhap(kh, "0900000001", "Sai!Passw0rd-12")
    assert r.status_code == 401 and khach.THONG_BAO_SAI in r.text
    assert "vg_khach=" not in r.headers.get("set-cookie", "")


def test_khong_dang_nhap_khi_sdt_chua_xac_minh(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_accounts SET phone_verified_at=NULL WHERE id=?", (acc["id"],))
        conn.commit()
    finally:
        conn.close()
    r = dang_nhap(kh, "0900000001")
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    assert "vg_khach=" not in r.headers.get("set-cookie", "")


def test_tu_choi_va_tam_khoa_khong_dang_nhap(kh):
    dang_ky(kh, 1)
    t = token_tu(outbox("kich_hoat_email")[-1]["body_text"], "/tai-khoan/xac-minh-email")
    kh.get(f"/tai-khoan/xac-minh-email?t={t}")
    acc = acc_theo_sdt("+84900000001")
    r = goi_noi_bo(kh, "/api/internal/khach/ket-qua-duyet",
                   {"subject": acc["subject"], "decision": "rejected", "reason": "trùng"})
    assert r.status_code == 200 and r.json()["data"]["status"] == "tu_choi"
    r2 = goi_noi_bo(kh, "/api/internal/khach/ket-qua-duyet",
                    {"subject": acc["subject"], "decision": "rejected"})
    assert r2.status_code == 200 and r2.json()["data"]["idempotent"] is True
    assert duyet(kh, acc["subject"]).status_code == 409
    r = dang_nhap(kh, "0900000001")
    assert r.status_code == 403 and "launch" not in r.headers.get("location", "")

    acc2 = tao_khach_hoat_dong(kh, 2)
    assert token_launch(dang_nhap(kh, "VG000002"))
    r = goi_noi_bo(kh, "/api/internal/khach/tam-khoa",
                   {"subject": acc2["subject"], "action": "khoa", "reason": "nợ cước"})
    assert r.status_code == 200
    # Phiên cũ bị thu hồi.
    assert kh.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"] == \
        "/tai-khoan/dang-nhap"
    assert dang_nhap(kh, "0900000002").status_code == 403
    r = goi_noi_bo(kh, "/api/internal/khach/tam-khoa",
                   {"subject": acc2["subject"], "action": "mo_khoa"})
    assert r.json()["data"]["status"] == "hoat_dong"
    token_launch(dang_nhap(kh, "0900000002"))


# ------------------------------------------------------------------ launch token
def test_dang_nhap_phat_launch_token_hop_le(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    r = dang_nhap(kh, "090 000 0001")
    tok = token_launch(r)
    ck = r.headers["set-cookie"]
    assert "vg_khach=" in ck and "Path=/tai-khoan" in ck and "HttpOnly" in ck
    assert "samesite=lax" in ck.lower()
    claims = crm_xac_minh_launch(tok, khach.portal_secret())
    assert claims["sub"] == acc["subject"] and claims["crm_customer_id"] == "crm-uuid-1"
    assert claims["portal_code"] == "VG000001"
    assert set(claims) == {"ver", "aud", "sub", "crm_customer_id", "portal_code", "iat", "exp",
                           "nonce"}
    # Hết hạn sau ≤ 60 giây.
    with pytest.raises(AssertionError):
        crm_xac_minh_launch(tok, khach.portal_secret(), now=claims["iat"] + 61)
    # Sai bí mật ⇒ không xác minh được.
    with pytest.raises(AssertionError):
        crm_xac_minh_launch(tok, "bi-mat-khac-" * 4)
    # vao-cong phát token mới, nonce khác.
    nonces = {claims["nonce"]}
    for _ in range(3):
        t2 = token_launch(kh.get("/tai-khoan/vao-cong", follow_redirects=False))
        nonces.add(crm_xac_minh_launch(t2, khach.portal_secret())["nonce"])
    assert len(nonces) == 4
    # Đăng nhập bằng mã khách (không phân biệt hoa thường).
    token_launch(dang_nhap(kh, "vg000001"))


def test_vao_cong_can_phien(kh):
    assert kh.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"] == \
        "/tai-khoan/dang-nhap"


def test_secure_cookie_khi_https(kh):
    tao_khach_hoat_dong(kh, 1)
    r = dang_nhap(kh, "0900000001", headers={"x-forwarded-proto": "https"})
    assert "secure" in r.headers["set-cookie"].lower()


# ------------------------------------------------------------------ dò mật khẩu
def test_khoa_theo_cap_tai_khoan_ip(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    ke = {"x-real-ip": "203.0.113.9"}
    for _ in range(config.KHACH_LOGIN_MAX_FAIL):
        assert dang_nhap(kh, "0900000001", "Sai!Passw0rd-12", headers=ke).status_code == 401
    # Kẻ tấn công bị khoá — kể cả khi đoán đúng.
    r = dang_nhap(kh, "0900000001", MK, headers=ke)
    assert r.status_code == 429 and "launch" not in r.headers.get("location", "")
    # Chủ tài khoản ở IP khác vẫn đăng nhập được.
    token_launch(dang_nhap(kh, "0900000001", MK, headers={"x-real-ip": "198.51.100.7"}))
    # Tài khoản không tồn tại: hành vi y hệt (không lộ tài khoản).
    for _ in range(config.KHACH_LOGIN_MAX_FAIL):
        assert dang_nhap(kh, "0900000009", "Sai!Passw0rd-12", headers=ke).status_code == 401
    assert dang_nhap(kh, "0900000009", "Sai!Passw0rd-12", headers=ke).status_code == 429


def test_ke_la_nhieu_ip_khong_khoa_duoc_chu_tai_khoan(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    for i in range(40):  # 40 lần sai từ 10 IP khác nhau
        dang_nhap(kh, "VG000001", "Sai!Passw0rd-12", headers={"x-real-ip": f"203.0.113.{i % 10}"})
    conn = db.connect()
    try:
        cho = khach.thoi_gian_cho_lam_cham(conn, acc_theo_sdt("+84900000001")["id"])
        assert 0 < cho <= khach.LAM_CHAM_TOI_DA_GIAY  # chỉ làm chậm, không khoá dài
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE tenant_id='khach' "
                         "AND action='khach.canh_bao.do_mat_khau'") == 1
        # Giả lập đã qua thời gian làm chậm.
        conn.execute("UPDATE customer_login_attempts SET created_at=? WHERE success=0",
                     (khach._truoc(seconds=khach.LAM_CHAM_TOI_DA_GIAY + 1),))
        conn.commit()
    finally:
        conn.close()
    token_launch(dang_nhap(kh, "0900000001", MK, headers={"x-real-ip": "198.51.100.7"}))


def test_gioi_han_theo_ip(kh, monkeypatch):
    _ip(monkeypatch)
    monkeypatch.setattr(config, "KHACH_LOGIN_IP_MAX_FAIL", 6)
    tao_khach_hoat_dong(kh, 1)
    ip = {"x-real-ip": "203.0.113.50"}
    for n in range(6):  # rải nhiều tài khoản (password spraying)
        dang_nhap(kh, f"090000001{n}", "Sai!Passw0rd-12", headers=ip)
    assert dang_nhap(kh, "0900000001", MK, headers=ip).status_code == 429
    token_launch(dang_nhap(kh, "0900000001", MK, headers={"x-real-ip": "198.51.100.8"}))


def test_bam_gia_khi_khong_co_tai_khoan(kh, monkeypatch):
    goi = []
    from cowork import security
    orig = security.bam_gia
    monkeypatch.setattr(security, "bam_gia", lambda mk: (goi.append(1), orig(mk)))
    r = dang_nhap(kh, "0900000008", "Sai!Passw0rd-12")
    assert r.status_code == 401 and khach.THONG_BAO_SAI in r.text and goi


# ------------------------------------------------------------------ HMAC nội bộ
def test_hmac_tu_choi_chu_ky_sai_cu_va_phat_lai(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    path = "/api/internal/khach/tam-khoa"
    body = json.dumps({"subject": acc["subject"], "action": "khoa"}).encode()
    # Thiếu chữ ký / chữ ký sai / sai chiều.
    assert kh.post(path, content=body).status_code == 401
    h = ky_vao(body)
    assert kh.post(path, content=body, headers={**h, "X-Portal-Sig": "0" * 64}).status_code == 401
    sai_chieu = khach.ky_portal(khach.HUONG_RA, body)
    assert kh.post(path, content=body, headers=sai_chieu).status_code == 401
    # Sửa body sau khi ký.
    assert kh.post(path, content=body.replace(b"khoa", b"mo_khoa"), headers=h).status_code == 401
    # Cũ quá 300 giây.
    assert kh.post(path, content=body, headers=ky_vao(body, int(time.time()) - 301)).status_code == 401
    assert acc_theo_sdt("+84900000001")["status"] == "hoat_dong"
    # Hợp lệ một lần, phát lại bị chặn.
    assert kh.post(path, content=body, headers=h).status_code == 200
    r = kh.post(path, content=body, headers=h)
    assert r.status_code == 409 and r.json()["loi"]["ma"] == "PHAT_LAI"
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE action='khach.hmac.phat_lai'") == 1
    finally:
        conn.close()


def test_ket_qua_duyet_idempotent_va_kiem_du_lieu(kh):
    dang_ky(kh, 1)
    acc = acc_theo_sdt("+84900000001")
    # Chưa xác minh email ⇒ không duyệt được.
    assert duyet(kh, acc["subject"]).status_code == 409
    t = token_tu(outbox("kich_hoat_email")[-1]["body_text"], "/tai-khoan/xac-minh-email")
    kh.get(f"/tai-khoan/xac-minh-email?t={t}")
    assert duyet(kh, acc["subject"], portal_code="ABC").status_code == 400
    assert duyet(kh, acc["subject"], phone_verified_by="").status_code == 400
    assert duyet(kh, "cust:khong-co").status_code == 404
    assert duyet(kh, acc["subject"]).status_code == 200
    a = acc_theo_sdt("+84900000001")
    assert a["status"] == "hoat_dong" and a["phone_verified_by"] == "nv-duyet"
    assert a["phone_verified_at"] and a["crm_customer_id"] == "crm-uuid-1"
    assert a["portal_code"] == "VG000001" and a["customer_code"] == "KH-1"
    r = duyet(kh, acc["subject"])
    assert r.status_code == 200 and r.json()["data"]["idempotent"] is True
    assert len(outbox("kich_hoat_xong")) == 1
    # Duyệt lại với hồ sơ CRM khác ⇒ xung đột.
    assert duyet(kh, acc["subject"], crm_customer_id="crm-khac").status_code == 409
    # portal_code đã dùng cho tài khoản khác ⇒ xung đột.
    dang_ky(kh, 2)
    t = token_tu(outbox("kich_hoat_email", "khach2@example.test")[-1]["body_text"],
                 "/tai-khoan/xac-minh-email")
    kh.get(f"/tai-khoan/xac-minh-email?t={t}")
    acc2 = acc_theo_sdt("+84900000002")
    assert duyet(kh, acc2["subject"], 2, portal_code="VG000001").status_code == 409


# ------------------------------------------------------------------ đăng xuất / khôi phục
def test_dang_xuat_thu_hoi_va_bao_crm(kh, crm):
    acc = tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    r = kh.get("/tai-khoan/dang-xuat")
    csrf = csrf_tu(r.text)
    # CSRF sai ⇒ không đăng xuất.
    assert kh.post("/tai-khoan/dang-xuat", data={"_csrf": "sai"}).status_code == 403
    r = kh.post("/tai-khoan/dang-xuat", data={"_csrf": csrf}, follow_redirects=False)
    assert r.status_code == 303
    assert kh.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"] == \
        "/tai-khoan/dang-nhap"
    goi = crm.goi[-1]
    assert goi["url"].endswith("/api/internal/portal/thu-hoi")
    assert goi["body"] == {"subject": acc["subject"], "reason": "dang_xuat"}


def test_thu_hoi_tu_crm(kh):
    tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    acc = acc_theo_sdt("+84900000001")
    r = goi_noi_bo(kh, "/api/internal/khach/thu-hoi", {"subject": acc["subject"], "reason": "x"})
    assert r.status_code == 200 and r.json()["data"]["phien_thu_hoi"] == 1
    assert "dang-nhap" in kh.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"]


def test_quen_mat_khau_khong_lo_va_dat_lai_thu_hoi_phien(kh, crm, monkeypatch):
    _ip(monkeypatch)
    acc = tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    csrf = _csrf(kh, "/tai-khoan/quen-mat-khau")
    r_co = kh.post("/tai-khoan/quen-mat-khau", data={"dinh_danh": "khach1@example.test",
                                                    "_csrf": csrf})
    r_khong = kh.post("/tai-khoan/quen-mat-khau", data={"dinh_danh": "khong-co@example.test",
                                                       "_csrf": csrf})
    assert r_co.status_code == r_khong.status_code == 200
    strip = lambda t: re.sub(r'value="[^"]*"', "", t)  # noqa: E731
    assert strip(r_co.text) == strip(r_khong.text)
    mails = outbox("khoi_phuc")
    assert len(mails) == 1 and mails[0]["to_email"] == "khach1@example.test"
    t = token_tu(mails[0]["body_text"], "/tai-khoan/dat-lai")
    # Bộ đếm sai trước đó (từ một IP) phải được xoá khi đặt lại thành công.
    for _ in range(3):
        dang_nhap(kh, "0900000001", "Sai!Passw0rd-12", headers={"x-real-ip": "203.0.113.1"})
    assert kh.get(f"/tai-khoan/dat-lai?t={t}").status_code == 200
    csrf = _csrf(kh, f"/tai-khoan/dat-lai?t={t}")
    r = kh.post("/tai-khoan/dat-lai", data={"t": t, "mat_khau": "ngan", "mat_khau_2": "ngan",
                                           "_csrf": csrf})
    assert r.status_code == 400  # mật khẩu yếu, token vẫn còn
    r = kh.post("/tai-khoan/dat-lai", data={"t": t, "mat_khau": MK_MOI, "mat_khau_2": MK_MOI,
                                           "_csrf": csrf})
    assert r.status_code == 200 and "Đã đặt mật khẩu mới" in r.text
    moi = acc_theo_sdt("+84900000001")
    assert moi["token_version"] == acc["token_version"] + 1
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_sessions WHERE account_id=? "
                         "AND status='active'", (acc["id"],)) == 0
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_login_attempts WHERE "
                         "account_key=? AND success=0", (acc["id"],)) == 0
    finally:
        conn.close()
    assert crm.goi[-1]["body"] == {"subject": acc["subject"], "reason": "dat_lai_mat_khau"}
    # Token cũ không dùng lại được.
    r = kh.post("/tai-khoan/dat-lai", data={"t": t, "mat_khau": "Lan2!Passw0rd-99",
                                           "mat_khau_2": "Lan2!Passw0rd-99", "_csrf": csrf})
    assert r.status_code == 400
    assert kh.get(f"/tai-khoan/dat-lai?t={t}").status_code == 400
    assert dang_nhap(kh, "0900000001", MK).status_code == 401
    token_launch(dang_nhap(kh, "0900000001", MK_MOI))


def test_phien_cu_vo_hieu_khi_token_version_doi(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_accounts SET token_version=token_version+1 WHERE id=?",
                     (acc["id"],))
        conn.commit()
    finally:
        conn.close()
    assert "dang-nhap" in kh.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"]


# ------------------------------------------------------------------ tách realm / dữ liệu
def test_bang_users_nhan_vien_khong_doi_va_khong_leo_thang(kh, client, owner):
    conn = db.connect()
    try:
        truoc = db.q(conn, "SELECT * FROM users ORDER BY id")
    finally:
        conn.close()
    tao_khach_hoat_dong(kh, 1)
    r = dang_nhap(kh, "0900000001")
    token_launch(r)
    conn = db.connect()
    try:
        assert db.q(conn, "SELECT * FROM users ORDER BY id") == truoc
        assert db.scalar(conn, "SELECT COUNT(*) FROM sessions") == 0
    finally:
        conn.close()
    # Cookie khách đem sang host nhân viên: không được coi là đăng nhập.
    tok = kh.cookies.get("vg_khach")
    assert tok
    r = client.get("/", cookies={"vg_khach": tok, "cowork_session": tok}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/dang-nhap")
    r = client.get("/api/me", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401
    # Phiên nhân viên đem sang host khách: không có tác dụng.
    dang_nhap_nv(client, "anh-thanh", "Owner!Passw0rd")
    nv = client.cookies.get("cowork_session")
    c2 = TestClient(app, base_url=HOST_KHACH)
    r = c2.get("/tai-khoan/vao-cong", cookies={"cowork_session": nv, "vg_khach": nv},
               follow_redirects=False)
    assert r.headers["location"] == "/tai-khoan/dang-nhap"
    assert c2.get("/", cookies={"cowork_session": nv}).status_code == 404
    # Khách không đăng nhập được realm nhân viên bằng SĐT/mã khách + mật khẩu khách.
    c3 = TestClient(app)
    for dd in ("VG000001", "vg000001", "+84900000001", acc_theo_sdt("+84900000001")["subject"]):
        r = dang_nhap_nv(c3, dd, MK)
        assert r.headers.get("location", "").startswith("/dang-nhap") or r.status_code != 303
        assert c3.get("/", follow_redirects=False).status_code == 303


def test_audit_su_kien_khach(kh):
    tao_khach_hoat_dong(kh, 1)
    dang_nhap(kh, "0900000001", "Sai!Passw0rd-12")
    token_launch(dang_nhap(kh, "0900000001"))
    conn = db.connect()
    try:
        acts = {r["action"] for r in db.q(conn, "SELECT action FROM audit_log WHERE tenant_id='khach'")}
        rows = db.q(conn, "SELECT detail FROM audit_log WHERE tenant_id='khach'")
    finally:
        conn.close()
    for a in ("khach.dang_ky", "khach.xac_minh_email", "khach.duyet", "khach.dang_nhap.sai",
              "khach.dang_nhap", "khach.launch"):
        assert a in acts, a
    blob = json.dumps(rows)
    assert MK not in blob and "+84900000001" not in blob


def test_migration_them_bang_khong_dong_du_lieu_cu(client, owner):
    from cowork import schema
    assert schema.SCHEMA_VERSION == 4
    conn = db.connect()
    try:
        truoc = db.q(conn, "SELECT * FROM users ORDER BY id")
        for t in ("customer_sessions", "customer_tokens", "customer_login_attempts",
                  "customer_outbox", "crm_sync_pending", "customer_hmac_seen",
                  "customer_rate_events", "customer_accounts"):
            conn.execute(f"DROP TABLE {t}")
        conn.execute("UPDATE meta SET value='3' WHERE key='schema_version'")
        conn.commit()
    finally:
        conn.close()
    db._initialized = False
    db.init_db()
    db._initialized = False
    db.init_db()  # chạy lại vẫn an toàn
    conn = db.connect()
    try:
        assert db.q(conn, "SELECT * FROM users ORDER BY id") == truoc
        assert db.scalar(conn, "SELECT value FROM meta WHERE key='schema_version'") == "4"
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_accounts") == 0
    finally:
        conn.close()


# ------------------------------------------------------------------ cấu hình khởi động
def test_kiem_cau_hinh(monkeypatch, bat):
    khach.kiem_cau_hinh()  # dev: hợp lệ
    monkeypatch.setattr(config, "ENV", "production")
    monkeypatch.setattr(config, "CRM_PORTAL_PUBLIC_URL", "https://khachhang.example.test")
    monkeypatch.setattr(config, "KHACH_PUBLIC_URL", "https://khachhang.example.test")
    with pytest.raises(RuntimeError, match="A8"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(config, "KHACH_MAIL_TRANSPORT", "smtp")  # chưa cài ⇒ vẫn chặn
    with pytest.raises(RuntimeError, match="A8"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(config, "ENV", "test")
    monkeypatch.setattr(khach, "_bi_mat_cache", config.BRAIN_SHARED_SECRET)
    with pytest.raises(RuntimeError, match="KHÁC"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(khach, "_bi_mat_cache", "ngan")
    with pytest.raises(RuntimeError, match="32 byte"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(khach, "_bi_mat_cache", None)
    monkeypatch.setattr(config, "KHACH_HOSTS", ["127.0.0.1:8899"])
    with pytest.raises(RuntimeError, match="trùng host nhân viên"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(config, "KHACH_ENABLED", False)
    monkeypatch.setattr(config, "ENV", "production")
    khach.kiem_cau_hinh()  # tắt ⇒ không chặn


def test_production_bat_realm_tu_choi_khoi_dong(monkeypatch, bat):
    monkeypatch.setattr(config, "ENV", "production")
    with pytest.raises(RuntimeError):
        with TestClient(app):
            pass


def test_bi_mat_khong_nam_trong_repo():
    files = subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                           cwd=config.BASE_DIR, check=True).stdout.splitlines()
    assert not [f for f in files if f.startswith(("data/", "secrets/")) or f.endswith(".key")]
    ignore = (config.BASE_DIR / ".gitignore").read_text()
    assert "data/" in ignore and "secrets/" in ignore
    bi_mat = khach.portal_secret()
    for f in files:
        p = config.BASE_DIR / f
        if p.is_file() and p.stat().st_size < 2_000_000:
            try:
                assert bi_mat not in p.read_text(encoding="utf-8", errors="ignore"), f
            except UnicodeDecodeError:
                pass
    # Tệp bí mật dev có quyền 0600.
    if config.PORTAL_SECRET_FILE.exists():
        assert (config.PORTAL_SECRET_FILE.stat().st_mode & 0o777) == 0o600
