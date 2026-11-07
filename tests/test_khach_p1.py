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


def KC(base: str = HOST_KHACH) -> TestClient:
    """Client trình duyệt trên host khách: gửi Origin như trình duyệt thật khi POST."""
    return TestClient(app, base_url=base, headers={"origin": base})


# ------------------------------------------------------------------ fixture
@pytest.fixture()
def crm(monkeypatch):
    """CRM giả: ghi lại mọi lần gọi; `crm.song=False` mô phỏng CRM không truy cập được.

    Request KHÔNG gọi CRM (chỉ xếp hàng). Đọc `crm.goi` = chạy một lượt vòng nền gửi hàng đợi
    rồi trả danh sách; `crm.goi_that` = các lần gọi thực sự đã xảy ra (không tự gửi)."""
    class _CRM:
        song = True
        cham = 0.0
        goi_that: list[dict] = []

        @property
        def goi(self):
            conn = db.connect()
            try:
                khach.dong_bo_crm(conn, tat_ca=True)
            finally:
                conn.close()
            return self.goi_that

    c = _CRM()
    c.goi_that = []

    def _post(url, body, headers):
        if c.cham:
            time.sleep(c.cham)
        if not c.song:
            raise ConnectionError("CRM không truy cập được")
        c.goi_that.append({"url": url, "body": json.loads(body), "headers": dict(headers),
                           "raw": body})
        return 200, "ok"

    monkeypatch.setattr(khach, "_http_post", _post)
    return c


@pytest.fixture()
def bat(monkeypatch):
    monkeypatch.setattr(config, "KHACH_ENABLED", True)
    monkeypatch.setattr(config, "KHACH_HOSTS", ["khach.localhost:8898", "khach.localhost"])
    monkeypatch.setattr(config, "STAFF_HOSTS", ["testserver"])
    monkeypatch.setattr(config, "CRM_PORTAL_PUBLIC_URL", "http://crm.localhost:8897")
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL", "http://127.0.0.1:8897")
    monkeypatch.setattr(config, "KHACH_PUBLIC_URL", HOST_KHACH)


@pytest.fixture()
def kh(client, bat, crm):
    """TestClient trên host khách (realm bật). `client` là host nhân viên (testserver)."""
    return KC()


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
            "email": f"khach{n}@example.test" if email is None else email, "mat_khau": mk,
            "mat_khau_2": mk if mk2 is None else mk2, "_csrf": _csrf(c, "/tai-khoan/dang-ky"),
            "cf-turnstile-response": "tot-dk"}
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


def link_dat_lai(c: TestClient, subject: str, nguoi: str = "nv-ho-tro") -> str:
    """CRM (HMAC) xin link đặt lại mật khẩu cho khách; trả token thô trong URL."""
    r = goi_noi_bo(c, "/api/internal/khach/tao-link-dat-lai",
                   {"subject": subject, "requested_by": nguoi})
    assert r.status_code == 200, r.text
    return token_tu(r.json()["data"]["url"], "/tai-khoan/dat-lai")


def acc_theo_sdt(phone: str) -> dict | None:
    conn = db.connect()
    try:
        return db.one(conn, "SELECT * FROM customer_accounts WHERE phone_e164=?", (phone,))
    finally:
        conn.close()


_da_ky: set[tuple[int, str, bytes]] = set()


def ky_vao(path: str, body: bytes, ts: int | None = None, method: str = "POST") -> dict:
    # CRM thật ký lại mỗi lần gửi; cùng (ts, path, body) = phát lại ⇒ chọn ts chưa dùng.
    if ts is None:
        ts = int(time.time())
        while (ts, path, body) in _da_ky:
            ts -= 1
        _da_ky.add((ts, path, body))
    h = khach.ky_portal(khach.HUONG_VAO, method, path, body, ts)
    return {**h, "Content-Type": "application/json"}


def goi_noi_bo(c: TestClient, path: str, payload: dict, ts: int | None = None, headers=None):
    body = json.dumps(payload).encode()
    return c.post(path, content=body, headers=headers or ky_vao(path, body, ts))


def duyet(c: TestClient, subject: str, n: int = 1, **extra):
    payload = {"subject": subject, "decision": "approved", "crm_customer_id": f"crm-uuid-{n}",
               "customer_code": f"KH-{n}", "portal_code": f"VG{1000 + n}",
               "phone_verified_by": "nv-duyet", **extra}
    return goi_noi_bo(c, "/api/internal/khach/ket-qua-duyet", payload)


def tao_khach_hoat_dong(c: TestClient, n: int = 1) -> dict:
    assert dang_ky(c, n).status_code == 303
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
    c = KC()
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
    assert r.headers["referrer-policy"] == "same-origin"
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
    assert khach.chuan_hoa_portal_code(" vg1001 ") == "VG1001"


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
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    acc = acc_theo_sdt("+84900000001")
    assert acc["status"] == "cho_duyet" and acc["subject"] == "cust:" + acc["id"]
    assert acc["id"].startswith("kh_") and len(acc["id"]) == 29
    assert acc["email_norm"] == "khach1@example.test" and acc["password_hash"] != MK


def test_dang_ky_khong_lo_tai_khoan(kh, crm):
    r1 = dang_ky(kh, 1)
    trung_sdt = dang_ky(kh, 1, email="nguoi-khac@example.test", mk="Khac!Passw0rd-99")
    trung_sdt_dd = dang_ky(kh, 1, sdt="+84 90 000 0001", email="")
    for r in (trung_sdt, trung_sdt_dd):
        assert r.status_code == r1.status_code == 303
        assert r.headers["location"] == r1.headers["location"] == "/tai-khoan/cho-duyet"
    assert _bo_token(kh.get("/tai-khoan/cho-duyet").text) == _bo_token(KC().get("/tai-khoan/cho-duyet").text)
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_accounts") == 1
        acc = db.one(conn, "SELECT * FROM customer_accounts")
        assert acc["email_norm"] == "khach1@example.test"  # không bị ghi đè
        assert acc["phone_conflict_count"] == 2
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE action='khach.dang_ky.trung'") >= 1
    finally:
        conn.close()
    assert outbox() == []  # email tắt: không gửi gì
    # Email KHÔNG unique: SĐT khác dùng chung email vẫn đăng ký được.
    assert dang_ky(kh, 2, email="khach1@example.test").status_code == 303
    assert acc_theo_sdt("+84900000002")["email_norm"] == "khach1@example.test"
    # Email để trống ⇒ hợp lệ, lưu NULL.
    assert dang_ky(kh, 3, email="").status_code == 303
    assert acc_theo_sdt("+84900000003")["email_norm"] is None


def test_dang_ky_gioi_han_tan_suat_ip(kh):
    for n in range(1, config.KHACH_SIGNUP_IP_PER_HOUR + 1):
        assert dang_ky(kh, n).status_code == 303
    assert dang_ky(kh, 9).status_code == 429


# ------------------------------------------------------------------ xác minh email
def test_dang_ky_gui_signup_crm_ngay(kh, crm):
    assert dang_ky(kh, 1).status_code == 303
    acc = acc_theo_sdt("+84900000001")
    assert acc["status"] == "cho_duyet" and acc["email_verified_at"] is None
    goi = crm.goi[-1]
    assert goi["url"] == "http://127.0.0.1:8897/api/internal/portal/signups"
    assert goi["body"] == {"subject": acc["subject"], "display_name": "Khách Thử 1",
                           "phone_e164": "+84900000001", "email": "khach1@example.test",
                           "phone_conflict": False, "phone_conflict_count": 0}
    assert goi["headers"]["Idempotency-Key"] == "signup:" + acc["subject"]
    ts = goi["headers"]["X-Portal-Ts"]
    mong = hmac.new(khach.portal_secret().encode(),
                    f"vipid->crm.POST./api/internal/portal/signups.{ts}.".encode() + goi["raw"],
                    hashlib.sha256).hexdigest()
    assert hmac.compare_digest(mong, goi["headers"]["X-Portal-Sig"])
    # Không có email ⇒ email null trong signup.
    dang_ky(kh, 2, email="")
    assert crm.goi[-1]["body"]["email"] is None
    assert outbox() == []


def test_crm_loi_thi_xep_hang_va_thu_lai(kh, crm):
    crm.song = False
    assert dang_ky(kh, 1).status_code == 303  # CRM lỗi vẫn nhận đăng ký
    conn = db.connect()
    try:
        row = db.one(conn, "SELECT * FROM crm_sync_pending")
        assert row["done_at"] is None and row["attempts"] == 0  # request không gọi CRM
        khach.dong_bo_crm(conn, tat_ca=True)  # vòng nền: CRM lỗi ⇒ giữ lại hàng đợi
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
def test_khong_dang_nhap_truoc_duyet(kh):
    dang_ky(kh, 1)
    r = dang_nhap(kh, "0900000001")
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    assert "vg_khach=" not in r.headers.get("set-cookie", "")
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
    acc = acc_theo_sdt("+84900000001")
    r = goi_noi_bo(kh, "/api/internal/khach/ket-qua-duyet",
                   {"subject": acc["subject"], "decision": "rejected", "reason": "trùng"})
    assert r.status_code == 200 and r.json()["data"]["status"] == "tu_choi"
    r2 = goi_noi_bo(kh, "/api/internal/khach/ket-qua-duyet",
                    {"subject": acc["subject"], "decision": "rejected"})
    assert r2.status_code == 200 and r2.json()["data"]["idempotent"] is True
    assert duyet(kh, acc["subject"]).status_code == 409
    # Bị từ chối ⇒ SĐT đã được giải phóng: đăng nhập chỉ nhận thông báo chung.
    r = dang_nhap(kh, "0900000001")
    assert r.status_code == 401 and "launch" not in r.headers.get("location", "")

    acc2 = tao_khach_hoat_dong(kh, 2)
    assert token_launch(dang_nhap(kh, "VG1002"))
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
    assert claims["portal_code"] == "VG1001"
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
    token_launch(dang_nhap(kh, "vg1001"))


def test_vao_cong_can_phien(kh):
    assert kh.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"] == \
        "/tai-khoan/dang-nhap"


def test_secure_cookie_khi_https(kh):
    tao_khach_hoat_dong(kh, 1)
    https = KC("https://khach.localhost:8898")
    r = dang_nhap(https, "0900000001")
    cks = r.headers.get_list("set-cookie")
    assert cks and all("secure" in c.lower() for c in cks)
    # Cookie tiền-phiên dùng tiền tố __Host- (Path=/, Secure) khi https.
    r = KC("https://khach.localhost:8898").get("/tai-khoan/quen-mat-khau")
    ck = r.headers.get("set-cookie", "")
    assert ck.startswith("__Host-vg_khach_ps=") and "Path=/;" in ck and "secure" in ck.lower()


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


def test_ke_la_nhieu_ip_chi_gioi_han_thiet_bi_moi(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    chu = KC()
    token_launch(dang_nhap(chu, "0900000001", MK, headers={"x-real-ip": "198.51.100.7"}))
    for i in range(40):  # 40 lần sai từ 10 IP khác nhau
        dang_nhap(kh, "VG1001", "Sai!Passw0rd-12", headers={"x-real-ip": f"203.0.113.{i % 10}"})
    conn = db.connect()
    try:
        assert khach.dang_gioi_han_toan_cuc(conn, acc_theo_sdt("+84900000001")["id"])
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE tenant_id='khach' "
                         "AND action='khach.canh_bao.do_mat_khau'") == 1
    finally:
        conn.close()
    # Chủ ở thiết bị đã dùng (cookie tin cậy) đăng nhập được ngay.
    token_launch(dang_nhap(chu, "0900000001", MK, headers={"x-real-ip": "198.51.100.7"}))


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
    orig = khach.bam_gia
    monkeypatch.setattr(khach, "bam_gia", lambda mk: (goi.append(1), orig(mk)))
    r = dang_nhap(kh, "0900000008", "Sai!Passw0rd-12")
    assert r.status_code == 401 and khach.THONG_BAO_SAI in r.text and goi


# ------------------------------------------------------------------ HMAC nội bộ
def test_hmac_tu_choi_chu_ky_sai_cu_va_phat_lai(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    path = "/api/internal/khach/tam-khoa"
    body = json.dumps({"subject": acc["subject"], "action": "khoa"}).encode()
    # Thiếu chữ ký / chữ ký sai / sai chiều.
    assert kh.post(path, content=body).status_code == 401
    h = ky_vao(path, body)
    assert kh.post(path, content=body, headers={**h, "X-Portal-Sig": "0" * 64}).status_code == 401
    sai_chieu = khach.ky_portal(khach.HUONG_RA, "POST", path, body)
    assert kh.post(path, content=body, headers=sai_chieu).status_code == 401
    # Sửa body sau khi ký.
    assert kh.post(path, content=body.replace(b"khoa", b"mo_khoa"), headers=h).status_code == 401
    # Cũ quá 300 giây.
    assert kh.post(path, content=body, headers=ky_vao(path, body, int(time.time()) - 301)).status_code == 401
    # ts không phải số thuần ("+N") ⇒ từ chối.
    hp = ky_vao(path, body)
    assert kh.post(path, content=body, headers={**hp, "X-Portal-Ts": "+" + hp["X-Portal-Ts"]}).status_code == 401
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
    assert duyet(kh, acc["subject"], portal_code="ABC").status_code == 400
    assert duyet(kh, acc["subject"], phone_verified_by="x" * 121).status_code == 400
    assert duyet(kh, "cust:khong-co").status_code == 404
    assert duyet(kh, acc["subject"]).status_code == 200
    a = acc_theo_sdt("+84900000001")
    assert a["status"] == "hoat_dong" and a["phone_verified_by"] == "nv-duyet"
    assert a["phone_verified_at"] and a["crm_customer_id"] == "crm-uuid-1"
    assert a["portal_code"] == "VG1001" and a["customer_code"] == "KH-1"
    r = duyet(kh, acc["subject"])
    assert r.status_code == 200 and r.json()["data"]["idempotent"] is True
    assert outbox("kich_hoat_xong") == []  # email tắt (mặc định)
    # Duyệt lại với hồ sơ CRM khác ⇒ xung đột.
    assert duyet(kh, acc["subject"], crm_customer_id="crm-khac").status_code == 409
    # portal_code đã dùng cho tài khoản khác ⇒ xung đột.
    dang_ky(kh, 2)
    acc2 = acc_theo_sdt("+84900000002")
    assert duyet(kh, acc2["subject"], 2, portal_code="VG1001").status_code == 409


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
    monkeypatch.setattr(config, "KHACH_EMAIL_ENABLED", True)  # đường email (cờ)
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
    c2 = KC()
    r = c2.get("/tai-khoan/vao-cong", cookies={"cowork_session": nv, "vg_khach": nv},
               follow_redirects=False)
    assert r.headers["location"] == "/tai-khoan/dang-nhap"
    assert c2.get("/", cookies={"cowork_session": nv}).status_code == 404
    # Khách không đăng nhập được realm nhân viên bằng SĐT/mã khách + mật khẩu khách.
    c3 = TestClient(app)
    for dd in ("VG1001", "vg1001", "+84900000001", acc_theo_sdt("+84900000001")["subject"]):
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
    for a in ("khach.dang_ky", "khach.duyet", "khach.dang_nhap.sai",
              "khach.dang_nhap", "khach.launch"):
        assert a in acts, a
    blob = json.dumps(rows)
    assert MK not in blob and "+84900000001" not in blob


def test_migration_them_bang_khong_dong_du_lieu_cu(client, owner):
    from cowork import schema
    assert schema.SCHEMA_VERSION == 6
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
        assert db.scalar(conn, "SELECT value FROM meta WHERE key='schema_version'") == "6"
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_accounts") == 0
    finally:
        conn.close()


# ------------------------------------------------------------------ cấu hình khởi động
def test_kiem_cau_hinh(monkeypatch, bat):
    khach.kiem_cau_hinh()  # dev: hợp lệ
    monkeypatch.setattr(config, "ENV", "production")
    monkeypatch.setattr(config, "CRM_PORTAL_PUBLIC_URL", "https://khachhang.example.test")
    monkeypatch.setattr(config, "KHACH_PUBLIC_URL", "https://khachhang.example.test")
    with pytest.raises(RuntimeError) as e:  # production cần Turnstile/TIN_PROXY/...
        khach.kiem_cau_hinh()
    assert "A8" not in str(e.value)  # email tắt ⇒ không đòi kênh email thật
    monkeypatch.setattr(config, "KHACH_EMAIL_ENABLED", True)
    with pytest.raises(RuntimeError, match="A8"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(config, "KHACH_MAIL_TRANSPORT", "smtp")  # chưa cài ⇒ vẫn chặn
    with pytest.raises(RuntimeError, match="A8"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(config, "KHACH_EMAIL_ENABLED", False)
    monkeypatch.setattr(config, "ENV", "test")
    monkeypatch.setattr(khach, "_bi_mat_cache", config.BRAIN_SHARED_SECRET)
    with pytest.raises(RuntimeError, match="KHÁC"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(khach, "_bi_mat_cache", "ngan")
    with pytest.raises(RuntimeError, match="32 byte"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(khach, "_bi_mat_cache", None)
    monkeypatch.setattr(config, "KHACH_HOSTS", ["testserver:8898"])  # khác cổng vẫn là trùng
    with pytest.raises(RuntimeError, match="trùng tên host"):
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


# ------------------------------------------------------------------ GET không tiêu token
def test_route_xac_minh_email_da_go(kh):
    for p in ("/tai-khoan/xac-minh-email?t=abc", "/tai-khoan/gui-lai-xac-minh",
              "/tai-khoan/da-gui-email"):
        assert kh.get(p).status_code == 404, p
    tok = csrf_tu(kh.get("/tai-khoan/dang-nhap").text)
    for p in ("/tai-khoan/xac-minh-email", "/tai-khoan/gui-lai-xac-minh"):
        assert kh.post(p, data={"_csrf": tok, "t": "x", "email": "a@example.test"}).status_code == 404


def test_get_dat_lai_khong_tieu_token(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    t = link_dat_lai(kh, acc["subject"])
    for _ in range(2):
        r = kh.get(f"/tai-khoan/dat-lai?t={t}")
        assert r.status_code == 200
    csrf = csrf_tu(r.text)
    d = {"t": t, "mat_khau": MK_MOI, "mat_khau_2": MK_MOI, "_csrf": csrf}
    assert kh.post("/tai-khoan/dat-lai", data=d).status_code == 200
    assert kh.post("/tai-khoan/dat-lai", data=d).status_code == 400


def test_ten_danh_rieng_khach_tren_host_nhan_vien(client, bat, crm, owner):
    from cowork import security, services, auth as nv_auth, rbac
    ten = ["dang-ky", "dang-nhap", "quen-mat-khau", "dat-lai", "xac-minh-email", "vao-cong",
           "dang-xuat", "static"]
    # Chưa đăng nhập: 404 (không chuyển sang trang đăng nhập nhân viên).
    for n in ten:
        assert client.get(f"/tai-khoan/{n}", follow_redirects=False).status_code == 404, n
    dang_nhap_nv(client, "anh-thanh", "Owner!Passw0rd")
    for n in ten:
        assert client.get(f"/tai-khoan/{n}", follow_redirects=False).status_code == 404, n
        assert client.get(f"/tai-khoan/{n}/phan-quyen", follow_redirects=False).status_code == 404
    # Route nhân viên khác vẫn hoạt động.
    assert client.get("/tai-khoan/anh-thanh").status_code == 200
    assert client.get("/tai-khoan/tao-moi").status_code == 200
    # Không tạo được ID nhân viên trùng tên dành riêng.
    for n in ten:
        assert security.kiem_tra_id(n), n
    conn = db.connect()
    try:
        actor = nv_auth.nguoi_dung_day_du(conn, "anh-thanh")
        perms = rbac.quyen_hieu_luc(conn, actor)
        from cowork.errors import ValidationError
        with pytest.raises(ValidationError, match="dành riêng"):
            services.tao_nguoi_dung(conn, actor, perms, {
                "id": "dang-nhap", "display_name": "x", "email": "x@example.test",
                "role_code": "employee", "department_id": "", "password": "User!Passw0rd",
                "must_change": "0", "scope_mode": "tenant", "scope_departments": [],
                "partner_org": ""})
        assert db.scalar(conn, "SELECT COUNT(*) FROM users WHERE id='dang-nhap'") == 0
    finally:
        conn.close()


# ================================================================== rà soát bảo mật (vòng 2)
def _doi_thoi_gian(giay: int) -> None:
    from datetime import datetime, timedelta
    conn = db.connect()
    try:
        for r in conn.execute("SELECT id, created_at FROM customer_login_attempts").fetchall():
            conn.execute("UPDATE customer_login_attempts SET created_at=? WHERE id=?",
                         ((datetime.fromisoformat(r[1]) - timedelta(seconds=giay)).isoformat(), r[0]))
        conn.commit()
    finally:
        conn.close()


def test_p1_1_ke_xoay_ip_khong_lam_chu_dang_nhap_that_bai(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    chu = KC()
    token_launch(dang_nhap(chu, "0900000001", MK, headers={"x-real-ip": "1.2.3.4"}))
    assert chu.cookies.get("vg_khach_tb")
    ke = KC()
    for i in range(10):
        dang_nhap(ke, "0900000001", "Sai!Passw0rd-xx", headers={"x-real-ip": f"10.0.0.{i}"})
    for chu_ky in range(12):  # kẻ tấn công luôn bắn trước chủ trong mỗi chu kỳ
        _doi_thoi_gian(31)
        dang_nhap(ke, "0900000001", "Sai!Passw0rd-xx", headers={"x-real-ip": f"10.1.{chu_ky}.1"})
        token_launch(dang_nhap(chu, "0900000001", MK, headers={"x-real-ip": "1.2.3.4"}))


def test_p1_1_cookie_thiet_bi_mien_gioi_han_ip_nhung_khong_mien_khoa_cap(kh, monkeypatch):
    _ip(monkeypatch)
    monkeypatch.setattr(config, "KHACH_LOGIN_IP_MAX_FAIL", 4)
    acc = tao_khach_hoat_dong(kh, 1)
    tao_khach_hoat_dong(kh, 2)
    nat = {"x-real-ip": "203.0.113.200"}  # chủ và kẻ lạ dùng chung NAT
    token_launch(dang_nhap(kh, "0900000001", MK, headers=nat))
    tb = kh.cookies.get("vg_khach_tb")
    acc = acc_theo_sdt("+84900000001")
    assert khach.thiet_bi_hop_le(tb, acc)
    ke = KC()
    for n in range(4):  # rải mật khẩu nhiều tài khoản từ cùng NAT ⇒ IP bị chặn
        dang_nhap(ke, f"090000002{n}", "Sai!Passw0rd-xx", headers=nat)
    assert dang_nhap(ke, "0900000002", MK, headers=nat).status_code == 429
    # Chủ có cookie thiết bị của ĐÚNG tài khoản ⇒ vẫn vào được.
    token_launch(dang_nhap(kh, "0900000001", MK, headers=nat))
    # Cookie thiết bị của tài khoản 1 không miễn cho tài khoản 2; cookie giả cũng không.
    lạ = KC()
    lạ.cookies.set("vg_khach_tb", tb, domain="khach.localhost", path="/tai-khoan")
    assert dang_nhap(lạ, "0900000002", MK, headers=nat).status_code == 429
    gia = tb.rsplit(".", 1)[0] + "." + "0" * 40
    assert not khach.thiet_bi_hop_le(gia, acc)
    # Khoá theo cặp (tài khoản, IP) vẫn áp cho thiết bị tin cậy.
    monkeypatch.setattr(config, "KHACH_LOGIN_IP_MAX_FAIL", 1000)
    for _ in range(config.KHACH_LOGIN_MAX_FAIL):
        dang_nhap(kh, "0900000001", "Sai!Passw0rd-xx", headers={"x-real-ip": "198.51.100.1"})
    assert dang_nhap(kh, "0900000001", MK, headers={"x-real-ip": "198.51.100.1"}).status_code == 429


def _quen(c, dd, ip):
    return c.post("/tai-khoan/quen-mat-khau", data={"dinh_danh": dd,
                  "_csrf": _csrf(c, "/tai-khoan/quen-mat-khau")}, headers={"x-real-ip": ip})


def test_p1_2_ke_la_khong_chan_duoc_khoi_phuc(kh, monkeypatch):
    _ip(monkeypatch)
    monkeypatch.setattr(config, "KHACH_EMAIL_ENABLED", True)  # đường email (cờ)
    tao_khach_hoat_dong(kh, 1)
    _quen(kh, "0900000001", "1.2.3.4")  # chủ yêu cầu
    t_chu = token_tu(outbox("khoi_phuc")[-1]["body_text"], "/tai-khoan/dat-lai")
    for i in range(8):  # kẻ lạ yêu cầu hộ từ nhiều IP
        _quen(kh, ["0900000001", "VG1001", "khach1@example.test"][i % 3], f"10.9.9.{i}")
    mails = outbox("khoi_phuc")
    assert len(mails) == config.KHACH_TOKEN_TOI_DA  # tối đa 3 link còn hiệu lực cùng lúc
    assert all(m["to_email"] == "khach1@example.test" for m in mails)
    # Link của chủ vẫn dùng được.
    assert kh.get(f"/tai-khoan/dat-lai?t={t_chu}").status_code == 200
    csrf = _csrf(kh, f"/tai-khoan/dat-lai?t={t_chu}")
    r = kh.post("/tai-khoan/dat-lai", data={"t": t_chu, "mat_khau": MK_MOI, "mat_khau_2": MK_MOI,
                                           "_csrf": csrf})
    assert r.status_code == 200
    # Dùng một link ⇒ mọi link khác vô hiệu.
    for m in mails[1:]:
        assert kh.get(f"/tai-khoan/dat-lai?t={token_tu(m['body_text'], '/tai-khoan/dat-lai')}"
                      ).status_code == 400
    # Giới hạn theo (tài khoản, IP): cùng IP chỉ 3 lần/giờ.
    conn = db.connect()
    try:
        n = db.scalar(conn, "SELECT COUNT(*) FROM customer_rate_events WHERE bucket='quen_acc_ip'")
        assert n >= 3
    finally:
        conn.close()


def test_p1_3_xung_dot_sdt_bao_crm_va_tu_choi_giai_phong(kh, crm):
    # Kẻ giữ chỗ đăng ký SĐT của nạn nhân bằng email của mình.
    dang_ky(kh, 5, email="ke-gia@example.test")
    ke = acc_theo_sdt("+84900000005")
    assert crm.goi[-1]["body"]["phone_conflict"] is False
    # Chủ thật đăng ký cùng SĐT.
    chu = KC()
    assert dang_ky(chu, 5, email="chu-that@example.test").status_code == 303
    goi = crm.goi[-1]
    assert goi["body"]["subject"] == ke["subject"]
    assert goi["body"]["phone_conflict"] is True and goi["body"]["phone_conflict_count"] == 1
    assert goi["headers"]["Idempotency-Key"] == f"signup:{ke['subject']}:xung-dot-1"
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE "
                         "action='khach.dang_ky.xung_dot_sdt' AND target_id=?", (ke["subject"],)) == 1
    finally:
        conn.close()
    # Nhân viên thấy cờ xung đột, kiểm tra ⇒ từ chối ⇒ SĐT được giải phóng.
    r = goi_noi_bo(kh, "/api/internal/khach/ket-qua-duyet",
                   {"subject": ke["subject"], "decision": "rejected", "reason": "sai chủ"})
    assert r.status_code == 200
    assert acc_theo_sdt("+84900000005") is None
    conn = db.connect()
    try:
        a = db.one(conn, "SELECT * FROM customer_accounts WHERE id=?", (ke["id"],))
        assert a["status"] == "tu_choi" and a["phone_e164"].startswith("released:")
        det = db.scalar(conn, "SELECT detail FROM audit_log WHERE action='khach.tu_choi'")
        assert hashlib.sha256(b"+84900000005").hexdigest() in det
    finally:
        conn.close()
    chu2 = KC()
    assert dang_ky(chu2, 5, email="chu-that@example.test").status_code == 303
    moi = acc_theo_sdt("+84900000005")
    assert moi and moi["email_norm"] == "chu-that@example.test" and moi["id"] != ke["id"]
    # Email không unique: dùng lại email cũ cho SĐT khác vẫn được.
    assert dang_ky(chu2, 6, email="ke-gia@example.test").status_code == 303


def test_p1_4_host_la_khong_roi_ve_nhan_vien(client, bat, crm):
    for h, mong in [("KHACH.LOCALHOST:8898", "khach"), ("khach.localhost.:8898", "khach"),
                    ("khach.localhost:08898", "khach"), ("khach.localhost", "khach"),
                    ("TESTSERVER", "staff"), ("testserver.", "staff"),
                    ("evil.example", None), ("localhost:8898", None), ("", None),
                    ("khach.localhost:8898 x", None), ("a..b", None), ("khach.localhost:70000", None)]:
        assert khach.chon_realm(h) == mong, h
    for h in ("evil.example", "127.0.0.1:8899", "localhost"):
        r = client.get("/dang-nhap", headers={"host": h})
        assert r.status_code == 421 and "COWORK" not in r.text, h
    assert client.get("/dang-nhap", headers={"host": "khach.localhost.:8898"}).status_code == 404
    assert client.get("/dang-nhap").status_code == 200  # host nhân viên hợp lệ
    # Thiếu Host (HTTP/1.0) ⇒ 421.
    import asyncio
    sent = []

    async def _recv():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def _send(m):
        sent.append(m)
    scope = {"type": "http", "method": "GET", "path": "/dang-nhap", "raw_path": b"/dang-nhap",
             "query_string": b"", "headers": [], "http_version": "1.0", "scheme": "http",
             "server": ("127.0.0.1", 8899), "client": ("127.0.0.1", 1), "root_path": ""}
    asyncio.run(app(scope, _recv, _send))
    assert sent[0]["status"] == 421


def test_p1_4_tat_realm_khong_kiem_host(client):
    assert config.KHACH_ENABLED is False and not config.STAFF_HOSTS
    assert client.get("/dang-nhap", headers={"host": "bat-ky.example"}).status_code == 200


def test_p2_6_env_chuan_hoa(monkeypatch, bat):
    monkeypatch.setattr(config, "ENV", "PROD ")
    assert khach.la_production()
    with pytest.raises(RuntimeError, match="Turnstile"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(config, "ENV", "prodution")
    with pytest.raises(RuntimeError, match="không hợp lệ"):
        khach.kiem_cau_hinh()


def test_p2_7_chu_ky_gan_phuong_thuc_va_duong_dan(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    body = json.dumps({"subject": acc["subject"], "action": "khoa", "reason": "x"}).encode()
    h = ky_vao("/api/internal/khach/thu-hoi", body)
    assert kh.post("/api/internal/khach/tam-khoa", content=body, headers=h).status_code == 401
    h = ky_vao("/api/internal/khach/tam-khoa", body, method="PUT")
    assert kh.post("/api/internal/khach/tam-khoa", content=body, headers=h).status_code == 401
    assert acc_theo_sdt("+84900000001")["status"] == "hoat_dong"
    h = ky_vao("/api/internal/khach/tam-khoa", body)
    assert kh.post("/api/internal/khach/tam-khoa", content=body, headers=h).status_code == 200


def test_p2_8_audit_chu_ky_sai_lay_mau(kh):
    conn = db.connect()
    try:
        n0 = db.scalar(conn, "SELECT COUNT(*) FROM audit_log")
    finally:
        conn.close()
    for _ in range(20):
        kh.post("/api/internal/khach/tam-khoa", content=b"{}",
                headers={"X-Portal-Ts": "1", "X-Portal-Sig": "0" * 64})
        dang_nhap(kh, "0900000009", "Sai!Passw0rd-xx")
    conn = db.connect()
    try:
        dem = dict(conn.execute("SELECT action, COUNT(*) FROM audit_log WHERE id>? "
                                "GROUP BY action", (n0,)).fetchall())
    finally:
        conn.close()
    # 40 lượt thất bại (20 chữ ký sai, 20 đăng nhập sai rồi bị khoá cặp) ⇒ 1 dòng mỗi loại.
    assert dem == {"khach.hmac.sai": 1, "khach.dang_nhap.sai": 1,
                   "khach.dang_nhap.khoa_cap_ip": 1}


def test_p2_9_gioi_han_body_truoc_khi_doc(kh):
    path = "/api/internal/khach/tam-khoa"
    lon = b"{" + b" " * 20_000 + b"}"
    r = kh.post(path, content=lon, headers=ky_vao(path, lon))
    assert r.status_code == 413
    r = kh.post(path, content=b"{}", headers={"content-length": "999999", **ky_vao(path, b"{}")})
    assert r.status_code == 413

    def _gen():
        yield b"{}"
    r = kh.post(path, content=_gen(), headers=ky_vao(path, b"{}"))  # chunked, không có CL
    assert r.status_code == 413


def _form_gui_lai(c, csrf, **h):
    """POST biểu mẫu ẩn danh (đăng nhập sai): CSRF đạt ⇒ 401, CSRF/nguồn hỏng ⇒ 403."""
    return c.post("/tai-khoan/dang-nhap", data={"dinh_danh": "0900000099",
                  "mat_khau": "Sai!Passw0rd-xx", "_csrf": csrf}, headers=h, follow_redirects=False)


def test_p2_10_csrf_gan_tien_phien_va_cung_nguon(kh):
    # Token hợp lệ của chính trình duyệt này ⇒ qua.
    tok = csrf_tu(kh.get("/tai-khoan/dang-nhap").text)
    assert _form_gui_lai(kh, tok).status_code == 401
    # Giá trị tuỳ ý ⇒ 403.
    assert _form_gui_lai(kh, "A" * 32).status_code == 403
    # Cookie tossing: kẻ tấn công lấy cặp token hợp lệ CỦA MÌNH, cài token vào nạn nhân.
    ke = KC()
    tok_ke = csrf_tu(ke.get("/tai-khoan/dang-nhap").text)
    nan_nhan = KC()
    nan_nhan.get("/tai-khoan/dang-nhap")  # nạn nhân có id tiền-phiên riêng
    assert _form_gui_lai(nan_nhan, tok_ke).status_code == 403
    # ... kể cả khi cài cả token CSRF cũ dạng double-submit.
    nan_nhan.cookies.set("vg_khach_csrf", tok_ke, domain="khach.localhost", path="/tai-khoan")
    assert _form_gui_lai(nan_nhan, tok_ke).status_code == 403
    # Không chứng minh được cùng nguồn ⇒ 403 dù token đúng.
    tho = TestClient(app, base_url=HOST_KHACH)  # không gửi Origin
    tok_tho = csrf_tu(tho.get("/tai-khoan/dang-nhap").text)
    assert _form_gui_lai(tho, tok_tho).status_code == 403
    assert _form_gui_lai(tho, tok_tho, **{"sec-fetch-site": "cross-site"}).status_code == 403
    assert _form_gui_lai(tho, tok_tho, **{"sec-fetch-site": "same-origin"}).status_code == 401
    for origin in ("null", "https://evil.example", "http://testserver",
                   "http://khach.localhost:9999"):
        assert _form_gui_lai(kh, tok, origin=origin).status_code == 403, origin
    # Token gắn id tiền-phiên: đổi id ⇒ token cũ hết giá trị.
    ps = "x" * 32
    assert khach.csrf_hop_le(khach.tao_csrf(ps), ps)
    assert not khach.csrf_hop_le(khach.tao_csrf(ps), "y" * 32)


def test_p2_11_dat_lai_khi_bi_khoa_bi_tu_choi(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    t = link_dat_lai(kh, acc["subject"])
    assert goi_noi_bo(kh, "/api/internal/khach/tam-khoa",
                      {"subject": acc["subject"], "action": "khoa"}).status_code == 200
    csrf = _csrf(kh, "/tai-khoan/dang-nhap")
    r = kh.post("/tai-khoan/dat-lai", data={"t": t, "mat_khau": MK_MOI, "mat_khau_2": MK_MOI,
                                           "_csrf": csrf})
    assert r.status_code == 403
    assert acc_theo_sdt("+84900000001")["password_hash"] == acc["password_hash"]


def test_p2_12_cookie_secure_production_va_bi_mat_0600(kh, monkeypatch, tmp_path):
    tao_khach_hoat_dong(kh, 1)
    monkeypatch.setattr(config, "ENV", "production")
    r = dang_nhap(KC("https://khach.localhost:8898"), "0900000001")
    cks = r.headers.get_list("set-cookie")
    assert cks and all("secure" in c.lower() for c in cks)
    import os
    import stat
    p = tmp_path / "bi-mat" / "x.key"
    monkeypatch.delenv("X_TEST_SECRET", raising=False)
    old = os.umask(0)
    try:
        v = config._secret(p, "X_TEST_SECRET")
    finally:
        os.umask(old)
    assert stat.S_IMODE(p.stat().st_mode) == 0o600 and p.read_text().strip() == v
    assert config._secret(p, "X_TEST_SECRET") == v


def test_p2_12_scrypt_manh_va_nang_cap_hash_cu(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    assert acc["password_algo"] == f"scrypt:n={2 ** 17},r=8,p=1"
    from cowork import security
    h, sa = security.bam_mat_khau(MK)  # hash kiểu cũ N=2^14, algo 'scrypt'
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_accounts SET password_hash=?, password_salt=?, "
                     "password_algo='scrypt' WHERE id=?", (h, sa, acc["id"]))
        conn.commit()
    finally:
        conn.close()
    token_launch(dang_nhap(kh, "0900000001"))
    assert acc_theo_sdt("+84900000001")["password_algo"] == f"scrypt:n={2 ** 17},r=8,p=1"
    token_launch(dang_nhap(kh, "0900000001"))


# ================================================================== rà soát bảo mật (vòng 3)
def _bo_token(html: str) -> str:
    return re.sub(r'value="[^"]*"', "", html)


def test_n1_gioi_han_toan_cuc_tra_429_giong_het_cho_thiet_bi_moi(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    cu = KC()  # thiết bị chủ đã dùng
    token_launch(dang_nhap(cu, "0900000001", MK, headers={"x-real-ip": "1.2.3.4"}))
    ke = KC()
    for i in range(60):  # dò phân tán: 15 IP × 4
        dang_nhap(ke, "0900000001", f"Sai!Passw0rd-{i:02d}", headers={"x-real-ip": f"10.{i // 4}.0.{i % 4}"})
    conn = db.connect()
    try:
        so_sai = db.scalar(conn, "SELECT COUNT(*) FROM customer_login_attempts WHERE success=0")
    finally:
        conn.close()
    assert so_sai == khach.LAM_CHAM_SAU  # sau ngưỡng, các lượt không còn được kiểm mật khẩu
    moi = KC()
    goi = []
    orig = khach._scrypt
    monkeypatch.setattr(khach, "_scrypt", lambda *a: (goi.append(1), orig(*a))[1])
    r_dung = dang_nhap(moi, "0900000001", MK, headers={"x-real-ip": "10.99.0.1"})
    r_sai = dang_nhap(moi, "0900000001", "Sai!Passw0rd-zz", headers={"x-real-ip": "10.98.0.1"})
    assert r_dung.status_code == r_sai.status_code == 429
    assert "vg_khach=" not in r_dung.headers.get("set-cookie", "")
    assert _bo_token(r_dung.text).replace("10.99.0.1", "") == _bo_token(r_sai.text).replace("10.98.0.1", "")
    assert goi == []  # không băm trên đường bị chặn
    # Thiết bị tin cậy vẫn vào được.
    token_launch(dang_nhap(cu, "0900000001", MK, headers={"x-real-ip": "1.2.3.4"}))
    # Thiết bị mới: nhân viên cấp link đặt lại (qua Zalo) ⇒ xoá bộ đếm ⇒ đăng nhập được.
    t = link_dat_lai(kh, acc_theo_sdt("+84900000001")["subject"])
    csrf = _csrf(moi, f"/tai-khoan/dat-lai?t={t}")
    assert moi.post("/tai-khoan/dat-lai", data={"t": t, "mat_khau": MK_MOI, "mat_khau_2": MK_MOI,
                                                "_csrf": csrf}).status_code == 200
    token_launch(dang_nhap(moi, "0900000001", MK_MOI, headers={"x-real-ip": "10.99.0.1"}))


def test_n2_duong_bi_chan_khong_bam(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    ip = {"x-real-ip": "203.0.113.5"}
    for _ in range(config.KHACH_LOGIN_MAX_FAIL):
        dang_nhap(kh, "0900000001", "Sai!Passw0rd-xx", headers=ip)
    goi = []
    monkeypatch.setattr(khach, "_scrypt", lambda *a: goi.append(1) or b"x" * 32)
    assert dang_nhap(kh, "0900000001", MK, headers=ip).status_code == 429
    monkeypatch.setattr(config, "KHACH_LOGIN_IP_MAX_FAIL", 1)
    assert dang_nhap(kh, "0900000077", MK, headers=ip).status_code == 429
    assert goi == []


def test_n2_semaphore_het_cho_tra_503(kh, monkeypatch):
    tao_khach_hoat_dong(kh, 1)
    monkeypatch.setattr(khach, "SCRYPT_CHO_TOI_DA_GIAY", 0.05)
    giu = [khach._scrypt_sem.acquire() for _ in range(config.KHACH_SCRYPT_DONG_THOI)]
    try:
        r = dang_nhap(kh, "0900000001")
        assert r.status_code == 503 and "bận" in r.text
    finally:
        for _ in giu:
            khach._scrypt_sem.release()
    token_launch(dang_nhap(kh, "0900000001"))


def test_n2_trang_nhan_vien_khong_nghen_khi_lu_dang_nhap_khach(kh, owner, monkeypatch):
    import asyncio
    import httpx
    _ip(monkeypatch)
    csrf_page = kh.get("/tai-khoan/dang-nhap")
    tok = csrf_tu(csrf_page.text)
    ck = "; ".join(f"{k}={v}" for k, v in kh.cookies.items())

    async def chay():
        tr = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=tr, base_url="http://testserver") as nv, \
                httpx.AsyncClient(transport=tr, base_url=HOST_KHACH) as c:
            async def login(i):
                return await c.post("/tai-khoan/dang-nhap", data={
                    "dinh_danh": f"0912{i:06d}", "mat_khau": "Sai!Passw0rd-xx", "_csrf": tok},
                    headers={"cookie": ck, "origin": HOST_KHACH, "x-real-ip": f"10.7.{i}.1"})
            tasks = [asyncio.create_task(login(i)) for i in range(60)]
            await asyncio.sleep(0.2)
            tre = []
            for path in ("/dang-nhap", "/tai-khoan/dang-nhap", "/tai-khoan/anh-thanh"):
                t0 = time.perf_counter()
                r = await nv.get(path, follow_redirects=False)
                tre.append((path, r.status_code, time.perf_counter() - t0))
            kq = await asyncio.gather(*tasks)
            return tre, [r.status_code for r in kq]

    tre, codes = asyncio.run(chay())
    for path, status, giay in tre:
        assert status in (200, 303, 404) and giay < 0.5, (path, status, giay)
    assert set(codes) <= {401, 503} and 503 in codes  # hàng đợi băm có trần


def test_n3_cookie_thiet_bi_mat_hieu_luc_khi_doi_token_version(kh):
    tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    tb = kh.cookies.get("vg_khach_tb")
    acc = acc_theo_sdt("+84900000001")
    assert khach.thiet_bi_hop_le(tb, acc)
    # Khoá rồi mở (CRM) ⇒ token_version tăng ⇒ cookie cũ vô hiệu.
    goi_noi_bo(kh, "/api/internal/khach/tam-khoa", {"subject": acc["subject"], "action": "khoa"})
    goi_noi_bo(kh, "/api/internal/khach/tam-khoa", {"subject": acc["subject"], "action": "mo_khoa"})
    assert not khach.thiet_bi_hop_le(tb, acc_theo_sdt("+84900000001"))
    # Sửa token_version trong cookie ⇒ chữ ký sai.
    p = tb.split(".")
    p[1] = str(acc_theo_sdt("+84900000001")["token_version"])
    assert not khach.thiet_bi_hop_le(".".join(p), acc_theo_sdt("+84900000001"))
    # Đăng nhập lại ⇒ cookie mới hợp lệ.
    token_launch(dang_nhap(kh, "0900000001"))
    assert khach.thiet_bi_hop_le(kh.cookies.get("vg_khach_tb"), acc_theo_sdt("+84900000001"))


def test_n4_staff_hosts_chua_dat(monkeypatch, bat, caplog):
    monkeypatch.setattr(config, "STAFF_HOSTS", [])
    import logging
    with caplog.at_level(logging.WARNING, logger="cowork.khach"):
        khach.kiem_cau_hinh()
    assert "COWORK_STAFF_HOSTS chưa đặt" in caplog.text
    monkeypatch.setattr(config, "ENV", "production")
    with pytest.raises(RuntimeError, match="COWORK_STAFF_HOSTS chưa đặt"):
        khach.kiem_cau_hinh()


# ================================================================== rà soát vòng 4
TS_SITE = "1x00000000000000000000AA"            # khoá thử nghiệm Cloudflare (chỉ test)
TS_SECRET = "1x0000000000000000000000000000000AA"


@pytest.fixture()
def turnstile(monkeypatch):
    """Turnstile bật bằng khoá thử nghiệm; siteverify GIẢ (không gọi mạng)."""
    from cowork import khach_web
    monkeypatch.setattr(config, "KHACH_TURNSTILE_SITE_KEY", TS_SITE)
    monkeypatch.setenv("COWORK_KHACH_TURNSTILE_SECRET", TS_SECRET)
    class _Goi(list):
        dang_ky: list = []
    goi = _Goi()
    goi.dang_ky = []  # các lượt siteverify cho đăng ký (tách khỏi đăng nhập)

    async def _gia(secret, token, remoteip):
        if token in ("tot-dk", "dk-sai-action"):
            goi.dang_ky.append((secret, token, remoteip))
            return {"success": True, "hostname": "khach.localhost",
                    "action": "khach_dang_ky" if token == "tot-dk" else "khach_login"}
        goi.append((secret, token, remoteip))
        if token == "tot":
            return {"success": True, "hostname": "khach.localhost", "action": "khach_login"}
        if token == "sai-host":
            return {"success": True, "hostname": "evil.example", "action": "khach_login"}
        if token == "sai-action":
            return {"success": True, "hostname": "khach.localhost", "action": "khac"}
        return {"success": False, "error-codes": ["invalid-input-response"]}

    monkeypatch.setattr(khach_web, "turnstile_siteverify", _gia)
    return goi


def _dang_nhap_ts(c, dd, mk, ip, cf=None):
    data = {"dinh_danh": dd, "mat_khau": mk, "_csrf": _csrf(c, "/tai-khoan/dang-nhap")}
    if cf is not None:
        data["cf-turnstile-response"] = cf
    return c.post("/tai-khoan/dang-nhap", data=data, headers={"x-real-ip": ip},
                  follow_redirects=False)


def _do_phan_tan(n=khach.LAM_CHAM_SAU):
    ke = KC()
    for i in range(n):
        dang_nhap(ke, "0900000001", f"Sai!Passw0rd-{i:02d}", headers={"x-real-ip": f"10.{i}.0.1"})


def test_r1_turnstile_thu_thach_thay_cho_khoa_cung(kh, monkeypatch, turnstile):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    # Bình thường: không có thử thách, CSP không mở Cloudflare.
    r = kh.get("/tai-khoan/dang-nhap")
    assert "cf-turnstile" not in r.text and "challenges.cloudflare.com" not in \
        r.headers["content-security-policy"]
    _do_phan_tan()
    moi = KC()
    r_dung = _dang_nhap_ts(moi, "0900000001", MK, "10.99.0.1")
    r_sai = _dang_nhap_ts(moi, "0900000001", "Sai!Passw0rd-zz", "10.99.0.1")
    for r in (r_dung, r_sai):
        assert r.status_code == 429
        assert 'class="cf-turnstile"' in r.text and f'data-sitekey="{TS_SITE}"' in r.text
        assert 'data-action="khach_login"' in r.text
        assert '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"' in r.text
        csp = r.headers["content-security-policy"]
        assert "script-src https://challenges.cloudflare.com;" in csp
        assert "frame-src https://challenges.cloudflare.com;" in csp
        assert "x-khach-turnstile" not in r.headers
    assert _bo_token(r_dung.text) == _bo_token(r_sai.text)
    assert turnstile == []  # chưa có token ⇒ không gọi siteverify
    # Token không hợp lệ / sai hostname / sai action ⇒ vẫn là thử thách, mật khẩu không được kiểm.
    for tok in ("rac", "sai-host", "sai-action"):
        r = _dang_nhap_ts(moi, "0900000001", MK, "10.99.0.1", cf=tok)
        assert r.status_code == 429 and "cf-turnstile" in r.text, tok
    assert {g[0] for g in turnstile} == {TS_SECRET} and turnstile[0][2] == "10.99.0.1"
    # Vượt thử thách + sai mật khẩu ⇒ 401, lượt sai VẪN được đếm.
    conn = db.connect()
    try:
        n0 = db.scalar(conn, "SELECT COUNT(*) FROM customer_login_attempts WHERE success=0")
    finally:
        conn.close()
    r = _dang_nhap_ts(moi, "0900000001", "Sai!Passw0rd-yy", "10.99.0.1", cf="tot")
    assert r.status_code == 401
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_login_attempts WHERE success=0") == n0 + 1
    finally:
        conn.close()
    # Vượt thử thách + đúng mật khẩu ⇒ đăng nhập được từ thiết bị mới.
    token_launch(_dang_nhap_ts(moi, "0900000001", MK, "10.99.0.1", cf="tot"))
    # Trang thường sau đó lại khoá CSP chặt.
    assert "challenges.cloudflare.com" not in kh.get("/tai-khoan/quen-mat-khau").headers[
        "content-security-policy"]


def test_r1_token_turnstile_vo_tac_dung_khi_khong_bi_gioi_han(kh, monkeypatch, turnstile):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    # Token tốt không vượt được khoá theo cặp (tài khoản, IP).
    for _ in range(config.KHACH_LOGIN_MAX_FAIL):
        _dang_nhap_ts(kh, "0900000001", "Sai!Passw0rd-xx", "203.0.113.4")
    r = _dang_nhap_ts(kh, "0900000001", MK, "203.0.113.4", cf="tot")
    assert r.status_code == 429 and "cf-turnstile" not in r.text


def test_r1_khong_cau_hinh_turnstile_giu_429_giong_het(kh, monkeypatch):
    _ip(monkeypatch)
    assert not khach.turnstile_bat()
    tao_khach_hoat_dong(kh, 1)
    _do_phan_tan()
    r = _dang_nhap_ts(KC(), "0900000001", MK, "10.99.0.2", cf="tot")
    assert r.status_code == 429 and "cf-turnstile" not in r.text


def test_r1_production_bat_buoc_turnstile_that(monkeypatch, bat):
    monkeypatch.setattr(config, "ENV", "production")
    with pytest.raises(RuntimeError, match="Turnstile"):
        khach.kiem_cau_hinh()
    monkeypatch.setattr(config, "KHACH_TURNSTILE_SITE_KEY", TS_SITE)
    monkeypatch.setenv("COWORK_KHACH_TURNSTILE_SECRET", TS_SECRET)
    with pytest.raises(RuntimeError, match="thử nghiệm"):
        khach.kiem_cau_hinh()


def test_r1_kiem_ket_qua_siteverify():
    ok = {"success": True, "hostname": "khachhang.vipgroup.com.vn", "action": "khach_login"}
    assert khach.ket_qua_turnstile_hop_le(ok, "KhachHang.VIPGROUP.com.vn.")
    assert khach.ket_qua_turnstile_hop_le(ok, "khachhang.vipgroup.com.vn:443")
    assert not khach.ket_qua_turnstile_hop_le({**ok, "success": "true"}, "khachhang.vipgroup.com.vn")
    assert not khach.ket_qua_turnstile_hop_le({**ok, "hostname": "x.vn"}, "khachhang.vipgroup.com.vn")
    assert not khach.ket_qua_turnstile_hop_le({**ok, "action": None}, "khachhang.vipgroup.com.vn")
    assert not khach.ket_qua_turnstile_hop_le(None, "khachhang.vipgroup.com.vn")


def test_r2_khoa_ip_ipv6_64_va_ipv4_mapped():
    assert khach.khoa_ip("203.0.113.5") == "203.0.113.5"
    assert khach.khoa_ip("::ffff:203.0.113.5") == "203.0.113.5"
    assert khach.khoa_ip("2001:db8:1:2::1") == khach.khoa_ip("2001:db8:1:2:ffff:ffff:ffff:ffff") \
        == "2001:db8:1:2::/64"
    assert khach.khoa_ip("2001:db8:1:3::1") != khach.khoa_ip("2001:db8:1:2::1")
    assert khach.khoa_ip("?") == "?"


def test_r2_khoa_cap_va_gioi_han_ip_theo_64(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    for i in range(config.KHACH_LOGIN_MAX_FAIL):  # xoay địa chỉ trong cùng /64
        dang_nhap(kh, "0900000001", "Sai!Passw0rd-xx", headers={"x-real-ip": f"2001:db8:1:2::{i + 1:x}"})
    r = dang_nhap(kh, "0900000001", MK, headers={"x-real-ip": "2001:db8:1:2:dead::beef"})
    assert r.status_code == 429
    token_launch(dang_nhap(kh, "0900000001", MK, headers={"x-real-ip": "2001:db8:1:3::1"}))
    # IPv4-mapped dùng chung khoá với IPv4.
    for _ in range(config.KHACH_LOGIN_MAX_FAIL):
        dang_nhap(kh, "0900000001", "Sai!Passw0rd-xx", headers={"x-real-ip": "::ffff:198.51.100.9"})
    assert dang_nhap(kh, "0900000001", MK, headers={"x-real-ip": "198.51.100.9"}).status_code == 429
    conn = db.connect()
    try:
        ips = {r[0] for r in conn.execute("SELECT DISTINCT ip FROM customer_login_attempts")}
    finally:
        conn.close()
    assert "2001:db8:1:2::/64" in ips and "198.51.100.9" in ips
    assert not any(i.startswith("2001:db8:1:2::") and not i.endswith("/64") for i in ips)


def test_r3_x_forwarded_proto_chi_tin_khi_tin_proxy(kh, monkeypatch):
    tao_khach_hoat_dong(kh, 1)
    r = dang_nhap(kh, "0900000001", headers={"x-forwarded-proto": "https"})
    cks = r.headers.get_list("set-cookie")
    assert cks and not any("secure" in c.lower() for c in cks)
    assert "strict-transport-security" not in r.headers
    monkeypatch.setattr(config, "TIN_PROXY", True)
    r = kh.get("/tai-khoan/dang-nhap", headers={"x-forwarded-proto": "https"})
    assert "strict-transport-security" in r.headers


# ================================================================== rà soát vòng 5
def test_p2a_siteverify_chi_goi_khi_can(kh, monkeypatch, turnstile):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    tao_khach_hoat_dong(kh, 2)
    # Tài khoản không bị giới hạn + có token ⇒ không gọi siteverify.
    token_launch(_dang_nhap_ts(KC(), "0900000002", MK, "198.51.100.2", cf="tot"))
    assert turnstile == []
    _do_phan_tan()
    # POST khác nguồn kèm token rác ⇒ 403, không gọi siteverify.
    tho = TestClient(app, base_url=HOST_KHACH)
    tok = csrf_tu(tho.get("/tai-khoan/dang-nhap").text)
    for h in ({}, {"origin": "https://evil.example"}, {"sec-fetch-site": "cross-site"}):
        r = tho.post("/tai-khoan/dang-nhap", data={"dinh_danh": "0900000001", "mat_khau": MK,
                     "_csrf": tok, "cf-turnstile-response": "rac"},
                     headers={"x-real-ip": "10.99.0.5", **h}, follow_redirects=False)
        assert r.status_code == 403, h
    # CSRF sai ⇒ 403, không gọi.
    r = KC().post("/tai-khoan/dang-nhap", data={"dinh_danh": "0900000001", "mat_khau": MK,
                  "_csrf": "sai", "cf-turnstile-response": "tot"}, headers={"x-real-ip": "10.99.0.6"})
    assert r.status_code == 403
    # Khoá theo cặp (tài khoản, IP) chặn trước thử thách ⇒ không gọi.
    ip_khoa = "203.0.113.66"
    monkeypatch.setattr(config, "KHACH_LOGIN_IP_MAX_FAIL", 1000)
    for _ in range(config.KHACH_LOGIN_MAX_FAIL):
        dang_nhap(KC(), "0900000002", "Sai!Passw0rd-xx", headers={"x-real-ip": ip_khoa})
    assert _dang_nhap_ts(KC(), "0900000002", MK, ip_khoa, cf="tot").status_code == 429
    assert turnstile == []
    # Đúng trường hợp cần thử thách ⇒ gọi đúng một lần.
    token_launch(_dang_nhap_ts(KC(), "0900000001", MK, "10.99.0.7", cf="tot"))
    assert len(turnstile) == 1


def test_p2a_tran_dong_thoi_siteverify(kh, monkeypatch, turnstile):
    from cowork import khach_web
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    _do_phan_tan()
    monkeypatch.setattr(khach_web, "_ts_dang_goi", khach_web.TURNSTILE_DONG_THOI_TOI_DA)
    r = _dang_nhap_ts(KC(), "0900000001", MK, "10.99.0.8", cf="tot")
    assert r.status_code == 429 and "cf-turnstile" in r.text  # coi như chưa vượt
    assert turnstile == []
    monkeypatch.setattr(khach_web, "_ts_dang_goi", 0)
    token_launch(_dang_nhap_ts(KC(), "0900000001", MK, "10.99.0.8", cf="tot"))


def test_p2b_production_bat_buoc_tin_proxy_va_cookie_secure(monkeypatch, bat):
    monkeypatch.setattr(config, "ENV", "production")
    monkeypatch.setattr(config, "TIN_PROXY", False)
    monkeypatch.setattr(config, "COOKIE_SECURE", False)
    with pytest.raises(RuntimeError) as e:
        khach.kiem_cau_hinh()
    assert "COWORK_TIN_PROXY=1" in str(e.value) and "COWORK_COOKIE_SECURE=1" in str(e.value)
    monkeypatch.setattr(config, "TIN_PROXY", True)
    monkeypatch.setattr(config, "COOKIE_SECURE", True)
    with pytest.raises(RuntimeError) as e:
        khach.kiem_cau_hinh()
    assert "COWORK_TIN_PROXY" not in str(e.value) and "COWORK_COOKIE_SECURE" not in str(e.value)


# ================================================================== mã khách VG1001… (owner)
@pytest.mark.parametrize("raw, mong", [
    ("VG1001", "VG1001"), ("vg1001", "VG1001"), (" Vg1002 ", "VG1002"), ("VG10000", "VG10000"),
    ("VG123456789", "VG123456789"), ("VG999", None), ("VG1000", None), ("VG01001", None),
    ("VG0001001", None), ("VG000001", None), ("VG1234567890", None), ("VG10O1", None),
    ("VG 1001", None), ("XG1001", None), ("1001", None), ("VG", None), ("VG-1001", None),
])
def test_dinh_dang_portal_code(raw, mong):
    assert khach.chuan_hoa_portal_code(raw) == mong


def _cho_duyet(kh, n):
    dang_ky(kh, n)
    return acc_theo_sdt(f"+8490000000{n}")


def test_ket_qua_duyet_dinh_dang_ma_moi(kh):
    acc = _cho_duyet(kh, 1)
    for bad in ("VG999", "VG01001", "VG000001", "VG1000", "VG1234567890"):
        r = duyet(kh, acc["subject"], portal_code=bad)
        assert r.status_code == 400, bad
    r = duyet(kh, acc["subject"], portal_code="vg10000")  # chữ thường ⇒ lưu chữ hoa
    assert r.status_code == 200
    assert acc_theo_sdt("+84900000001")["portal_code"] == "VG10000"
    # Trùng portal_code ⇒ 409.
    acc2 = _cho_duyet(kh, 2)
    r = duyet(kh, acc2["subject"], 2, portal_code="VG10000")
    assert r.status_code == 409
    assert duyet(kh, acc2["subject"], 2, portal_code="VG1002").status_code == 200
    # Đăng nhập bằng mã chữ thường; mã và SĐT không nhập nhằng.
    token_launch(dang_nhap(kh, "vg10000"))
    tok = token_launch(dang_nhap(kh, "Vg1002"))
    assert crm_xac_minh_launch(tok, khach.portal_secret())["portal_code"] == "VG1002"
    assert dang_nhap(kh, "VG01002").status_code == 401  # số 0 đầu ⇒ không phải mã, sai chung
    assert dang_nhap(kh, "1002").status_code == 401


def test_db_check_tu_choi_ma_sai_dinh_dang(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    assert acc["portal_code"] == "VG1001"
    conn = db.connect()
    try:
        for bad in ("VG01001", "VG999", "VG000001", "VG12a4", "VG1234567890"):
            with pytest.raises(__import__("sqlite3").IntegrityError):
                conn.execute("UPDATE customer_accounts SET portal_code=? WHERE id=?", (bad, acc["id"]))
        conn.execute("UPDATE customer_accounts SET portal_code='VG123456789' WHERE id=?", (acc["id"],))
        conn.commit()
    finally:
        conn.close()


def _dung_bang_v4(conn, portal_code):
    """Dựng lại customer_accounts theo DDL v4 (CHECK VG + 6 số) với một dòng."""
    from cowork import schema
    import re as _re
    ddl = _re.search(r"CREATE TABLE IF NOT EXISTS customer_accounts\((.*?)\n\);", schema.DDL, _re.S).group(1)
    ddl_v4 = _re.sub(r"portal_code TEXT UNIQUE CHECK\(portal_code IS NULL OR \(.*?1001\)\),",
                     "portal_code TEXT UNIQUE CHECK(portal_code IS NULL OR portal_code GLOB "
                     "'VG[0-9][0-9][0-9][0-9][0-9][0-9]'),", ddl, flags=_re.S)
    ddl_v4 = ddl_v4.replace("    email_norm TEXT,\n", "    email_norm TEXT NOT NULL UNIQUE,\n")
    ddl_v4 = ddl_v4.replace("    phone_verified_method TEXT,\n", "")
    assert "VG[0-9][0-9][0-9][0-9][0-9][0-9]" in ddl_v4 and "email_norm TEXT NOT NULL UNIQUE" in ddl_v4
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DROP TABLE customer_accounts")
    conn.execute(f"CREATE TABLE customer_accounts({ddl_v4}\n)")
    now = db.now_iso()
    conn.execute(
        "INSERT INTO customer_accounts(id, subject, phone_e164, email_norm, display_name, "
        "password_hash, password_salt, status, consent_at, portal_code, crm_customer_id, "
        "created_at, updated_at) VALUES('kh_x','cust:kh_x','+84900000001','a@example.test','A',"
        "'h','s','hoat_dong',?,?,?,?,?)", (now, portal_code, "crm-x" if portal_code else None, now, now))
    conn.execute("INSERT INTO customer_sessions(id, token_hash, csrf_token, account_id, token_version, "
                 "created_at, last_seen_at, expires_at) VALUES('s1','th','c','kh_x',1,?,?,?)", (now, now, now))
    conn.execute("UPDATE meta SET value='4' WHERE key='schema_version'")
    conn.commit()
    conn.execute("PRAGMA foreign_keys=ON")


def test_migration_v5_dung_lai_bang_giu_du_lieu(client):
    conn = db.connect()
    try:
        _dung_bang_v4(conn, None)
    finally:
        conn.close()
    db._initialized = False
    db.init_db()
    conn = db.connect()
    try:
        sql = db.scalar(conn, "SELECT sql FROM sqlite_master WHERE name='customer_accounts'")
        assert "1001" in sql and "VG[0-9][0-9][0-9][0-9][0-9][0-9]" not in sql
        row = db.one(conn, "SELECT * FROM customer_accounts WHERE id='kh_x'")
        assert row["phone_e164"] == "+84900000001" and row["status"] == "hoat_dong"
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_sessions WHERE account_id='kh_x'") == 1
        assert db.scalar(conn, "SELECT value FROM meta WHERE key='schema_version'") == "6"
        assert db.scalar(conn, "SELECT COUNT(*) FROM sqlite_master WHERE name='idx_customer_crm_id'") == 1
        conn.execute("UPDATE customer_accounts SET portal_code='VG1001' WHERE id='kh_x'")
        conn.commit()
        # Khoá ngoại vẫn trỏ đúng bảng mới (xoá tài khoản ⇒ xoá phiên).
        conn.execute("DELETE FROM customer_accounts WHERE id='kh_x'")
        conn.commit()
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_sessions") == 0
    finally:
        conn.close()
    db._initialized = False
    db.init_db()  # chạy lại an toàn


def test_migration_v5_dung_khi_co_ma_kieu_cu(client):
    conn = db.connect()
    try:
        _dung_bang_v4(conn, "VG000001")
    finally:
        conn.close()
    db._initialized = False
    db.init_db()  # KHÔNG làm sập khởi động: realm khách tắt, nhân viên vẫn chạy
    assert db.KHACH_LOI and "VG1001" in db.KHACH_LOI
    conn = db.connect()
    try:  # không mất dữ liệu: bảng cũ còn nguyên; có audit lỗi
        assert db.scalar(conn, "SELECT portal_code FROM customer_accounts WHERE id='kh_x'") == "VG000001"
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE action='khach.migration.loi'") == 1
    finally:
        conn.close()
    db._initialized = False


# ================================================================== hồ sơ + đổi mật khẩu
def _doi_mk(c, cu, moi, moi2=None, csrf=None, **h):
    if csrf is None:
        csrf = csrf_tu(c.get("/tai-khoan/doi-mat-khau").text)
    return c.post("/tai-khoan/doi-mat-khau", data={"mat_khau_cu": cu, "mat_khau": moi,
                  "mat_khau_2": moi if moi2 is None else moi2, "_csrf": csrf},
                  headers=h, follow_redirects=False)


def test_ho_so_can_phien_va_hien_thong_tin(kh):
    for p in ("/tai-khoan/ho-so", "/tai-khoan/doi-mat-khau"):
        assert kh.get(p, follow_redirects=False).headers["location"] == "/tai-khoan/dang-nhap"
    tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    r = kh.get("/tai-khoan/ho-so")
    assert r.status_code == 200
    t = r.text
    assert "Khách Thử 1" in t and "VG1001" in t and "khach1@example.test" in t
    assert khach.che_sdt("+84900000001") in t and "+84900000001" not in t
    for link in ('href="/tai-khoan/vao-cong"', 'href="/tai-khoan/doi-mat-khau"',
                 'action="/tai-khoan/dang-xuat"'):
        assert link in t
    csp = r.headers["content-security-policy"]
    assert "script-src 'none'" in csp and "<script" not in t and "style=" not in t
    assert 'href="/tai-khoan/ho-so"' in kh.get("/tai-khoan/dang-nhap").text


def test_doi_mat_khau_thanh_cong(kh, crm, monkeypatch):
    monkeypatch.setattr(config, "KHACH_EMAIL_ENABLED", True)  # để kiểm email thông báo
    acc = tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    khac = KC()  # một thiết bị khác cũng đang đăng nhập
    token_launch(dang_nhap(khac, "0900000001"))
    tb_cu = kh.cookies.get("vg_khach_tb")
    phien_cu = kh.cookies.get("vg_khach")
    r = _doi_mk(kh, MK, MK_MOI)
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/ho-so?da_doi=1"
    moi = acc_theo_sdt("+84900000001")
    assert moi["token_version"] == acc["token_version"] + 1
    # Phiên hiện tại được thay bằng phiên mới; phiên cũ và thiết bị khác bị đăng xuất.
    assert kh.cookies.get("vg_khach") != phien_cu
    assert "Đã đổi mật khẩu" in kh.get("/tai-khoan/ho-so?da_doi=1").text
    token_launch(kh.get("/tai-khoan/vao-cong", follow_redirects=False))
    assert khac.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"] == \
        "/tai-khoan/dang-nhap"
    cu = KC()
    cu.cookies.set("vg_khach", phien_cu, domain="khach.localhost", path="/tai-khoan")
    assert cu.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"] == \
        "/tai-khoan/dang-nhap"
    # Cookie thiết bị: cũ mất hiệu lực, mới hợp lệ.
    assert not khach.thiet_bi_hop_le(tb_cu, moi)
    assert khach.thiet_bi_hop_le(kh.cookies.get("vg_khach_tb"), moi)
    # Email thông báo, CRM thu hồi phiên portal, audit.
    mail = outbox("doi_mat_khau", "khach1@example.test")[-1]
    assert "Mật khẩu vừa được thay đổi" in mail["subject"]
    assert MK_MOI not in mail["body_text"]
    assert crm.goi[-1]["url"].endswith("/api/internal/portal/thu-hoi")
    assert crm.goi[-1]["body"] == {"subject": acc["subject"], "reason": "doi_mat_khau"}
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE action='khach.doi_mat_khau' "
                         "AND target_id=?", (acc["subject"],)) == 1
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_sessions WHERE account_id=? "
                         "AND status='active'", (acc["id"],)) == 1
    finally:
        conn.close()
    assert dang_nhap(KC(), "0900000001", MK).status_code == 401
    token_launch(dang_nhap(KC(), "0900000001", MK_MOI))


def test_doi_mat_khau_kiem_du_lieu_csrf_va_cung_nguon(kh):
    acc = tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    for moi, moi2 in (("ngan!A1", None), (MK_MOI, "Khac!Passw0rd-99"), (MK, None),
                      ("aaaaaaaaaaaaaa", None)):
        r = _doi_mk(kh, MK, moi, moi2)
        assert r.status_code == 400, moi
    assert _doi_mk(kh, MK, MK_MOI, csrf="sai").status_code == 403
    tok = csrf_tu(kh.get("/tai-khoan/doi-mat-khau").text)
    assert _doi_mk(kh, MK, MK_MOI, csrf=tok, origin="https://evil.example").status_code == 403
    tho = TestClient(app, base_url=HOST_KHACH)  # không Origin, không Sec-Fetch-Site
    tho.cookies.set("vg_khach", kh.cookies.get("vg_khach"), domain="khach.localhost",
                    path="/tai-khoan")
    assert _doi_mk(tho, MK, MK_MOI, csrf=tok).status_code == 403
    # Token CSRF ẩn danh (không phải của phiên) không dùng được.
    anon = csrf_tu(KC().get("/tai-khoan/dang-nhap").text)
    assert _doi_mk(kh, MK, MK_MOI, csrf=anon).status_code == 403
    assert acc_theo_sdt("+84900000001")["token_version"] == acc["token_version"]


def test_doi_mat_khau_gioi_han_sai_mat_khau_hien_tai(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    ip = {"x-real-ip": "203.0.113.20"}
    token_launch(dang_nhap(kh, "0900000001", headers=ip))
    for _ in range(khach.DOI_MK_SAI_TOI_DA):
        assert _doi_mk(kh, "Sai!Passw0rd-xx", MK_MOI, **ip).status_code == 400
    goi = []
    orig = khach._scrypt
    monkeypatch.setattr(khach, "_scrypt", lambda *a: (goi.append(1), orig(*a))[1])
    r = _doi_mk(kh, MK, MK_MOI, **ip)  # đúng mật khẩu vẫn bị tạm khoá trên IP này
    assert r.status_code == 429 and goi == []
    # Theo (tài khoản, IP): IP khác vẫn đổi được.
    assert _doi_mk(kh, MK, MK_MOI, **{"x-real-ip": "198.51.100.20"}).status_code == 303


def test_ten_danh_rieng_moi_tren_host_nhan_vien(client, bat, crm, owner):
    for n in ("doi-mat-khau", "ho-so"):
        assert client.get(f"/tai-khoan/{n}", follow_redirects=False).status_code == 404
        from cowork import security
        assert security.kiem_tra_id(n)


# ================================================================== owner 07/11: bỏ xác minh
def test_bug_vipid_01_khong_meta_referrer_va_post_trinh_duyet(kh):
    """Chrome gửi Origin: null khi trang có <meta name=referrer content=no-referrer> ⇒ mọi form
    bị 403. Trang không được có meta đó; header Referrer-Policy: same-origin là đủ."""
    for p in ("/tai-khoan/dang-ky", "/tai-khoan/dang-nhap", "/tai-khoan/quen-mat-khau",
              "/tai-khoan/cho-duyet"):
        r = kh.get(p)
        assert 'name="referrer"' not in r.text, p
        assert r.headers["referrer-policy"] == "same-origin"
    tpl = (config.BASE_DIR / "cowork" / "templates" / "khach" / "base.html").read_text()
    assert "no-referrer" not in tpl
    # Trình duyệt thật: POST cùng nguồn gửi Origin thật + Sec-Fetch-Site ⇒ đi qua.
    trinh_duyet = TestClient(app, base_url=HOST_KHACH)
    tok = csrf_tu(trinh_duyet.get("/tai-khoan/dang-ky").text)
    r = trinh_duyet.post("/tai-khoan/dang-ky", data={
        "ho_ten": "Khách Trình Duyệt", "sdt": "0900000007", "email": "", "mat_khau": MK,
        "mat_khau_2": MK, "dong_y": "1", "_csrf": tok},
        headers={"origin": HOST_KHACH, "sec-fetch-site": "same-origin", "sec-fetch-mode": "navigate",
                 "referer": HOST_KHACH + "/tai-khoan/dang-ky"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    # Origin: null vẫn bị từ chối (sửa nguyên nhân, không nới kiểm tra).
    r = trinh_duyet.post("/tai-khoan/dang-nhap", data={"dinh_danh": "0900000007", "mat_khau": MK,
                         "_csrf": tok}, headers={"origin": "null", "sec-fetch-site": "same-origin"})
    assert r.status_code == 403


def test_duyet_khong_can_phone_verified_by(kh):
    dang_ky(kh, 1)
    acc = acc_theo_sdt("+84900000001")
    payload = {"subject": acc["subject"], "decision": "approved", "crm_customer_id": "crm-1",
               "portal_code": "VG1001"}
    r = goi_noi_bo(kh, "/api/internal/khach/ket-qua-duyet", payload)
    assert r.status_code == 200, r.text
    a = acc_theo_sdt("+84900000001")
    assert a["status"] == "hoat_dong" and a["phone_verified_at"]
    assert a["phone_verified_method"] == "duyet_crm" and a["phone_verified_by"] == "crm"
    token_launch(dang_nhap(kh, "VG1001"))
    # Có người duyệt ⇒ lưu đúng người duyệt.
    dang_ky(kh, 2)
    acc2 = acc_theo_sdt("+84900000002")
    r = goi_noi_bo(kh, "/api/internal/khach/ket-qua-duyet", {**payload, "subject": acc2["subject"],
                   "crm_customer_id": "crm-2", "portal_code": "VG1002", "approved_by": "nv-lan"})
    assert r.status_code == 200 and acc_theo_sdt("+84900000002")["phone_verified_by"] == "nv-lan"


def test_quen_mat_khau_hien_hotline(kh, monkeypatch):
    r = kh.get("/tai-khoan/quen-mat-khau")
    assert r.status_code == 200 and "0961 102 655" in r.text and "Zalo" in r.text
    assert "<form" not in r.text
    tok = csrf_tu(kh.get("/tai-khoan/dang-nhap").text)
    assert kh.post("/tai-khoan/quen-mat-khau", data={"dinh_danh": "0900000001",
                   "_csrf": tok}).status_code == 404
    monkeypatch.setattr(config, "KHACH_HOTLINE", "0900 000 999")
    assert "0900 000 999" in kh.get("/tai-khoan/quen-mat-khau").text


def test_tao_link_dat_lai_hmac_mot_lan_het_han_thu_hoi_phien(kh, crm):
    acc = tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    path = "/api/internal/khach/tao-link-dat-lai"
    body = json.dumps({"subject": acc["subject"], "requested_by": "nv-ho-tro"}).encode()
    # HMAC bắt buộc; sai đường dẫn ký ⇒ 401.
    assert kh.post(path, content=body).status_code == 401
    assert kh.post(path, content=body, headers=ky_vao("/api/internal/khach/thu-hoi", body)).status_code == 401
    assert goi_noi_bo(kh, path, {"subject": acc["subject"]}).status_code == 400  # thiếu requested_by
    assert goi_noi_bo(kh, path, {"subject": "cust:khong-co", "requested_by": "x"}).status_code == 404
    r = goi_noi_bo(kh, path, {"subject": acc["subject"], "requested_by": "nv-ho-tro"})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["url"].startswith(HOST_KHACH + "/tai-khoan/dat-lai?t=") and d["expires_at"]
    t1 = token_tu(d["url"], "/tai-khoan/dat-lai")
    conn = db.connect()
    try:  # chỉ lưu sha256; audit có người yêu cầu
        assert db.scalar(conn, "SELECT COUNT(*) FROM customer_tokens WHERE token_hash=?",
                         (hashlib.sha256(t1.encode()).hexdigest(),)) == 1
        assert t1 not in json.dumps(db.q(conn, "SELECT * FROM customer_tokens"))
        det = db.scalar(conn, "SELECT detail FROM audit_log WHERE action='khach.tao_link_dat_lai'")
        assert "nv-ho-tro" in det and t1 not in det
    finally:
        conn.close()
    # Link mới thay link cũ.
    t2 = link_dat_lai(kh, acc["subject"])
    assert kh.get(f"/tai-khoan/dat-lai?t={t1}").status_code == 400
    # GET không tiêu; POST tiêu một lần; thu hồi phiên; báo CRM.
    for _ in range(2):
        assert kh.get(f"/tai-khoan/dat-lai?t={t2}").status_code == 200
    csrf = _csrf(kh, f"/tai-khoan/dat-lai?t={t2}")
    d2 = {"t": t2, "mat_khau": MK_MOI, "mat_khau_2": MK_MOI, "_csrf": csrf}
    assert kh.post("/tai-khoan/dat-lai", data=d2).status_code == 200
    assert kh.post("/tai-khoan/dat-lai", data=d2).status_code == 400
    assert "dang-nhap" in kh.get("/tai-khoan/vao-cong", follow_redirects=False).headers["location"]
    assert crm.goi[-1]["body"] == {"subject": acc["subject"], "reason": "dat_lai_mat_khau"}
    token_launch(dang_nhap(KC(), "0900000001", MK_MOI))
    # Hết hạn.
    t3 = link_dat_lai(kh, acc["subject"])
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_tokens SET expires_at='2020-01-01T00:00:00+07:00' "
                     "WHERE used_at IS NULL")
        conn.commit()
    finally:
        conn.close()
    assert kh.get(f"/tai-khoan/dat-lai?t={t3}").status_code == 400
    # Tài khoản bị khoá ⇒ không cấp link.
    goi_noi_bo(kh, "/api/internal/khach/tam-khoa", {"subject": acc["subject"], "action": "khoa"})
    assert goi_noi_bo(kh, path, {"subject": acc["subject"], "requested_by": "x"}).status_code == 409


def test_khong_gui_email_khi_tat(kh, crm):
    acc = tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001"))
    t = link_dat_lai(kh, acc["subject"])
    kh.post("/tai-khoan/dat-lai", data={"t": t, "mat_khau": MK_MOI, "mat_khau_2": MK_MOI,
                                       "_csrf": _csrf(kh, f"/tai-khoan/dat-lai?t={t}")})
    assert outbox() == []


def test_migration_v6_email_tuy_chon(client):
    conn = db.connect()
    try:
        _dung_bang_v4(conn, None)  # DDL cũ còn email_norm TEXT NOT NULL UNIQUE + CHECK VG 6 số
        sql = db.scalar(conn, "SELECT sql FROM sqlite_master WHERE name='customer_accounts'")
        assert "email_norm TEXT NOT NULL UNIQUE" in sql
    finally:
        conn.close()
    db._initialized = False
    db.init_db()
    conn = db.connect()
    try:
        sql = db.scalar(conn, "SELECT sql FROM sqlite_master WHERE name='customer_accounts'")
        assert "email_norm TEXT," in sql and "phone_verified_method" in sql
        assert db.one(conn, "SELECT email_norm FROM customer_accounts WHERE id='kh_x'")["email_norm"] == "a@example.test"
        assert db.scalar(conn, "SELECT value FROM meta WHERE key='schema_version'") == "6"
        now = db.now_iso()
        for i in (2, 3):  # email trùng / trống được phép
            conn.execute("INSERT INTO customer_accounts(id, subject, phone_e164, email_norm, display_name, "
                         "password_hash, password_salt, consent_at, created_at, updated_at) "
                         "VALUES(?,?,?,?, 'B','h','s',?,?,?)",
                         (f"kh_{i}", f"cust:kh_{i}", f"+8490000000{i}",
                          "a@example.test" if i == 2 else None, now, now, now))
        conn.commit()
    finally:
        conn.close()


# ================================================================== rà soát vòng 5
def test_n5_1_request_khong_goi_crm_thoi_gian_khong_lo_nhanh(kh, crm, monkeypatch):
    crm.cham = 1.0  # CRM chậm 1 giây
    tao_khach_hoat_dong(kh, 1)               # SĐT 1: đang hoạt động
    dang_ky(kh, 2)                           # SĐT 2: đang chờ duyệt
    crm.goi_that.clear()
    t = {}
    for ten, n, email in (("moi", 3, None), ("cho_duyet", 2, "khac2@example.test"),
                          ("hoat_dong", 1, "khac1@example.test")):
        t0 = time.perf_counter()
        r = dang_ky(KC(), n, email=email)
        t[ten] = time.perf_counter() - t0
        assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    assert crm.goi_that == []  # không có lời gọi CRM nào trong request
    assert max(t.values()) < 0.9, t  # không chờ CRM chậm
    assert max(t.values()) - min(t.values()) < 0.3, t
    # Vòng nền gửi sau đó.
    from cowork import khach_web
    crm.cham = 0
    kq = khach_web.dong_bo_mot_luot()
    assert kq["thanh_cong"] >= 2 and crm.goi_that


def test_n5_1_vong_nen_gui_hang_doi(kh, crm, monkeypatch):
    import asyncio
    from cowork import khach_web
    dang_ky(kh, 1)
    assert crm.goi_that == []
    monkeypatch.setattr(config, "KHACH_SYNC_GIAY", 0.01)

    async def chay():
        task = asyncio.create_task(khach_web.vong_dong_bo_crm())
        for _ in range(200):
            await asyncio.sleep(0.02)
            if crm.goi_that:
                break
        task.cancel()
    asyncio.run(chay())
    assert crm.goi_that and crm.goi_that[0]["url"].endswith("/api/internal/portal/signups")


def test_n5_2_dang_ky_bat_buoc_turnstile(kh, monkeypatch, turnstile):
    r = kh.get("/tai-khoan/dang-ky")
    assert 'class="cf-turnstile"' in r.text and 'data-action="khach_dang_ky"' in r.text
    assert "script-src https://challenges.cloudflare.com;" in r.headers["content-security-policy"]
    tok = csrf_tu(r.text)
    base = {"ho_ten": "Khách Máy", "sdt": "0900000004", "email": "", "mat_khau": MK,
            "mat_khau_2": MK, "dong_y": "1", "_csrf": tok}
    # Thiếu token / token của action đăng nhập ⇒ không tạo tài khoản.
    for extra in ({}, {"cf-turnstile-response": "tot"}, {"cf-turnstile-response": "dk-sai-action"}):
        r = kh.post("/tai-khoan/dang-ky", data={**base, **extra}, follow_redirects=False)
        assert r.status_code == 400 and "cf-turnstile" in r.text, extra
    assert acc_theo_sdt("+84900000004") is None
    # Khác nguồn ⇒ 403 và KHÔNG gọi siteverify.
    n0 = len(turnstile.dang_ky)
    r = kh.post("/tai-khoan/dang-ky", data={**base, "cf-turnstile-response": "tot-dk"},
                headers={"origin": "https://evil.example"})
    assert r.status_code == 403 and len(turnstile.dang_ky) == n0
    r = kh.post("/tai-khoan/dang-ky", data={**base, "cf-turnstile-response": "tot-dk"},
                follow_redirects=False)
    assert r.status_code == 303 and acc_theo_sdt("+84900000004")["status"] == "cho_duyet"


def test_n5_2_tran_dang_ky_toan_he_thong(kh, monkeypatch):
    _ip(monkeypatch)
    monkeypatch.setattr(config, "KHACH_SIGNUP_GLOBAL_PER_HOUR", 2)
    for n in (1, 2):
        assert dang_ky(KC(), n, headers={"x-real-ip": f"10.5.0.{n}"}).status_code == 303
    for n in (3, 4):
        r = dang_ky(KC(), n, headers={"x-real-ip": f"10.5.0.{n}"})
        assert r.status_code == 503 and "quá nhiều đăng ký" in r.text
        assert acc_theo_sdt(f"+8490000000{n}") is None
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE "
                         "action='khach.canh_bao.dang_ky_tang_dot_bien'") == 1
    finally:
        conn.close()


def test_n5_2_gop_cap_nhat_xung_dot(kh, crm, monkeypatch):
    _ip(monkeypatch)
    dang_ky(kh, 1)
    crm.goi  # gửi signup đầu
    crm.goi_that.clear()
    for i in range(5):
        dang_ky(KC(), 1, email=f"ke{i}@example.test", headers={"x-real-ip": f"10.6.0.{i}"})
    goi = [g for g in crm.goi if g["body"].get("phone_conflict")]
    assert len(goi) == 1 and goi[0]["body"]["phone_conflict_count"] == 1
    assert acc_theo_sdt("+84900000001")["phone_conflict_count"] == 5
    # Sau một giờ, lần xung đột tiếp theo gửi số mới nhất.
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_rate_events SET created_at='2020-01-01T00:00:00+07:00' "
                     "WHERE bucket='xung_dot_crm'")
        conn.commit()
    finally:
        conn.close()
    dang_ky(KC(), 1, email="ke9@example.test", headers={"x-real-ip": "10.6.0.9"})
    goi = [g for g in crm.goi if g["body"].get("phone_conflict")]
    assert len(goi) == 2 and goi[-1]["body"]["phone_conflict_count"] == 6


def test_n5_3_doi_mat_khau_dem_theo_tai_khoan_moi_ip(kh, monkeypatch):
    _ip(monkeypatch)
    tao_khach_hoat_dong(kh, 1)
    token_launch(dang_nhap(kh, "0900000001", headers={"x-real-ip": "198.51.100.30"}))
    for i in range(khach.DOI_MK_SAI_TK_TOI_DA):  # mỗi IP chỉ 2 lần ⇒ không chạm khoá theo cặp
        r = _doi_mk(kh, "Sai!Passw0rd-xx", MK_MOI, **{"x-real-ip": f"10.7.{i // 2}.1"})
        assert r.status_code == 400
    r = _doi_mk(kh, MK, MK_MOI, **{"x-real-ip": "198.51.100.31"})
    assert r.status_code == 429
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM audit_log WHERE "
                         "action='khach.doi_mat_khau.tam_khoa_tai_khoan'") == 1
    finally:
        conn.close()


def test_n5_4_chuyen_cho_xac_minh_email_sang_cho_duyet(kh, crm):
    dang_ky(kh, 1)
    acc = acc_theo_sdt("+84900000001")
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_accounts SET status='cho_xac_minh_email' WHERE id=?", (acc["id"],))
        conn.execute("DELETE FROM crm_sync_pending")
        conn.commit()
    finally:
        conn.close()
    db._initialized = False
    db.init_db()
    assert acc_theo_sdt("+84900000001")["status"] == "cho_duyet"
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM crm_sync_pending WHERE subject=? AND done_at IS NULL",
                         (acc["subject"],)) == 1
    finally:
        conn.close()
    assert crm.goi[-1]["body"]["subject"] == acc["subject"]


def test_n5_5_loi_nang_cap_khong_sap_realm_nhan_vien(client, bat, crm, owner):
    conn = db.connect()
    try:
        _dung_bang_v4(conn, "VG000001")
    finally:
        conn.close()
    db._initialized = False
    db.init_db()
    assert db.KHACH_LOI and not khach.realm_bat()
    # Nhân viên vẫn đăng nhập/dùng được.
    assert dang_nhap_nv(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    assert client.get("/tai-khoan").status_code == 200
    # Host khách không được phục vụ (realm coi như tắt; Host không thuộc danh sách nhân viên ⇒ 421).
    r = KC().get("/tai-khoan/dang-nhap")
    assert r.status_code == 421
