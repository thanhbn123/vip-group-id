"""§16 — Đăng ký TỰ KÍCH HOẠT (owner chốt 09/11/2026, DE_XUAT_TU_DONG_DUYET §5–6).

Cờ COWORK_KHACH_TU_DONG: tắt ⇒ luồng chờ duyệt cũ y nguyên; bật ⇒ kiểm trùng tại VIP ID, gọi CRM
đồng bộ `/api/internal/portal/dang-ky-tu-dong`, chỉ `kich_hoat` mới tạo tài khoản `hoat_dong`.
Chỉ dữ liệu tổng hợp (SĐT +8490000000x, email @example.test).
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import json
import re
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from cowork import config, db, khach

from conftest import csrf_tu
from test_khach_p1 import (DK, DN, KC, MK, acc_theo_sdt, bat, crm, dang_nhap,  # noqa: F401
                           duyet, hai_host, token_launch)

CRM_NOI_BO = "http://127.0.0.1:8897"
_HTTP_THAT = khach._http_post_tu_dong  # bản thật (gọi HTTP) — fixture CRM giả thay thế nó


# ------------------------------------------------------------------ fixture
@pytest.fixture()
def crm_td(monkeypatch):
    """CRM giả cho lời gọi ĐỒNG BỘ §16: kiểm HMAC như CRM thật, ghi lại mọi lần gọi.

    `che_do`: 'kich_hoat' | 'tai_khoan_cong' | 'ho_so_cu' | hàm(body) -> (status, bytes)."""
    class _F:
        che_do = "kich_hoat"
        cham = 0.0
        goi: list[dict] = []
        ma = 1000

    f = _F()
    f.goi = []
    khoa = threading.Lock()

    def _post(url, body, headers):
        h = {k.lower(): v for k, v in headers.items()}
        path = url[len(config.CRM_PORTAL_INTERNAL_URL):]
        mong = hmac.new(khach.portal_secret().encode(),
                        khach.chuoi_ky("vipid->crm", "POST", path, h["x-portal-ts"], body),
                        hashlib.sha256).hexdigest()
        f.goi.append({"url": url, "path": path, "body": json.loads(body), "headers": h,
                      "raw": body, "ky_dung": hmac.compare_digest(mong, h["x-portal-sig"])})
        if f.cham:
            time.sleep(f.cham)
        if callable(f.che_do):
            return f.che_do(json.loads(body))
        if f.che_do == "kich_hoat":
            with khoa:
                f.ma += 1
                n = f.ma
            return 200, json.dumps({"ok": True, "data": {
                "trang_thai": "kich_hoat", "crm_customer_id": f"crm-td-{n}",
                "portal_code": f"VG{n}"}}).encode()
        return 200, json.dumps({"ok": True, "data": {"trang_thai": "trung",
                                                     "loai": f.che_do}}).encode()

    monkeypatch.setattr(khach, "_http_post_tu_dong", _post)
    return f


@pytest.fixture()
def td(hai_host, crm_td, monkeypatch):
    """Hai host (dangky/dangnhap) + cờ tự kích hoạt BẬT."""
    monkeypatch.setattr(config, "KHACH_TU_DONG", True)
    return hai_host


def _form(c, n: int = 1, sdt: str | None = None, **extra) -> dict:
    data = {"ho_ten": f"Khách Tự Động {n}", "sdt": sdt or f"090000000{n}",
            "email": f"td{n}@example.test", "mat_khau": MK, "mat_khau_2": MK, "dong_y": "1",
            "_csrf": csrf_tu(c.get("/tai-khoan/dang-ky").text)}
    data.update(extra)
    return data


def dk(c, n: int = 1, sdt: str | None = None, headers=None, **extra):
    return c.post("/tai-khoan/dang-ky", data=_form(c, n, sdt, **extra), follow_redirects=False,
                  headers=headers or {})


def _so_tk() -> int:
    conn = db.connect()
    try:
        return int(db.scalar(conn, "SELECT COUNT(*) FROM customer_accounts"))
    finally:
        conn.close()


def _audit(action: str) -> list[dict]:
    conn = db.connect()
    try:
        return db.q(conn, "SELECT * FROM audit_log WHERE tenant_id='khach' AND action=? "
                    "ORDER BY id", (action,))
    finally:
        conn.close()


def _handoff(html: str) -> str:
    m = re.search(r'name="t" value="([^"]+)"', html)
    assert m, html[:500]
    return m.group(1)


def _sub(html: str) -> str:
    m = re.search(r'name="_sub" value="([^"]+)"', html)
    assert m, html[:500]
    return m.group(1)


def _nhan(c, t: str, origin: str = DK):
    return c.post("/tai-khoan/nhan-phien", data={"t": t}, headers={"origin": origin},
                  follow_redirects=False)


def _csp_sach(r) -> str:
    csp = r.headers["content-security-policy"]
    assert "script-src 'none'" in csp and "unsafe-inline" not in csp
    assert "<script" not in r.text and "style=" not in r.text
    return csp


# ------------------------------------------------------------------ cờ tắt: không đổi gì
def test_co_tat_luong_cho_duyet_y_nguyen(hai_host, crm_td):
    assert config.KHACH_TU_DONG is False
    dkc, dnc = hai_host
    assert "nhân viên VIP GROUP sẽ duyệt" in dkc.get("/tai-khoan/dang-ky").text
    r = dk(dkc, 1)
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    acc = acc_theo_sdt("+84900000001")
    assert acc["status"] == "cho_duyet" and acc["crm_customer_id"] is None
    assert crm_td.goi == []  # không gọi API đồng bộ
    assert _nhan(dnc, "v1.x.1.y.z").status_code == 404  # route chuyển phiên không tồn tại


# ------------------------------------------------------------------ thành công
def test_thanh_cong_tao_tai_khoan_hoat_dong_va_dang_nhap_ngay(td, crm_td):
    dkc, dnc = td
    assert "kích hoạt ngay" in dkc.get("/tai-khoan/dang-ky").text
    r = dk(dkc, 1, headers={"x-forwarded-for": "203.0.113.9", "user-agent": "trinh-duyet"})
    assert r.status_code == 201, r.text[:400]
    assert "Tạo tài khoản thành công" in r.text and "VG1001" in r.text
    assert "Vào cổng khách hàng" in r.text and f'action="{DN}/tai-khoan/nhan-phien"' in r.text
    assert MK not in r.text
    csp = _csp_sach(r)
    assert f"form-action 'self' {DN} http://crm.localhost:8897;" in csp

    acc = acc_theo_sdt("+84900000001")
    assert acc["status"] == "hoat_dong" and acc["phone_verified_at"]
    assert acc["phone_verified_method"] == "tu_dong"
    assert acc["crm_customer_id"] == "crm-td-1001" and acc["portal_code"] == "VG1001"
    assert acc["password_hash"] and MK not in json.dumps(acc)
    au = _audit("khach.dang_ky.tu_dong")
    assert len(au) == 1 and au[0]["target_id"] == acc["subject"]
    assert json.loads(au[0]["detail"])["portal_code"] == "VG1001"

    # Lời gọi CRM: đúng URL nội bộ + path, ký HMAC vipid->crm chuẩn, body đúng 4 trường,
    # không chuyển tiếp header của trình duyệt.
    (g,) = crm_td.goi
    assert g["url"] == CRM_NOI_BO + "/api/internal/portal/dang-ky-tu-dong" and g["ky_dung"]
    assert g["body"] == {"subject": acc["subject"], "display_name": "Khách Tự Động 1",
                         "phone_e164": "+84900000001", "email": "td1@example.test"}
    assert g["headers"]["idempotency-key"] == acc["subject"]
    assert set(g["headers"]) == {"content-type", "idempotency-key", "x-portal-ts", "x-portal-sig"}
    # Chữ ký gắn method + path: đem sang path khác là sai.
    sai = hmac.new(khach.portal_secret().encode(), khach.chuoi_ky(
        "vipid->crm", "POST", "/api/internal/portal/signups", g["headers"]["x-portal-ts"],
        g["raw"]), hashlib.sha256).hexdigest()
    assert sai != g["headers"]["x-portal-sig"]

    # Đăng nhập ngay như tài khoản được duyệt: bằng SĐT và bằng mã VG.
    token_launch(dang_nhap(dnc, "0900000001"))
    token_launch(dang_nhap(KC(DN), "vg1001"))
    # Không xếp hàng signup cũ cho tài khoản tự kích hoạt.
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM crm_sync_pending WHERE kind='signup'") == 0
    finally:
        conn.close()


def test_email_trong_gui_null(td, crm_td):
    dkc, _ = td
    assert dk(dkc, 2, email="").status_code == 201
    assert crm_td.goi[0]["body"]["email"] is None


# ------------------------------------------------------------------ token chuyển phiên
def test_handoff_tao_phien_dangnhap_va_vao_cong(td, crm_td):
    dkc, dnc = td
    t = _handoff(dk(dkc, 1).text)
    r = _nhan(dnc, t)
    token_launch(r)  # 303 thẳng sang CRM launch
    cks = r.headers.get_list("set-cookie")
    assert any(c.startswith("vg_khach=") for c in cks)
    assert all("domain=" not in c.lower() for c in cks)
    assert dnc.get("/tai-khoan/ho-so").status_code == 200  # phiên dangnhap dùng được
    assert len(_audit("khach.handoff")) == 1
    # Phát lại ⇒ từ chối, không tạo phiên mới.
    r2 = _nhan(KC(DN), t)
    assert r2.status_code == 400 and "đã hết hạn hoặc đã được dùng" in r2.text
    assert not any(c.startswith("vg_khach=") for c in r2.headers.get_list("set-cookie"))


def test_handoff_het_han(td, crm_td, monkeypatch):
    dkc, dnc = td
    t = _handoff(dk(dkc, 1).text)
    # Đồng hồ vượt 60 giây ⇒ token hết hạn.
    that = time.time
    monkeypatch.setattr(khach.time, "time", lambda: that() + 61)
    assert _nhan(dnc, t).status_code == 400
    monkeypatch.setattr(khach.time, "time", that)
    # Dòng DB hết hạn (dù phần ký còn hạn) ⇒ từ chối.
    t2 = _handoff(dk(dkc, 2).text)
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_handoff SET expires_at='2000-01-01T00:00:00+07:00'")
        conn.commit()
    finally:
        conn.close()
    assert _nhan(dnc, t2).status_code == 400
    # Token tự đặt hạn dài hơn 60 giây (ký hợp lệ) ⇒ từ chối.
    acc = acc_theo_sdt("+84900000002")
    du = f"v1.{acc['id']}.{int(time.time()) + 3600}.abc"
    assert _nhan(dnc, f"{du}.{khach._ky('khach-handoff', du)}").status_code == 400


def test_handoff_sai_tai_khoan_sai_chu_ky(td, crm_td):
    dkc, dnc = td
    ta = _handoff(dk(dkc, 1).text)
    dk(dkc, 2)
    b = acc_theo_sdt("+84900000002")
    _, _, exp, nonce, _ = ta.split(".")
    # Nonce của A gắn sang tài khoản B (ký hợp lệ) ⇒ DB không khớp tài khoản.
    du = f"v1.{b['id']}.{exp}.{nonce}"
    assert _nhan(dnc, f"{du}.{khach._ky('khach-handoff', du)}").status_code == 400
    # Đổi tài khoản mà không ký lại ⇒ sai chữ ký.
    gia = ta.replace(ta.split(".")[1], b["id"])
    assert _nhan(dnc, gia).status_code == 400
    for rac in ("", "abc", "v1.a.b.c.d", ta + "x", "v2" + ta[2:]):
        assert _nhan(dnc, rac).status_code == 400, rac
    # Các lượt sai không làm hỏng token thật của A.
    token_launch(_nhan(dnc, ta))


def test_handoff_chi_tren_dangnhap_va_chi_tu_dangky(td, crm_td, client):
    dkc, dnc = td
    t = _handoff(dk(dkc, 1).text)
    assert _nhan(dkc, t).status_code == 404                     # host dangky không phục vụ
    # Host nhân viên: không có route này (realm nhân viên từ chối POST lạ).
    assert client.post("/tai-khoan/nhan-phien", data={"t": t}).status_code in (403, 404)
    for o in ("https://evil.example", DN, "null"):              # chỉ nhận Origin = dangky
        assert _nhan(dnc, t, origin=o).status_code == 403, o
    from fastapi.testclient import TestClient
    from cowork.main import app
    r = TestClient(app, base_url=DN).post("/tai-khoan/nhan-phien", data={"t": t},
                                          follow_redirects=False)
    assert r.status_code == 403  # thiếu Origin và không có Sec-Fetch-Site same-origin
    token_launch(_nhan(dnc, t))  # chưa bị tiêu bởi các lượt bị từ chối


def test_handoff_tai_khoan_bi_khoa_sau_khi_tao(td, crm_td):
    dkc, dnc = td
    t = _handoff(dk(dkc, 1).text)
    acc = acc_theo_sdt("+84900000001")
    from test_khach_p1 import goi_noi_bo
    assert goi_noi_bo(dnc, "/api/internal/khach/tam-khoa",
                      {"subject": acc["subject"], "action": "khoa"}).status_code == 200
    assert _nhan(dnc, t).status_code == 400


def test_dang_nhap_dien_san_ma_vg(td, crm_td):
    _, dnc = td
    assert 'value="VG1001"' in dnc.get("/tai-khoan/dang-nhap?u=vg1001").text
    t = dnc.get("/tai-khoan/dang-nhap?u=0900000001").text
    assert "0900000001" not in t  # không điền SĐT từ URL


# ------------------------------------------------------------------ trùng
def test_trung_tai_vip_id_khong_goi_crm(td, crm_td):
    dkc, _ = td
    assert dk(dkc, 1).status_code == 201
    n = len(crm_td.goi)
    for sdt in ("0900000001", "+84 900 000 001", "84900000001"):
        r = dk(KC(DK), 9, sdt=sdt)
        assert r.status_code == 409 and "Số điện thoại này đã được đăng ký" in r.text, sdt
        assert f'href="{DK}/tai-khoan/dang-ky"' in r.text
        assert f'href="{DN}/tai-khoan/dang-nhap"' in r.text
        assert f'href="{DN}/tai-khoan/quen-mat-khau"' in r.text
        _csp_sach(r)
    assert len(crm_td.goi) == n and _so_tk() == 1


def test_trung_voi_tai_khoan_cho_duyet_cu(hai_host, crm_td, monkeypatch):
    dkc, _ = hai_host
    assert dk(dkc, 1).status_code == 303  # cờ tắt: tạo cho_duyet
    monkeypatch.setattr(config, "KHACH_TU_DONG", True)
    r = dk(KC(DK), 1)
    assert r.status_code == 409 and "đã được đăng ký" in r.text
    assert crm_td.goi == []
    assert acc_theo_sdt("+84900000001")["phone_conflict_count"] == 1


def test_crm_tai_khoan_cong(td, crm_td):
    dkc, _ = td
    crm_td.che_do = "tai_khoan_cong"
    r = dk(dkc, 1)
    assert r.status_code == 409 and "Số điện thoại này đã được đăng ký" in r.text
    assert _so_tk() == 0 and len(crm_td.goi) == 1


def test_crm_ho_so_cu(td, crm_td):
    dkc, _ = td
    crm_td.che_do = "ho_so_cu"
    r = dk(dkc, 7)
    assert r.status_code == 409
    assert "Số này đã có hồ sơ khách hàng tại VIP GROUP" in r.text
    assert "0961 102 655" in r.text and "Dùng số khác" in r.text
    assert "quen-mat-khau" not in r.text
    csp = _csp_sach(r)
    assert DN not in csp
    assert _so_tk() == 0


# ------------------------------------------------------------------ CRM lỗi ⇒ không tạo gì
def _tra(status: int, body: bytes):
    return lambda _b: (status, body)


def _nem(exc):
    def f(_b):
        raise exc
    return f


@pytest.mark.parametrize("che_do", [
    _tra(503, b'{"ok":false,"error":{"code":"AUTO_APPROVE_OFF"}}'),
    _tra(401, b'{"ok":false,"error":{"code":"SIGNATURE_INVALID"}}'),
    _tra(409, b'{"ok":false,"error":{"code":"PHAT_LAI"}}'),
    _tra(200, b"<html>khong phai json"),
    _tra(200, b'{"ok":true}'),
    _tra(200, b'[1,2]'),
    _tra(200, b'{"ok":true,"data":{"trang_thai":"la"}}'),
    _tra(200, b'{"ok":true,"data":{"trang_thai":"trung","loai":"khac"}}'),
    _tra(200, b'{"ok":true,"data":{"trang_thai":"kich_hoat","crm_customer_id":"x1"}}'),
    _tra(200, b'{"ok":true,"data":{"trang_thai":"kich_hoat","crm_customer_id":"x1",'
              b'"portal_code":"VG999"}}'),
    _tra(200, b'{"ok":true,"data":{"trang_thai":"kich_hoat","crm_customer_id":"a b",'
              b'"portal_code":"VG1001"}}'),
    _tra(200, b'{"ok":"true","data":{"trang_thai":"kich_hoat","crm_customer_id":"x1",'
              b'"portal_code":"VG1001"}}'),
    _nem(TimeoutError("read timeout")),
    _nem(ConnectionError("refused")),
], ids=["503", "401-chu-ky", "409", "html", "thieu-data", "mang", "trang-thai-la", "loai-la",
        "thieu-ma", "ma-sai", "crm-id-sai", "ok-chuoi", "timeout", "mang-loi"])
def test_crm_loi_khong_tao_tai_khoan(td, crm_td, che_do):
    dkc, _ = td
    crm_td.che_do = che_do
    r = dk(dkc, 1)
    assert r.status_code == 503 and khach.THONG_BAO_BAN in r.text
    assert 'value="Khách Tự Động 1"' in r.text and MK not in r.text  # giữ họ tên, không giữ mật khẩu
    _csp_sach(r)
    assert _so_tk() == 0
    conn = db.connect()
    try:
        assert db.scalar(conn, "SELECT COUNT(*) FROM crm_sync_pending") == 0  # không xếp hàng
    finally:
        conn.close()
    assert _audit("khach.dang_ky.tu_dong.crm_loi")


def test_crm_cham_qua_han_chot(td, crm_td, monkeypatch):
    dkc, _ = td
    monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.5)
    crm_td.cham = 2.5
    t0 = time.monotonic()
    r = dk(dkc, 1)
    assert r.status_code == 503 and time.monotonic() - t0 < 2.2  # không chờ hết 2,5 s của CRM
    time.sleep(2.2)  # lời gọi treo kết thúc trong executor: vẫn KHÔNG tạo tài khoản
    assert _so_tk() == 0


def test_thu_lai_sau_ban_dung_lai_subject(td, crm_td, monkeypatch):
    monkeypatch.setattr(config, "KHACH_SIGNUP_IP_PER_HOUR", 50)
    dkc, _ = td
    crm_td.che_do = _tra(503, b"{}")
    r = dk(dkc, 1)
    sub = _sub(r.text)
    crm_td.che_do = "kich_hoat"
    assert dk(dkc, 1, _sub=sub).status_code == 201
    s1, s2 = (g["body"]["subject"] for g in crm_td.goi)
    assert s1 == s2 and acc_theo_sdt("+84900000001")["subject"] == s1
    # Subject ký gắn SĐT + trình duyệt: số khác hoặc trình duyệt khác ⇒ subject mới.
    crm_td.che_do = _tra(503, b"{}")
    sub3 = _sub(dk(dkc, 3).text)
    assert dk(dkc, 4, _sub=sub3).status_code == 503
    assert crm_td.goi[-1]["body"]["subject"] != crm_td.goi[-2]["body"]["subject"]
    assert dk(KC(DK), 3, _sub=sub3).status_code == 503
    assert crm_td.goi[-1]["body"]["subject"] != crm_td.goi[-3]["body"]["subject"]
    assert dk(dkc, 3, _sub=sub3[:-2] + "00").status_code == 503  # chữ ký sai ⇒ subject mới
    assert crm_td.goi[-1]["body"]["subject"] != crm_td.goi[-4]["body"]["subject"]


def test_luu_cuc_bo_loi_ghi_mo_coi(td, crm_td):
    """CRM kích hoạt nhưng mã VG trùng tài khoản khác ở VIP ID ⇒ không tạo, báo bận, audit mồ côi."""
    dkc, _ = td
    assert dk(dkc, 1).status_code == 201
    crm_td.che_do = _tra(200, json.dumps({"ok": True, "data": {
        "trang_thai": "kich_hoat", "crm_customer_id": "crm-khac", "portal_code": "VG1001"}}).encode())
    assert dk(dkc, 2).status_code == 503
    assert _so_tk() == 1
    (mc,) = _audit("khach.dang_ky.tu_dong.mo_coi")
    assert json.loads(mc["detail"])["crm_customer_id"] == "crm-khac"


# ------------------------------------------------------------------ đồng thời
def test_dong_thoi_cung_sdt_chi_mot_tai_khoan(td, crm_td, monkeypatch):
    """CRM (giả) KHÔNG chống trùng — VIP ID vẫn chỉ ra một tài khoản nhờ UNIQUE(phone)."""
    monkeypatch.setattr(config, "TIN_PROXY", True)
    crm_td.cham = 0.2
    kq: list[int] = []
    cs = [KC(DK) for _ in range(5)]
    forms = [_form(c, 1) for c in cs]

    def luot(i):
        r = cs[i].post("/tai-khoan/dang-ky", data=forms[i], follow_redirects=False,
                       headers={"x-real-ip": f"10.0.0.{i + 1}"})
        kq.append(r.status_code)
    ts = [threading.Thread(target=luot, args=(i,)) for i in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(kq).count(201) == 1 and all(k in (201, 409) for k in kq), kq
    assert _so_tk() == 1
    # Mỗi lượt thua đã qua CRM đều được ghi audit mồ côi để đối soát.
    assert len(_audit("khach.dang_ky.tu_dong.mo_coi")) == len(crm_td.goi) - 1


# ------------------------------------------------------------------ luồng chờ duyệt cũ vẫn chạy
def test_cho_duyet_cu_van_duyet_duoc_khi_bat_co(hai_host, crm_td, monkeypatch):
    dkc, dnc = hai_host
    assert dk(dkc, 1).status_code == 303
    monkeypatch.setattr(config, "KHACH_TU_DONG", True)
    acc = acc_theo_sdt("+84900000001")
    assert duyet(dnc, acc["subject"], 1).status_code == 200
    token_launch(dang_nhap(dnc, "0900000001"))


def test_pilot_chan_truoc_khi_goi_crm(td, crm_td, monkeypatch, tmp_path):
    dkc, _ = td
    monkeypatch.setattr(config, "KHACH_PILOT", True)
    monkeypatch.setattr(config, "KHACH_PILOT_PHONES", ["0900000001"])
    monkeypatch.setattr(config, "KHACH_PILOT_FILE", tmp_path / "pilot.txt")
    khach._pilot_cache.update(khoa=None)
    r = dk(dkc, 2)
    assert r.status_code == 403 and "chạy thử" in r.text
    assert crm_td.goi == [] and _so_tk() == 0
    assert dk(dkc, 1).status_code == 201


# ------------------------------------------------------------------ CRM giả thật qua HTTP
@pytest.fixture()
def mock_crm(td, monkeypatch):
    p = Path(__file__).resolve().parent.parent / "scripts" / "khach_mock_crm.py"
    spec = importlib.util.spec_from_file_location("khach_mock_crm_td", p)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    monkeypatch.setattr(khach, "_http_post_tu_dong", _HTTP_THAT)
    monkeypatch.setenv("VIPID_PORTAL_SECRET", khach.portal_secret())
    srv = ThreadingHTTPServer(("127.0.0.1", 0), m.H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL", f"http://127.0.0.1:{srv.server_port}")
    yield m, srv.server_port
    srv.shutdown()


def test_mock_crm_http_that(td, mock_crm, monkeypatch):
    monkeypatch.setattr(config, "KHACH_SIGNUP_IP_PER_HOUR", 50)
    m, port = mock_crm
    dkc, dnc = td
    r = dk(dkc, 1)
    assert r.status_code == 201 and "VG1001" in r.text
    assert m.HOST_NHAN == [f"127.0.0.1:{port}"]  # Host = host nội bộ của CRM, không phải host cổng
    assert dk(KC(DK), 2).status_code == 201 and acc_theo_sdt("+84900000002")["portal_code"] == "VG1002"
    r = dk(KC(DK), 7)
    assert r.status_code == 409 and "đã có hồ sơ" in r.text
    assert dk(KC(DK), 6).status_code == 503  # mock: SĐT đuôi 6 ⇒ 503 AUTO_APPROVE_OFF
    # CRM thấy SĐT đã có tài khoản cổng (VIP ID không có — ví dụ đã giải phóng) ⇒ trùng.
    conn = db.connect()
    try:
        conn.execute("DELETE FROM customer_accounts WHERE phone_e164='+84900000002'")
        conn.commit()
    finally:
        conn.close()
    r = dk(KC(DK), 2)
    assert r.status_code == 409 and "đã được đăng ký" in r.text
    # Bí mật lệch ⇒ CRM trả 401 ⇒ bận, không tạo.
    monkeypatch.setattr(khach, "_bi_mat_cache", "bi-mat-khac-" + "x" * 40)
    assert dk(KC(DK), 3).status_code == 503 and acc_theo_sdt("+84900000003") is None


# ------------------------------------------------------------------ cấu hình production
def test_la_url_noi_bo():
    for u in ("https://crm.vipgroup.com.vn", "http://crm", "http://vip-crm:3000", "http://localhost:8897",
              "http://crm.localhost", "http://127.0.0.1:8897", "http://10.1.2.3", "http://172.20.0.5",
              "http://192.168.1.2", "http://[::1]:80", "http://[fd00::1]"):
        assert khach.la_url_noi_bo(u), u
    for u in ("http://crm.vipgroup.com.vn", "http://8.8.8.8", "http://172.32.0.1",
              "http://169.254.1.1", "http://0.0.0.0", "http://u:p@crm", "ftp://crm", "",
              "http://[2001:db8::1]"):
        assert not khach.la_url_noi_bo(u), u


def test_kiem_cau_hinh_tu_dong(hai_host, monkeypatch, tmp_path):
    monkeypatch.setattr(config, "KHACH_TU_DONG", True)
    khach.kiem_cau_hinh()  # dev: mặc định 127.0.0.1 hợp lệ
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL", "http://crm.vipgroup.com.vn")
    with pytest.raises(RuntimeError, match="CRM_PORTAL_INTERNAL_URL phải là https"):
        khach.kiem_cau_hinh()
    # Production: bắt buộc đặt tường minh + bí mật có sẵn.
    monkeypatch.setattr(config, "ENV", "production")
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL", "http://127.0.0.1:8897")
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL_DAT", False)
    monkeypatch.setattr(khach, "_bi_mat_cache", None)
    monkeypatch.delenv("VIPID_PORTAL_SECRET", raising=False)
    monkeypatch.setattr(config, "PORTAL_SECRET_FILE", tmp_path / "khong-co.key")
    loi = khach._loi_cau_hinh_tu_dong()
    assert any("bắt buộc đặt CRM_PORTAL_INTERNAL_URL" in x for x in loi)
    assert any("VIPID_PORTAL_SECRET" in x for x in loi)
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL", "http://crm")
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL_DAT", True)
    monkeypatch.setenv("VIPID_PORTAL_SECRET", "p" * 48)
    assert khach._loi_cau_hinh_tu_dong() == []
    monkeypatch.setattr(config, "KHACH_TU_DONG", False)
    monkeypatch.setattr(config, "ENV", "test")
