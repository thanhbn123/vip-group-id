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


def test_crm_ho_so_cu_dau_cho_duyet_roi_lien_ket(td, crm_td):
    """Owner Q1: hồ sơ cũ ⇒ VIP ID đậu tài khoản cho_duyet gắn đúng subject đã gửi CRM; nhân viên
    Liên kết ⇒ CRM gửi ket-qua-duyet(approved) ⇒ kích hoạt, đăng nhập được."""
    dkc, dnc = td
    crm_td.che_do = "ho_so_cu"
    r = dk(dkc, 7)
    assert r.status_code == 409
    assert "Số này đã có hồ sơ tại VIP GROUP" in r.text
    assert ("Vui lòng gọi hoặc nhắn Zalo <b class=\"kh-nowrap\">0961 102 655</b>: nhân viên xác minh "
            "và gửi link đặt mật khẩu tới số điện thoại trên hồ sơ.") in r.text
    assert "Dùng số khác" in r.text
    assert "quen-mat-khau" not in r.text
    csp = _csp_sach(r)
    assert DN not in csp and r.headers["referrer-policy"] == "same-origin"
    acc = acc_theo_sdt("+84900000007")
    assert acc["status"] == "cho_duyet" and acc["tu_dong_loai"] == "ho_so_cu"
    assert acc["subject"] == crm_td.goi[0]["body"]["subject"]
    assert acc["crm_customer_id"] is None and acc["phone_verified_at"] is None
    assert _cho("+84900000007") is None
    assert _audit("khach.dang_ky.tu_dong.ho_so_cu_cho_duyet")
    conn = db.connect()
    try:  # CRM đã có dòng signup cho subject này ⇒ không xếp hàng signup cũ
        assert db.scalar(conn, "SELECT COUNT(*) FROM crm_sync_pending") == 0
    finally:
        conn.close()
    # Đăng nhập trước khi được Liên kết ⇒ trang chờ duyệt có sẵn.
    r = dang_nhap(dnc, "0900000007")
    assert r.status_code == 303 and r.headers["location"] == "/tai-khoan/cho-duyet"
    # Đăng ký lại: cùng mật khẩu ⇒ lại trang hồ sơ cũ; mật khẩu khác ⇒ 'đang xử lý'. Không gọi CRM.
    n = len(crm_td.goi)
    r = dk(KC(DK), 7)
    assert r.status_code == 409 and "Số này đã có hồ sơ tại VIP GROUP" in r.text
    ke = KC(DK)
    r = ke.post("/tai-khoan/dang-ky", data=_form(ke, 7, mat_khau=MK_KHAC, mat_khau_2=MK_KHAC),
                follow_redirects=False)
    assert r.status_code == 503 and khach.THONG_BAO_DANG_XU_LY in r.text
    assert len(crm_td.goi) == n
    a2 = acc_theo_sdt("+84900000007")
    assert a2["password_hash"] == acc["password_hash"] and a2["phone_conflict_count"] == 0
    # Nhân viên Liên kết ⇒ CRM gửi ket-qua-duyet(approved) cho đúng subject ⇒ kích hoạt, NHƯNG mật
    # khẩu người đăng ký tự đặt bị thay (R12-1) + token_version tăng.
    r = duyet(dnc, acc["subject"], 7)
    assert r.status_code == 200, r.text
    assert r.json()["data"]["can_link_dat_lai"] is True
    a3 = acc_theo_sdt("+84900000007")
    assert a3["status"] == "hoat_dong" and a3["phone_verified_method"] == "duyet_crm"
    assert a3["password_hash"] != acc["password_hash"]
    assert a3["token_version"] == acc["token_version"] + 1
    assert len(_audit("khach.ho_so_cu.lien_ket_dat_lai_mk")) == 1
    r = dang_nhap(KC(DN), "0900000007")
    assert r.status_code == 401  # mật khẩu lúc đăng ký không còn dùng được
    # Duyệt lại (CRM gửi lại) idempotent: không đổi mật khẩu lần nữa.
    assert duyet(dnc, acc["subject"], 7).json()["data"]["idempotent"] is True
    assert acc_theo_sdt("+84900000007")["password_hash"] == a3["password_hash"]
    # Nhân viên cấp link đặt lại (gửi Zalo tới SĐT trên hồ sơ) ⇒ khách đặt mật khẩu ⇒ đăng nhập.
    _dat_mk_qua_link(dnc, acc["subject"])
    token_launch(dang_nhap(KC(DN), "0900000007", MK_MOI_HSC))


MK_MOI_HSC = "HoSoCu!Passw0rd-42"


def _dat_mk_qua_link(dnc, subject: str) -> None:
    from test_khach_p1 import link_dat_lai
    t = link_dat_lai(dnc, subject)
    c = KC(DN)
    r = c.post("/tai-khoan/dat-lai", data={
        "t": t, "mat_khau": MK_MOI_HSC, "mat_khau_2": MK_MOI_HSC,
        "_csrf": csrf_tu(c.get("/tai-khoan/dat-lai?t=" + t).text)}, follow_redirects=False)
    assert r.status_code == 200 and "Đã đặt mật khẩu mới" in r.text, r.text[:300]


def test_ho_so_cu_lien_ket_thu_hoi_thiet_bi_va_phien(td, crm_td):
    """Cookie thiết bị tin cậy (gắn token_version) cũ không còn hợp lệ sau Liên kết."""
    dkc, dnc = td
    crm_td.che_do = "ho_so_cu"
    dk(dkc, 7)
    acc = acc_theo_sdt("+84900000007")
    tb = khach.tao_thiet_bi(acc)
    assert khach.thiet_bi_hop_le(tb, acc)
    assert duyet(dnc, acc["subject"], 7).status_code == 200
    assert not khach.thiet_bi_hop_le(tb, acc_theo_sdt("+84900000007"))


def test_duyet_thuong_khong_doi_mat_khau(hai_host, crm_td):
    """Luồng chờ duyệt cũ (không phải ho_so_cu) giữ nguyên mật khẩu khách khi được duyệt."""
    dkc, dnc = hai_host
    assert dk(dkc, 1).status_code == 303
    acc = acc_theo_sdt("+84900000001")
    r = duyet(dnc, acc["subject"], 1)
    assert "can_link_dat_lai" not in r.json()["data"]
    assert _audit("khach.ho_so_cu.lien_ket_dat_lai_mk") == []
    token_launch(dang_nhap(dnc, "0900000001"))


def test_crm_ho_so_cu_tu_choi_giai_phong_sdt(td, crm_td):
    dkc, dnc = td
    crm_td.che_do = "ho_so_cu"
    dk(dkc, 7)
    acc = acc_theo_sdt("+84900000007")
    from test_khach_p1 import goi_noi_bo
    r = goi_noi_bo(dnc, "/api/internal/khach/ket-qua-duyet",
                   {"subject": acc["subject"], "decision": "rejected", "reason": "không phải chủ"})
    assert r.status_code == 200 and acc_theo_sdt("+84900000007") is None
    crm_td.che_do = "kich_hoat"
    assert dk(KC(DK), 7).status_code == 201  # SĐT được giải phóng, đăng ký lại được


def test_trang_thanh_cong_referrer_policy_cho_origin_that(td, crm_td):
    """E2E thật: với 'same-origin' Chromium gửi Origin: null khi POST chéo origin ⇒ trang thành công
    phải dùng strict-origin-when-cross-origin; các trang khác giữ same-origin."""
    dkc, dnc = td
    assert dkc.get("/tai-khoan/dang-ky").headers["referrer-policy"] == "same-origin"
    r = dk(dkc, 1)
    assert r.status_code == 201
    assert r.headers["referrer-policy"] == "strict-origin-when-cross-origin"
    csp = r.headers["content-security-policy"]
    fa = re.search(r"form-action ([^;]+);", csp).group(1)
    assert fa == f"'self' {DN} http://crm.localhost:8897"  # chỉ thêm đúng origin dangnhap
    assert "x-khach-form-dangnhap" not in r.headers
    t = _handoff(r.text)
    for o in ("null", "https://khachhang.vipgroup.com.vn", "https://evil.example", DN):
        assert _nhan(dnc, t, origin=o).status_code == 403, o
    # Trình duyệt thật (strict-origin-when-cross-origin) gửi Origin = dangky ⇒ thành công.
    r = dnc.post("/tai-khoan/nhan-phien", data={"t": t}, follow_redirects=False,
                 headers={"origin": DK, "sec-fetch-site": "same-site", "referer": DK + "/"})
    token_launch(r)
    assert dnc.get("/tai-khoan/ho-so").headers["referrer-policy"] == "same-origin"


# ------------------------------------------------------------------ CRM lỗi ⇒ không tạo gì
def _tra(status: int, body: bytes):
    return lambda _b: (status, body)


def _nem(exc):
    def f(_b):
        raise exc
    return f


CL, MC = "khach.dang_ky.tu_dong.crm_loi", "khach.dang_ky.tu_dong.co_the_mo_coi"


@pytest.mark.parametrize("che_do,su_kien", [
    (_tra(503, b'{"ok":false,"error":{"code":"AUTO_APPROVE_OFF"}}'), CL),
    (_tra(401, b'{"ok":false,"error":{"code":"SIGNATURE_INVALID"}}'), CL),
    (_tra(409, b'{"ok":false,"error":{"code":"PHAT_LAI"}}'), CL),
    (_tra(502, b"bad gateway"), MC),
    (_tra(200, b"<html>khong phai json"), MC),
    (_tra(200, b'{"ok":true}'), MC),
    (_tra(200, b'[1,2]'), MC),
    (_tra(200, b'{"ok":true,"data":{"trang_thai":"la"}}'), MC),
    (_tra(200, b'{"ok":true,"data":{"trang_thai":"trung","loai":"khac"}}'), MC),
    (_tra(200, b'{"ok":true,"data":{"trang_thai":"kich_hoat","crm_customer_id":"x1"}}'), MC),
    (_tra(200, b'{"ok":true,"data":{"trang_thai":"kich_hoat","crm_customer_id":"x1",'
               b'"portal_code":"VG999"}}'), MC),
    (_tra(200, b'{"ok":true,"data":{"trang_thai":"kich_hoat","crm_customer_id":"a b",'
               b'"portal_code":"VG1001"}}'), MC),
    (_tra(200, b'{"ok":"true","data":{"trang_thai":"kich_hoat","crm_customer_id":"x1",'
               b'"portal_code":"VG1001"}}'), MC),
    (_nem(TimeoutError("read timeout")), MC),
    (_nem(ConnectionError("reset")), MC),
    (_nem(__import__("httpx").ConnectError("refused")), CL),
    (_nem(__import__("httpx").ConnectTimeout("connect")), CL),
], ids=["503", "401-chu-ky", "409", "502", "html", "thieu-data", "mang", "trang-thai-la",
        "loai-la", "thieu-ma", "ma-sai", "crm-id-sai", "ok-chuoi", "timeout", "reset",
        "connect-loi", "connect-timeout"])
def test_crm_loi_khong_tao_tai_khoan(td, crm_td, che_do, su_kien):
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
        # Đăng ký chờ giữ subject cho lần thử lại.
        cho = db.one(conn, "SELECT * FROM customer_tu_dong_cho WHERE phone_e164='+84900000001'")
        assert cho and "cust:" + cho["acc_id"] == crm_td.goi[0]["body"]["subject"]
    finally:
        conn.close()
    khac = MC if su_kien == CL else CL
    assert len(_audit(su_kien)) == 1 and _audit(khac) == []
    if su_kien == MC:  # không lấy mẫu, đủ dữ liệu đối soát
        d = json.loads(_audit(MC)[0]["detail"])
        assert d["phoneSha256"] == hashlib.sha256(b"+84900000001").hexdigest()


def test_crm_cham_qua_han_chot(td, crm_td, monkeypatch):
    dkc, _ = td
    monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.5)
    crm_td.cham = 2.5
    t0 = time.monotonic()
    r = dk(dkc, 1)
    assert r.status_code == 503 and time.monotonic() - t0 < 2.2  # không chờ hết 2,5 s của CRM
    from cowork import khach_web
    assert khach_web._crm_dk_dang_goi == 1  # luồng treo vẫn được đếm (trần chống tích tụ)
    time.sleep(2.2)  # lời gọi treo kết thúc trong executor: vẫn KHÔNG tạo tài khoản
    assert _so_tk() == 0 and khach_web._crm_dk_dang_goi == 0
    assert _audit("khach.dang_ky.tu_dong.co_the_mo_coi")


class CrmThat:
    """CRM giả có TRẠNG THÁI như CRM thật: idempotent theo subject, khoá theo SĐT (đã có tài khoản
    cổng ⇒ trung/tai_khoan_cong). `tre_sau_commit` giây: GHI xong rồi mới trả lời (mô phỏng trả lời
    sau hạn chót của VIP ID)."""

    def __init__(self):
        self.theo_sub: dict[str, dict] = {}
        self.theo_sdt: dict[str, str] = {}
        self.ma = 1000
        self.tre_sau_commit = 0.0
        self.khoa = threading.Lock()

    def __call__(self, b):
        with self.khoa:
            if b["subject"] in self.theo_sub:
                kq = self.theo_sub[b["subject"]]
            elif b["phone_e164"] in self.theo_sdt:
                kq = {"trang_thai": "trung", "loai": "tai_khoan_cong"}
            else:
                self.ma += 1
                kq = {"trang_thai": "kich_hoat", "crm_customer_id": f"crm-that-{self.ma}",
                      "portal_code": f"VG{self.ma}"}
                self.theo_sdt[b["phone_e164"]] = b["subject"]
                self.theo_sub[b["subject"]] = kq
        if self.tre_sau_commit:
            time.sleep(self.tre_sau_commit)
        return 200, json.dumps({"ok": True, "data": kq}).encode()


def _cho(phone="+84900000001") -> dict | None:
    conn = db.connect()
    try:
        return db.one(conn, "SELECT * FROM customer_tu_dong_cho WHERE phone_e164=?", (phone,))
    finally:
        conn.close()


def test_verifier_crm_ghi_roi_tra_loi_sau_han_chot_thu_lai_trinh_duyet_khac(td, crm_td,
                                                                            monkeypatch):
    """P1 vòng 10: CRM commit nhưng trả lời sau 5 s ⇒ VIP ID báo bận; khách thử lại từ TRÌNH DUYỆT
    KHÁC ⇒ dùng lại subject đã lưu ⇒ CRM trả kich_hoat cũ ⇒ kích hoạt, không bị khoá ngoài."""
    dkc, dnc = td
    monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.5)
    crm = CrmThat()
    crm.tre_sau_commit = 1.0
    crm_td.che_do = crm
    assert dk(dkc, 1).status_code == 503 and _so_tk() == 0
    s1 = crm_td.goi[0]["body"]["subject"]
    assert s1 in crm.theo_sub  # CRM đã tạo khách
    assert json.loads(_audit("khach.dang_ky.tu_dong.co_the_mo_coi")[0]["detail"])
    time.sleep(0.7)
    crm.tre_sau_commit = 0.0
    moi = KC(DK)  # trình duyệt khác, CÙNG mật khẩu (cùng người), họ tên mới
    r = moi.post("/tai-khoan/dang-ky", data=_form(moi, 1, ho_ten="Tên Mới Sửa"),
                 follow_redirects=False)
    assert r.status_code == 201 and "VG1001" in r.text
    assert crm_td.goi[-1]["body"]["subject"] == s1
    acc = acc_theo_sdt("+84900000001")
    assert acc["subject"] == s1 and acc["crm_customer_id"] == "crm-that-1001"
    assert acc["display_name"] == "Tên Mới Sửa"  # giá trị của lần gọi thành công
    assert _cho() is None  # thành công ⇒ xoá đăng ký chờ
    token_launch(dang_nhap(dnc, "0900000001"))


MK_KHAC = "Ke!La-Passw0rd-999"


def test_nguoi_khac_cung_sdt_khong_thua_huong_ho_so_crm(td, crm_td, monkeypatch):
    """Vòng 11 P2-1: nạn nhân quá hạn chờ (CRM đã tạo khách) ⇒ kẻ khác cùng SĐT, mật khẩu khác, trong
    TTL ⇒ trang 'đang xử lý' (không gọi CRM, không tạo gì); nạn nhân thử lại bằng mật khẩu của mình ⇒
    kích hoạt."""
    dkc, dnc = td
    monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.5)
    crm = CrmThat()
    crm.tre_sau_commit = 1.0
    crm_td.che_do = crm
    assert dk(dkc, 1).status_code == 503
    time.sleep(0.7)
    crm.tre_sau_commit = 0.0
    n = len(crm_td.goi)
    ke = KC(DK)
    r = ke.post("/tai-khoan/dang-ky", data=_form(ke, 1, ho_ten="Kẻ Lạ", mat_khau=MK_KHAC,
                                                 mat_khau_2=MK_KHAC), follow_redirects=False)
    assert r.status_code == 503 and khach.THONG_BAO_DANG_XU_LY in r.text
    assert "Cần hỗ trợ, vui lòng gọi hoặc nhắn Zalo 0961 102 655." in r.text
    _csp_sach(r)
    assert len(crm_td.goi) == n and _so_tk() == 0  # không gọi CRM, không tạo
    assert _cho()["display_name"] == "Khách Tự Động 1" and _cho()["attempts"] == 1  # không đổi dòng
    assert _audit("khach.dang_ky.tu_dong.dang_xu_ly")
    assert dang_nhap(dnc, "0900000001", MK_KHAC).status_code == 401
    r = dk(KC(DK), 1)  # nạn nhân, mật khẩu của mình, trình duyệt khác
    assert r.status_code == 201
    token_launch(dang_nhap(dnc, "0900000001"))


def test_het_han_nguoi_khac_khong_dung_subject_cu(td, crm_td, monkeypatch):
    """Hết TTL: người khác (mật khẩu khác) dùng subject MỚI và KHÔNG được dự phòng subject cũ."""
    dkc, _ = td
    monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.5)
    crm = CrmThat()
    crm.tre_sau_commit = 1.0
    crm_td.che_do = crm
    assert dk(dkc, 1).status_code == 503
    s1 = crm_td.goi[0]["body"]["subject"]
    time.sleep(0.7)
    crm.tre_sau_commit = 0.0
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_tu_dong_cho SET expires_at='2000-01-01T00:00:00+07:00'")
        conn.commit()
    finally:
        conn.close()
    ke = KC(DK)
    r = ke.post("/tai-khoan/dang-ky", data=_form(ke, 1, mat_khau=MK_KHAC, mat_khau_2=MK_KHAC),
                follow_redirects=False)
    assert r.status_code == 409 and "đã được đăng ký" in r.text  # CRM: SĐT thuộc s1
    assert all(g["body"]["subject"] != s1 for g in crm_td.goi[1:])  # không thử s1
    assert _so_tk() == 0


def test_don_dang_ky_cho_sau_hai_lan_ttl(td, crm_td):
    dkc, _ = td
    crm_td.che_do = _tra(503, b"{}")
    dk(dkc, 1)
    dk(dkc, 2)
    conn = db.connect()
    try:
        gio = config.KHACH_TU_DONG_CHO_GIO
        tu = (khach._bay_gio() - khach.timedelta(hours=2 * gio, minutes=1)).isoformat()
        ngay = (khach._bay_gio() - khach.timedelta(hours=2 * gio - 1)).isoformat()
        conn.execute("UPDATE customer_tu_dong_cho SET last_attempt=?, expires_at=? "
                     "WHERE phone_e164='+84900000001'", (tu, tu))
        conn.execute("UPDATE customer_tu_dong_cho SET last_attempt=?, expires_at=? "
                     "WHERE phone_e164='+84900000002'", (ngay, ngay))
        conn.commit()
    finally:
        conn.close()
    dk(dkc, 3)  # lần ghi kế tiếp dọn dòng quá 2 × TTL
    assert _cho("+84900000001") is None
    assert _cho("+84900000002") is not None  # mới quá 1 × TTL: giữ (dự phòng subject cũ)
    assert khach.CHO_DON_SAU_TTL == 2


def test_dang_ky_cho_het_han_subject_moi_va_du_phong_subject_cu(td, crm_td, monkeypatch):
    dkc, _ = td
    monkeypatch.setattr(config, "KHACH_SIGNUP_IP_PER_HOUR", 50)
    monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.5)
    crm = CrmThat()
    crm.tre_sau_commit = 1.0
    crm_td.che_do = crm
    assert dk(dkc, 1).status_code == 503
    s1 = crm_td.goi[0]["body"]["subject"]
    time.sleep(0.7)
    crm.tre_sau_commit = 0.0
    # Còn hạn: thử lại (kể cả khi CRM lại bận) vẫn subject cũ, TTL trượt.
    het_cu = _cho()["expires_at"]
    crm_td.che_do = _tra(503, b"{}")
    time.sleep(1.1)
    assert dk(KC(DK), 1).status_code == 503 and crm_td.goi[-1]["body"]["subject"] == s1
    assert _cho()["expires_at"] > het_cu and _cho()["attempts"] == 2
    # Hết hạn ⇒ subject MỚI; CRM báo SĐT thuộc tài khoản cổng (của s1) ⇒ thử lại một lần bằng s1
    # ⇒ kich_hoat cũ ⇒ kích hoạt, không khoá ngoài.
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_tu_dong_cho SET expires_at='2000-01-01T00:00:00+07:00'")
        conn.commit()
    finally:
        conn.close()
    crm_td.che_do = crm
    r = dk(KC(DK), 1)
    s2, s3 = (g["body"]["subject"] for g in crm_td.goi[-2:])
    assert s2 != s1 and s3 == s1
    assert r.status_code == 201 and acc_theo_sdt("+84900000001")["subject"] == s1
    au = json.loads(_audit("khach.dang_ky.tu_dong")[0]["detail"])
    assert au["subject_cu"] is True


def test_dang_ky_cho_het_han_khong_co_khach_crm_thi_dung_subject_moi(td, crm_td):
    dkc, _ = td
    crm_td.che_do = _tra(503, b"{}")
    dk(dkc, 1)
    s1 = crm_td.goi[0]["body"]["subject"]
    conn = db.connect()
    try:
        conn.execute("UPDATE customer_tu_dong_cho SET expires_at='2000-01-01T00:00:00+07:00'")
        conn.commit()
    finally:
        conn.close()
    crm_td.che_do = "kich_hoat"
    assert dk(KC(DK), 1).status_code == 201
    assert len(crm_td.goi) == 2 and crm_td.goi[1]["body"]["subject"] != s1
    assert acc_theo_sdt("+84900000001")["subject"] == crm_td.goi[1]["body"]["subject"]


def test_trung_dut_khoat_xoa_dang_ky_cho(td, crm_td):
    dkc, _ = td
    crm_td.che_do = _tra(503, b"{}")
    dk(dkc, 7)
    assert _cho("+84900000007")
    crm_td.che_do = "ho_so_cu"
    assert dk(dkc, 7).status_code == 409 and _cho("+84900000007") is None


# ------------------------------------------------------------------ CLI đối soát
def _cli(*a) -> tuple[int, str]:
    import contextlib
    import io
    from cowork import cli
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = cli.main(["khach-doi-soat", *a])
    return rc, buf.getvalue()


def test_cli_doi_soat_theo_sdt_tao_tai_khoan_mat_khau_cua_khach(td, crm_td, monkeypatch):
    dkc, dnc = td
    monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.5)
    crm = CrmThat()
    crm.tre_sau_commit = 1.0
    crm_td.che_do = crm
    assert dk(dkc, 1).status_code == 503
    time.sleep(0.7)
    crm.tre_sau_commit = 0.0
    assert _cli("0900000009")[0] == 1  # không có đăng ký chờ
    rc, out = _cli("0900000001")
    assert rc == 0 and "VG1001" in out and "crm-that-1001" in out
    acc = acc_theo_sdt("+84900000001")
    assert acc["status"] == "hoat_dong" and acc["phone_verified_method"] == "tu_dong"
    assert acc["phone_verified_by"].startswith("cli:")
    assert _audit("khach.ops.doi_soat_tu_dong")
    token_launch(dang_nhap(dnc, "0900000001"))  # mật khẩu khách đã đặt khi đăng ký
    rc, out = _cli(acc["subject"])
    assert rc == 0 and "Đã liên kết" in out  # chạy lại: idempotent


def test_cli_doi_soat_theo_subject_khong_con_dang_ky_cho(td, crm_td, monkeypatch):
    dkc, dnc = td
    crm = CrmThat()
    crm_td.che_do = crm
    sub = "cust:kh_" + "a" * 26
    crm({"subject": sub, "phone_e164": "+84900000002"})  # CRM đã có khách cho subject này
    n = len(crm_td.goi)
    rc, out = _cli(sub)  # mặc định chỉ tra cứu: không gọi CRM
    assert rc == 1 and "không có lượt đăng ký dở" in out.lower() and len(crm_td.goi) == n
    rc, out = _cli(sub, "--sdt", "0900000002", "--ten", "Khách Đối Soát")
    assert rc == 1 and len(crm_td.goi) == n and _so_tk() == 0  # thiếu --tao-moi
    assert _cli("cust:sai")[0] == 2
    assert _cli(sub, "--tao-moi", "--yes")[0] == 2  # thiếu --sdt/--ten
    # --tao-moi không --yes: hỏi xác nhận; trả lời sai ⇒ huỷ, không gọi CRM.
    monkeypatch.setattr("builtins.input", lambda _p="": "khong")
    rc, out = _cli(sub, "--tao-moi", "--sdt", "0900000002", "--ten", "Khách Đối Soát")
    assert rc == 1 and "CẢNH BÁO" in out and "Đã huỷ" in out and len(crm_td.goi) == n
    monkeypatch.setattr("builtins.input", lambda _p="": "TAO MOI")
    rc, out = _cli(sub, "--tao-moi", "--sdt", "0900000002", "--ten", "Khách Đối Soát")
    assert rc == 0 and "Mật khẩu ngẫu nhiên" in out
    acc = acc_theo_sdt("+84900000002")
    assert acc["subject"] == sub and acc["portal_code"] == "VG1001"
    assert dang_nhap(dnc, "0900000002").status_code == 401  # không ai biết mật khẩu
    # Subject khác cho SĐT đã có tài khoản ⇒ không đổi gì.
    rc, out = _cli("cust:kh_" + "b" * 26, "--tao-moi", "--yes", "--sdt", "0900000002",
                   "--ten", "X Y")
    assert rc == 1 and "tài khoản VIP ID khác" in out
    assert "lượt đăng ký dở" in _cli("0900000008")[1]  # SĐT không có lượt dở ⇒ rc 1


def test_cli_doi_soat_crm_bao_trung_hoac_ban(td, crm_td):
    dkc, _ = td
    crm_td.che_do = _tra(503, b"{}")
    dk(dkc, 1)
    assert _cli("0900000001")[0] == 3 and _so_tk() == 0
    crm_td.che_do = "tai_khoan_cong"
    rc, out = _cli("0900000001")
    assert rc == 1 and "trùng" in out and _so_tk() == 0
    crm_td.che_do = _tra(503, b"{}")
    dk(dkc, 1)  # lượt dở mới (lượt trước đã bị xoá vì trùng dứt khoát)
    crm_td.che_do = _tra(409, b'{"error":{"code":"SIGNUP_REJECTED","message":"x"}}')
    rc, out = _cli("0900000001")
    assert rc == 1 and "từ chối dứt khoát" in out and _so_tk() == 0 and _cho() is None


# ------------------------------------------------------------------ hạn chót tổng của HTTP
def test_http_han_chot_tong_chan_crm_nho_giot(monkeypatch):
    """CRM gửi header rồi nhỏ giọt thân (mỗi byte < read timeout) ⇒ vẫn dừng ở hạn chót tổng."""
    from http.server import BaseHTTPRequestHandler

    class Nho(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("content-length") or 0))
            self.send_response(200)
            self.send_header("Content-Length", "100")
            self.end_headers()
            for _ in range(40):
                try:
                    self.wfile.write(b" ")
                    self.wfile.flush()
                except OSError:
                    return
                time.sleep(0.1)

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Nho)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        monkeypatch.setattr(config, "KHACH_TU_DONG_TIMEOUT", 0.6)
        t0 = time.monotonic()
        with pytest.raises(TimeoutError):
            _HTTP_THAT(f"http://127.0.0.1:{srv.server_port}/x", b"{}", {})
        assert time.monotonic() - t0 < 1.5
    finally:
        srv.shutdown()


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
    # Lượt cùng lúc dùng CHUNG subject đã lưu ⇒ lượt thua không phải mồ côi; chỉ lượt đến sau khi
    # lượt thắng đã xoá đăng ký chờ (subject mới) mới có thể bị ghi mồ côi.
    sub_thang = acc_theo_sdt("+84900000001")["subject"]
    so_khac = sum(1 for g in crm_td.goi if g["body"]["subject"] != sub_thang)
    assert len(_audit("khach.dang_ky.tu_dong.mo_coi")) == so_khac


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


# ------------------------------------------------------------------ CRM 409 từ chối dứt khoát
@pytest.mark.parametrize("ma,su_kien", [("SIGNUP_REJECTED", "signup_rejected"),
                                        ("SUBJECT_HAS_USER", "subject_has_user")])
def test_crm_409_tu_choi_dut_khoat(td, crm_td, ma, su_kien):
    dkc, _ = td
    crm_td.che_do = _tra(503, b"{}")
    dk(dkc, 1)
    s1 = _cho()["acc_id"]
    body = json.dumps({"error": {"code": ma, "message": "x", "details": None}}).encode()
    crm_td.che_do = _tra(409, body)
    r = dk(dkc, 1)
    assert r.status_code == 409
    assert "Không thể tạo tài khoản tự động cho số này" in r.text and "0961 102 655" in r.text
    _csp_sach(r)
    assert _so_tk() == 0 and _cho() is None  # xoá đăng ký chờ
    assert len(_audit("khach.dang_ky.tu_dong." + su_kien)) == 1
    assert _audit(CL)[1:] == [] and _audit(MC) == []  # chỉ lần 503 trước đó; 409 không coi là bận
    crm_td.che_do = "kich_hoat"
    assert dk(dkc, 1).status_code == 201
    assert crm_td.goi[-1]["body"]["subject"] != "cust:" + s1  # lần sau dùng subject mới


def test_crm_409_khac_van_la_ban(td, crm_td):
    dkc, _ = td
    crm_td.che_do = _tra(409, b'{"error":{"code":"PHAT_LAI","message":"x"}}')
    assert dk(dkc, 1).status_code == 503 and _cho() is not None


def test_mock_crm_ho_so_cu_lien_ket_dang_nhap(td, mock_crm):
    """Chuỗi đầy đủ với CRM giả qua HTTP: đăng ký → ho_so_cu → đậu cho_duyet → ket-qua-duyet
    (Liên kết) → đăng nhập được."""
    _, dnc = td
    r = dk(KC(DK), 7)
    assert r.status_code == 409 and "đã có hồ sơ" in r.text
    acc = acc_theo_sdt("+84900000007")
    assert acc["status"] == "cho_duyet"
    assert dang_nhap(dnc, "0900000007").headers["location"] == "/tai-khoan/cho-duyet"
    assert duyet(dnc, acc["subject"], 7).status_code == 200
    assert dang_nhap(KC(DN), "0900000007").status_code == 401  # mật khẩu đăng ký bị thay
    _dat_mk_qua_link(dnc, acc["subject"])
    token_launch(dang_nhap(KC(DN), "0900000007", MK_MOI_HSC))


def test_mock_crm_409(td, mock_crm, monkeypatch):
    monkeypatch.setattr(config, "KHACH_SIGNUP_IP_PER_HOUR", 50)
    for n in (5, 4):
        r = dk(KC(DK), n)
        assert r.status_code == 409 and "Không thể tạo tài khoản tự động" in r.text, n
    assert _so_tk() == 0


def test_ttl_dang_ky_cho_mac_dinh_hai_gio():
    import os
    import subprocess
    import sys
    env = {k: v for k, v in os.environ.items() if k != "COWORK_KHACH_TU_DONG_CHO_GIO"}
    out = subprocess.run([sys.executable, "-c", "from cowork import config; "
                          "print(config.KHACH_TU_DONG_CHO_GIO)"], env=env, capture_output=True,
                         text=True, cwd=str(Path(__file__).resolve().parent.parent))
    assert out.stdout.strip() == "2", out.stderr[-300:]
