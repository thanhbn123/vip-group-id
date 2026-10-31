"""Màn Hạ tầng + cửa nhận báo cáo agent — mỗi cửa khoá có ca thử NGƯỢC."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta

from conftest import dang_nhap, tao_user

from cowork import config, db, hatang, security

MAY = "vps-160-22-171-228"


def _bao_cao(may_chu: str = MAY, **ghi_de) -> dict:
    bc = {
        "mayChu": may_chu,
        "doLuc": db.now_iso(),
        "cauHinh": {"hostname": "test", "os": "Ubuntu 26.04", "ramMb": 7376,
                    "diaTong": "89G", "cpu": "Xeon test", "nhanCpu": 4},
        "trangThai": {"uptimeGiay": 86400, "load1": "0.04", "ramDungMb": 2883,
                      "diaDung": "27G", "diaDungPhanTram": "32"},
        "dichVu": [{"ten": "viporder-hethong", "act": "active", "nr": 0,
                    "memBytes": 124_309_504}],
        "docker": [{"ten": "cowork-staging", "trangThai": "Up 11 days (healthy)"}],
    }
    bc.update(ghi_de)
    return bc


def _gui(client, bc: dict, secret: str | None = None, ts: str | None = None):
    body = json.dumps(bc, ensure_ascii=False).encode("utf-8")
    hdr = security.ky_hmac("hatang->cowork", body,
                           secret=secret or config.HATANG_SHARED_SECRET)
    if ts is not None:
        hdr["x-cowork-ts"] = ts
    return client.post("/api/internal/hatang/bao-cao", content=body,
                       headers={"Content-Type": "application/json", **hdr})


# ----------------------------- cửa nhận báo cáo -----------------------------

def test_bao_cao_dung_hmac_duoc_nhan(client, owner):
    r = _gui(client, _bao_cao())
    assert r.status_code == 200 and r.json()["ok"] is True
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM hatang_bao_cao WHERE may_chu=?",
                           (MAY,)).fetchone()
        assert row is not None
        assert json.loads(row["du_lieu"])["cauHinh"]["hostname"] == "test"
    finally:
        conn.close()


def test_chu_ky_sai_bi_tu_choi(client, owner):
    """NGƯỢC: đúng nội dung nhưng ký bằng bí mật khác → 401, không lưu gì."""
    r = _gui(client, _bao_cao(), secret="bi-mat-khac-hoan-toan")
    assert r.status_code == 401
    conn = db.connect()
    try:
        assert conn.execute("SELECT COUNT(*) c FROM hatang_bao_cao").fetchone()["c"] == 0
    finally:
        conn.close()


def test_ts_cu_bi_tu_choi(client, owner):
    """NGƯỢC: chữ ký đúng nhưng mốc thời gian quá cửa sổ 300 giây → 401 (chống phát lại)."""
    cu = str(int(time.time()) - 301)
    body = json.dumps(_bao_cao(), ensure_ascii=False).encode("utf-8")
    import hashlib, hmac as hmac_mod
    sig = hmac_mod.new(config.HATANG_SHARED_SECRET.encode(),
                       f"hatang->cowork.{cu}.".encode() + body,
                       hashlib.sha256).hexdigest()
    r = client.post("/api/internal/hatang/bao-cao", content=body,
                    headers={"x-cowork-ts": cu, "x-cowork-sig": sig})
    assert r.status_code == 401


def test_may_chu_la_bi_tu_choi(client, owner):
    """NGƯỢC: chữ ký đúng nhưng máy không có trong sổ → 403 (danh sách trắng)."""
    r = _gui(client, _bao_cao(may_chu="vps-la-hoac-gia-mao"))
    assert r.status_code == 403


def test_body_hong_bi_tu_choi(client, owner):
    body = b"khong phai json"
    hdr = security.ky_hmac("hatang->cowork", body, secret=config.HATANG_SHARED_SECRET)
    r = client.post("/api/internal/hatang/bao-cao", content=body, headers=hdr)
    assert r.status_code == 400
    r2 = _gui(client, {"mayChu": MAY})           # thiếu doLuc
    assert r2.status_code == 400


def test_bi_mat_brain_khong_mo_duoc_cua_hatang(client, owner):
    """NGƯỢC: hai bí mật phải ĐỘC LẬP — ký bằng bí mật Brain phải bị 401."""
    r = _gui(client, _bao_cao(), secret=config.BRAIN_SHARED_SECRET)
    assert r.status_code == 401


# ----------------------------- quyền xem màn -----------------------------

def test_super_admin_xem_duoc(client, owner):
    _gui(client, _bao_cao())
    dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    r = client.get("/ha-tang")
    assert r.status_code == 200
    assert "VPS sản xuất VIP Order" in r.text
    assert "viporder-hethong" in r.text


def test_nhan_vien_khong_duoc_xem(client, owner):
    """NGƯỢC: employee không có hatang.view → 403, và sidebar không có module."""
    tao_user("employee", "nv-thuong", dept="ky-thuat")
    dang_nhap(client, "nv-thuong", "User!Passw0rd")
    r = client.get("/ha-tang")
    assert r.status_code == 403
    trang_chu = client.get("/", follow_redirects=True)
    assert "/ha-tang" not in trang_chu.text


def test_uy_quyen_thi_xem_duoc(client, owner):
    """Quyết định 2 của anh Thành: chỉ Super Admin + người được UỶ QUYỀN."""
    tao_user("employee", "nv-duoc-uy-quyen", dept="ky-thuat")
    conn = db.connect()
    try:
        conn.execute(
            "INSERT INTO user_permissions(tenant_id, user_id, permission_code, effect, "
            "granted_by, granted_at) VALUES('vip-group', 'nv-duoc-uy-quyen', "
            "'hatang.view', 'allow', 'anh-thanh', ?)", (db.now_iso(),))
    finally:
        conn.close()
    dang_nhap(client, "nv-duoc-uy-quyen", "User!Passw0rd")
    r = client.get("/ha-tang")
    assert r.status_code == 200


# ----------------------------- tính cảnh báo -----------------------------

def test_canh_bao_dia_va_ram():
    bc = _bao_cao()
    bc["trangThai"]["diaDungPhanTram"] = "85"
    bc["trangThai"]["ramDungMb"] = 7000
    cb = hatang.tinh_canh_bao(bc, db.now_iso())
    assert any("Đĩa 85%" in c for c in cb)
    assert any(c.startswith("RAM") for c in cb)


def test_dich_vu_failed_thi_bao():
    bc = _bao_cao()
    bc["dichVu"].append({"ten": "dich-vu-chet", "act": "failed"})
    cb = hatang.tinh_canh_bao(bc, db.now_iso())
    assert any("dich-vu-chet" in c for c in cb)


def test_vault_khong_healthy_thi_bao():
    bc = _bao_cao()
    bc["vault"] = {"status": "degraded"}
    assert any("degraded" in c for c in hatang.tinh_canh_bao(bc, db.now_iso()))


def test_on_dinh_thi_khong_canh_bao():
    assert hatang.tinh_canh_bao(_bao_cao(), db.now_iso()) == []


def test_qua_han_thi_mat_tin_hieu():
    """NGƯỢC của đường đo: báo cáo cũ quá HATANG_TRE_PHUT → MẤT TÍN HIỆU."""
    cu = (datetime.now(db.TZ) - timedelta(minutes=config.HATANG_TRE_PHUT + 5)) \
        .replace(microsecond=0).isoformat()
    cb = hatang.tinh_canh_bao(_bao_cao(), cu)
    assert any("MẤT TÍN HIỆU" in c for c in cb)


def test_man_hinh_hien_mat_tin_hieu(client, owner):
    _gui(client, _bao_cao())
    conn = db.connect()
    try:
        cu = (datetime.now(db.TZ) - timedelta(minutes=config.HATANG_TRE_PHUT + 10)) \
            .replace(microsecond=0).isoformat()
        conn.execute("UPDATE hatang_bao_cao SET nhan_luc=? WHERE may_chu=?", (cu, MAY))
    finally:
        conn.close()
    dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    r = client.get("/ha-tang")
    assert "MẤT TÍN HIỆU" in r.text
