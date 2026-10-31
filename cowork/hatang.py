"""Hạ tầng: nhận báo cáo từ agent trên từng máy chủ, lưu ảnh chụp, tính cảnh báo.

Đường dữ liệu (anh Thành chốt 31/10/2026, V-14901): mỗi máy chủ tự đo rồi ĐẨY
ảnh chụp về COWORK bằng HMAC, 10 phút/lượt. COWORK không giữ khoá SSH nào.
V1 chỉ giữ ảnh chụp cuối của mỗi máy — lịch sử theo thời gian là giai đoạn 2.

Cảnh báo tính ở đây để một chỗ quyết, màn hình và dashboard cùng đọc:
  - đĩa ≥ NGUONG_DIA %            (khớp ngưỡng CANH_BAO_DIA_NGUONG=80 của canh-bao.py)
  - RAM ≥ NGUONG_RAM %
  - dịch vụ systemd ở trạng thái `failed`
  - VIP Vault status != healthy    (chỉ máy nào gửi khối `vault`)
  - MẤT TÍN HIỆU: quá HATANG_TRE_PHUT phút không có báo cáo — cái chết của chính
    đường đo cũng phải hiện ra, không hỏng im lặng.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime

from . import config, db

NGUONG_DIA = 80
NGUONG_RAM = 90
GIOI_HAN_BODY = 200_000

#: Khoá bắt buộc trong một báo cáo hợp lệ.
KHOA_BAT_BUOC = ("mayChu", "doLuc")


class BaoCaoSai(ValueError):
    pass


def kiem_bao_cao(raw: bytes) -> dict:
    """Giải và kiểm body của agent. Sai ở đâu nói rõ ở đó — không nuốt lỗi."""
    try:
        body = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise BaoCaoSai("Body phải là JSON UTF-8.") from exc
    if not isinstance(body, dict):
        raise BaoCaoSai("Body phải là một object JSON.")
    for k in KHOA_BAT_BUOC:
        if not str(body.get(k) or "").strip():
            raise BaoCaoSai(f"Thiếu trường bắt buộc '{k}'.")
    try:
        datetime.fromisoformat(str(body["doLuc"]))
    except ValueError as exc:
        raise BaoCaoSai("'doLuc' phải là ISO-8601.") from exc
    return body


def may_chu_hop_le(conn: sqlite3.Connection, code: str) -> dict | None:
    """Danh sách TRẮNG máy chủ: agent lạ bị từ chối (bỏ sót = an toàn, §12.2)."""
    row = conn.execute(
        "SELECT * FROM hatang_may_chu WHERE code=? AND enabled=1", (code,)).fetchone()
    return dict(row) if row else None


def luu_bao_cao(conn: sqlite3.Connection, code: str, body: dict) -> None:
    conn.execute(
        "INSERT INTO hatang_bao_cao(may_chu, do_luc, nhan_luc, du_lieu) VALUES(?,?,?,?) "
        "ON CONFLICT(may_chu) DO UPDATE SET do_luc=excluded.do_luc, "
        "nhan_luc=excluded.nhan_luc, du_lieu=excluded.du_lieu",
        (code, str(body["doLuc"]), db.now_iso(), json.dumps(body, ensure_ascii=False)))


def _phut_tu(nhan_luc: str | None) -> float | None:
    if not nhan_luc:
        return None
    try:
        moc = datetime.fromisoformat(nhan_luc)
    except (TypeError, ValueError):
        return None
    return (datetime.now(db.TZ) - moc).total_seconds() / 60


def tinh_canh_bao(du_lieu: dict | None, nhan_luc: str | None) -> list[str]:
    """Danh sách cảnh báo của MỘT máy. Rỗng = ổn định trong phạm vi đã đo."""
    ra: list[str] = []
    phut = _phut_tu(nhan_luc)
    if phut is None:
        ra.append("Chưa có báo cáo nào")
        return ra
    if phut > config.HATANG_TRE_PHUT:
        ra.append(f"MẤT TÍN HIỆU — báo cáo cuối cách đây {phut:.0f} phút")
    if not du_lieu:
        return ra
    tt = du_lieu.get("trangThai") or {}
    ch = du_lieu.get("cauHinh") or {}
    try:
        dia = int(str(tt.get("diaDungPhanTram", "")).rstrip("%"))
        if dia >= NGUONG_DIA:
            ra.append(f"Đĩa {dia}% (ngưỡng {NGUONG_DIA}%)")
    except ValueError:
        pass
    try:
        ram_dung = int(tt.get("ramDungMb", 0))
        ram_tong = int(ch.get("ramMb", 0))
        if ram_tong > 0 and ram_dung * 100 // ram_tong >= NGUONG_RAM:
            ra.append(f"RAM {ram_dung * 100 // ram_tong}% (ngưỡng {NGUONG_RAM}%)")
    except (TypeError, ValueError):
        pass
    hong = [d.get("ten") for d in (du_lieu.get("dichVu") or [])
            if d.get("act") == "failed"]
    if hong:
        ra.append("Dịch vụ hỏng: " + ", ".join(str(t) for t in hong[:5]))
    vault = du_lieu.get("vault")
    if isinstance(vault, dict) and vault.get("status") not in (None, "", "healthy"):
        ra.append(f"Sao lưu VIP Vault: {vault.get('status')}")
    return ra


def danh_sach(conn: sqlite3.Connection) -> list[dict]:
    """Mọi máy trong sổ + ảnh chụp cuối + cảnh báo, cho màn hình và dashboard."""
    rows = db.q(conn,
                "SELECT m.code, m.name, m.ip, b.do_luc, b.nhan_luc, b.du_lieu "
                "FROM hatang_may_chu m LEFT JOIN hatang_bao_cao b ON b.may_chu=m.code "
                "WHERE m.enabled=1 ORDER BY m.code")
    ra = []
    for r in rows:
        du_lieu = None
        if r.get("du_lieu"):
            try:
                du_lieu = json.loads(r["du_lieu"])
            except ValueError:
                du_lieu = None
        canh_bao = tinh_canh_bao(du_lieu, r.get("nhan_luc"))
        mat = any(c.startswith(("MẤT TÍN HIỆU", "Chưa có báo cáo")) for c in canh_bao)
        ra.append({
            "code": r["code"], "name": r["name"], "ip": r["ip"],
            "do_luc": r.get("do_luc"), "nhan_luc": r.get("nhan_luc"),
            "du_lieu": du_lieu, "canh_bao": canh_bao,
            "trang_thai": "mat-tin-hieu" if mat else ("canh-bao" if canh_bao else "on-dinh"),
        })
    return ra


def tong_canh_bao(conn: sqlite3.Connection) -> int:
    """Tổng cảnh báo mọi máy — dashboard dùng để 'COWORK cũng báo' (quyết định 4)."""
    return sum(len(m["canh_bao"]) for m in danh_sach(conn))
