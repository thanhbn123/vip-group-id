"""Màn Hạ tầng + cửa nhận báo cáo agent (HMAC, không cookie/CSRF)."""
from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from .. import config, db, hatang, security, web

router = APIRouter()


def _loi(status: int, ma: str, thong_bao: str) -> JSONResponse:
    return JSONResponse(status_code=status,
                        content={"ok": False, "loi": {"ma": ma, "thongBao": thong_bao}})


@router.post("/api/internal/hatang/bao-cao")
async def nhan_bao_cao(request: Request):
    """Agent trên từng máy chủ POST ảnh chụp 10 phút/lượt.

    Bí mật HMAC riêng (`HATANG_SHARED_SECRET`), chiều `hatang->cowork`.
    Máy chủ phải có trong sổ `hatang_may_chu` (danh sách trắng) — agent lạ 403.
    """
    raw = await request.body()
    if len(raw) > hatang.GIOI_HAN_BODY:
        return _loi(413, "QUA_LON", "Báo cáo quá lớn.")
    if not security.xac_thuc_hmac(
            "hatang->cowork", request.headers.get("x-cowork-ts"),
            request.headers.get("x-cowork-sig"), raw,
            secret=config.HATANG_SHARED_SECRET):
        return _loi(401, "CHU_KY_SAI", "Chữ ký nội bộ không hợp lệ hoặc đã hết hạn.")
    try:
        body = hatang.kiem_bao_cao(raw)
    except hatang.BaoCaoSai as exc:
        return _loi(400, "BAO_CAO_SAI", str(exc))
    code = str(body["mayChu"]).strip()
    conn = db.connect()
    try:
        if not hatang.may_chu_hop_le(conn, code):
            return _loi(403, "MAY_CHU_LA",
                        "Máy chủ không có trong sổ hoặc đã tắt. Thêm máy là việc của "
                        "quản trị, không phải của agent.")
        hatang.luu_bao_cao(conn, code, body)
    finally:
        conn.close()
    return JSONResponse({"ok": True, "data": {"mayChu": code, "nhanLuc": db.now_iso()}})


@router.get("/ha-tang")
async def trang_ha_tang(request: Request):
    """Chỉ Super Admin và người được uỷ quyền `hatang.view` (quyết định 2)."""
    user = await web.yeu_cau_dang_nhap(request)
    guard = web.yeu_cau_module("hatang")
    await guard(request)
    conn = db.connect()
    try:
        may_chu = hatang.danh_sach(conn)
    finally:
        conn.close()
    tong_cb = sum(len(m["canh_bao"]) for m in may_chu)
    return web.render(request, "hatang.html", page_title="Hạ tầng", user=user,
                      active_module="hatang", may_chu=may_chu, tong_cb=tong_cb,
                      tre_phut=config.HATANG_TRE_PHUT)
