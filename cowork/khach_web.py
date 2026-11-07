"""Web realm KHÁCH: ứng dụng ASGI riêng, chọn theo Host.

- `KhachHostDispatch` (middleware ngoài cùng của app nhân viên): khi realm bật và Host thuộc
  `COWORK_KHACH_HOSTS` ⇒ request đi vào `khach_app`; ngược lại đi vào app nhân viên.
  Vì vậy trên host khách MỌI route nhân viên (/, /dang-nhap, quản trị, /api/internal/brain…)
  không tồn tại (404), và trên host nhân viên realm khách không tồn tại.
- Realm tắt ⇒ dispatch không làm gì; `/api/internal/khach/*` không có ở đâu.
"""
from __future__ import annotations

import asyncio
import functools
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse,
                               Response)
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import Headers
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from . import auth, config, db, khach, security, web

log = logging.getLogger("cowork.khach")


class KhachHostDispatch:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            await self.app(scope, receive, send)
            return
        if not config.KHACH_ENABLED and not config.STAFF_HOSTS:
            await self.app(scope, receive, send)  # hành vi cũ: không kiểm Host
            return
        realm = khach.chon_realm(Headers(scope=scope).get("host"))
        if realm == "khach" and khach.realm_bat():
            if _dang_bao_tri():  # công tắc khẩn: tệp tồn tại ⇒ đóng toàn bộ host khách
                await _bao_tri(scope, receive, send)
                return
            hdr = Headers(scope=scope)
            vai = khach.vai_tro_host(hdr.get("host"))
            path = scope.get("path") or ""
            if not duoc_phuc_vu(vai, path) or (path.startswith("/api/internal/")
                                               and _qua_proxy_cong_khai(hdr)):
                # Mỗi host chỉ phục vụ route của nó; /api/internal/* chỉ qua mạng nội bộ ⇒ 404.
                scope = dict(scope)
                scope["path"] = "/api/__404__" if path.startswith("/api/") else "/tai-khoan/__404__"
                scope["raw_path"] = scope["path"].encode()
            await khach_app(scope, receive, send)
        elif realm == "staff":
            await self.app(scope, receive, send)
        else:
            # Host thiếu/lạ/sai cú pháp: KHÔNG BAO GIỜ rơi về realm nhân viên.
            await _sai_host(scope, receive, send)


_DANGKY_DUONG = {"/", "/tai-khoan/dang-ky", "/tai-khoan/cho-duyet"}
_DANGNHAP_DUONG = {"/", "/tai-khoan", "/tai-khoan/", "/tai-khoan/dang-nhap", "/tai-khoan/dang-xuat",
                   "/tai-khoan/ho-so", "/tai-khoan/doi-mat-khau", "/tai-khoan/quen-mat-khau",
                   "/tai-khoan/dat-lai", "/tai-khoan/vao-cong", "/tai-khoan/cho-duyet"}


def duoc_phuc_vu(vai: str | None, path: str) -> bool:
    """§15: dangky chỉ đăng ký + chờ duyệt; dangnhap đăng nhập/tài khoản + API nội bộ; chế độ một
    host cũ ('tat_ca') phục vụ mọi route khách."""
    if vai == "tat_ca":
        return True
    if path.startswith("/tai-khoan/static/"):
        return vai in ("dangky", "dangnhap")
    if vai == "dangky":
        return path in _DANGKY_DUONG
    if vai == "dangnhap":
        return path in _DANGNHAP_DUONG or path.startswith("/api/internal/khach/")
    return False


def _qua_proxy_cong_khai(hdr: Headers) -> bool:
    """Request đi qua reverse proxy công khai (Caddy luôn thêm các header này). CRM gọi API nội
    bộ trực tiếp qua mạng docker ⇒ không có các header này."""
    return any(hdr.get(k) for k in ("x-forwarded-for", "x-real-ip", "forwarded", "via"))


def _dang_bao_tri() -> bool:
    """Fail-closed: tệp tồn tại ⇒ bảo trì; KHÔNG có tệp ⇒ mở; mọi lỗi khác (quyền, IO) ⇒ bảo trì."""
    try:
        os.stat(config.KHACH_MAINTENANCE_FILE)
        return True
    except FileNotFoundError:
        return False
    except Exception:  # noqa: BLE001
        return True


_TRANG_BAO_TRI = """<!doctype html><html lang="vi"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="robots" content="noindex">
<title>Bảo trì · Cổng khách hàng VIP GROUP</title></head><body>
<main><h1>Cổng khách hàng VIP GROUP đang bảo trì</h1>
<p>Vui lòng quay lại sau ít phút. Cần hỗ trợ, liên hệ hotline/Zalo <b>{hotline}</b>.</p>
<p>CÔNG TY TNHH VIP GROUP</p></main></body></html>"""


async def _bao_tri(scope, receive, send):
    from html import escape
    h = {"Cache-Control": "no-store", "Retry-After": "300", "X-Content-Type-Options": "nosniff",
         "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"}
    if scope["type"] != "http":
        await send({"type": "websocket.close", "code": 1013})
        return
    if (scope.get("path") or "").startswith("/api/"):
        resp = JSONResponse(status_code=503, headers=h, content={
            "ok": False, "loi": {"ma": "BAO_TRI", "thongBao": "Cổng khách hàng đang bảo trì."}})
    else:
        resp = HTMLResponse(_TRANG_BAO_TRI.format(hotline=escape(config.KHACH_HOTLINE)),
                            status_code=503, headers=h)
    await resp(scope, receive, send)


async def _sai_host(scope, receive, send):
    if scope["type"] != "http":
        await send({"type": "websocket.close", "code": 1008})
        return
    await PlainTextResponse("421 Misdirected Request", status_code=421,
                            headers={"Cache-Control": "no-store"})(scope, receive, send)


def _crm_origin() -> str:
    try:
        p = urlsplit(config.CRM_PORTAL_PUBLIC_URL)
        if p.scheme in ("http", "https") and p.netloc:
            return f"{p.scheme}://{p.netloc}"
    except ValueError:
        pass
    return ""


class KhachHeaders(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        # URL chứa token một lần (?t=) ⇒ không gửi Referer ra ngoài origin; trong cùng origin
        # trình duyệt vẫn gửi Origin thật để kiểm CSRF.
        h["Referrer-Policy"] = "same-origin"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        crm = _crm_origin()
        # Chỉ trang thử thách được nạp script/iframe Turnstile của Cloudflare.
        tt = h.get("x-khach-turnstile") == "1"
        if "x-khach-turnstile" in h:
            del h["x-khach-turnstile"]
        script = f"script-src {TURNSTILE_ORIGIN}; frame-src {TURNSTILE_ORIGIN}; " if tt else \
            "script-src 'none'; frame-src 'none'; "
        h["Content-Security-Policy"] = (
            "default-src 'none'; img-src 'self' data:; style-src 'self'; " + script +
            f"font-src 'self'; connect-src 'none'; form-action 'self'{(' ' + crm) if crm else ''}; "
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
        h["Cache-Control"] = "no-store"
        if auth.la_https(request):
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


khach_app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
khach_app.add_middleware(KhachHeaders)
_static = config.BASE_DIR / "cowork" / "static"
khach_app.mount("/tai-khoan/static", StaticFiles(directory=str(_static)), name="khach_static")


# ------------------------------------------------------------------ tiện ích
def _secure(request: Request) -> bool:
    return config.COOKIE_SECURE or khach.la_production() or auth.la_https(request)


def _ten_ps(request: Request) -> str:
    # __Host- (bắt buộc Secure, Path=/, không Domain): subdomain không cài đè được cookie này.
    return "__Host-vg_khach_ps" if _secure(request) else "vg_khach_ps"


def _ps(request: Request) -> str | None:
    v = request.cookies.get(_ten_ps(request))
    return v if v and khach.PS_RE.match(v) else None


def _render(request: Request, ten: str, status: int = 200, **ctx) -> Response:
    csrf_phien = ctx.pop("csrf", None)
    ps_moi = None
    if csrf_phien:
        csrf = csrf_phien
    else:
        ps = _ps(request)
        if not ps:
            ps = ps_moi = security.token_moi(24)
        csrf = khach.tao_csrf(ps)
    ctx.update({"request": request, "csrf": csrf, "page_title": ctx.get("page_title", ""),
                "BRAND": "CÔNG TY TNHH VIP GROUP", "URL_DANGKY": khach.url_dangky(),
                "URL_DANGNHAP": khach.url_dangnhap()})
    resp = web.templates.TemplateResponse(request=request, name=f"khach/{ten}",
                                          status_code=status, context=ctx)
    if ps_moi:
        ten_ck = _ten_ps(request)
        resp.set_cookie(ten_ck, ps_moi, max_age=86400, httponly=True, samesite="lax",
                        path="/" if ten_ck.startswith("__Host-") else khach.COOKIE_PATH,
                        secure=_secure(request))
    return resp


def _cung_nguon(request: Request) -> bool:
    """POST của trình duyệt phải chứng minh cùng nguồn: Origin khớp host khách, hoặc (khi không
    có Origin) Sec-Fetch-Site: same-origin. Thiếu cả hai ⇒ từ chối."""
    origin = request.headers.get("origin")
    host = khach.chuan_hoa_host(request.headers.get("host"))
    if origin is not None:
        if origin == "null":
            return False
        try:
            nl = khach.chuan_hoa_host(urlsplit(origin).netloc)
        except ValueError:
            return False
        return bool(host) and nl == host and khach.la_host_khach(nl)
    return request.headers.get("sec-fetch-site") == "same-origin"


def _kiem_csrf(request: Request, gui: str | None, mong: str | None = None) -> bool:
    """Cùng nguồn + (token phiên trong DB, hoặc token ẩn danh ký HMAC gắn id tiền-phiên)."""
    if not _cung_nguon(request):
        return False
    if mong is None:
        return khach.csrf_hop_le(gui, _ps(request))
    return bool(gui) and security.hmac.compare_digest(str(mong), str(gui))


def _loi_csrf(request: Request) -> Response:
    return _render(request, "thong_bao.html", 403, page_title="Phiên không hợp lệ",
                   tieu_de="Phiên biểu mẫu đã hết hạn",
                   noi_dung="Vui lòng tải lại trang và thử lại.")


# ------------------------------------------------------------------ vòng nền gửi CRM
def dong_bo_mot_luot() -> dict:
    conn = db.connect()
    try:
        return khach.dong_bo_crm(conn)
    finally:
        conn.close()


async def vong_dong_bo_crm() -> None:
    """Chạy nền suốt vòng đời app: gửi hàng đợi crm_sync_pending mỗi KHACH_SYNC_GIAY giây
    (trong luồng riêng — không chặn event loop). CLI `khach-dong-bo` vẫn dùng được song song."""
    while True:
        await asyncio.sleep(config.KHACH_SYNC_GIAY)
        try:
            await asyncio.to_thread(dong_bo_mot_luot)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - vòng nền không được chết
            log.exception("Vòng gửi CRM lỗi")


# Băm mật khẩu (scrypt 128 MiB) chạy trong executor RIÊNG: lượt đăng nhập ồ ạt không chiếm
# threadpool mặc định (route đồng bộ của realm khác vẫn có luồng). Hàng đợi có trần ⇒ 503.
_kdf_pool = ThreadPoolExecutor(max_workers=max(1, config.KHACH_SCRYPT_DONG_THOI),
                               thread_name_prefix="khach-kdf")
KDF_HANG_DOI_TOI_DA = 16
KDF_TIMEOUT_GIAY = 10.0
_kdf_dang_cho = 0


def _ban(request: Request) -> Response:
    return _render(request, "thong_bao.html", 503, page_title="Hệ thống bận",
                   tieu_de="Hệ thống đang bận",
                   noi_dung="Vui lòng thử lại sau ít giây.", link_dang_nhap=True)


async def _chay_kdf(request: Request, fn, *args) -> Response:
    global _kdf_dang_cho
    if _kdf_dang_cho >= KDF_HANG_DOI_TOI_DA:
        return _ban(request)
    _kdf_dang_cho += 1
    try:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(
            loop.run_in_executor(_kdf_pool, functools.partial(fn, *args)), KDF_TIMEOUT_GIAY)
    except (asyncio.TimeoutError, khach.HeThongBan):
        return _ban(request)
    finally:
        _kdf_dang_cho -= 1


def _ctx_phien(request: Request, conn) -> dict | None:
    ctx = khach.xac_thuc_phien(conn, request.cookies.get(khach.COOKIE_PHIEN))
    if ctx and not khach.pilot_cho_phep(ctx["account"]["phone_e164"]):
        return None  # pilot: tài khoản đã bị rút khỏi danh sách ⇒ phiên không còn dùng được
    return ctx


def _trang_pilot(request: Request) -> Response:
    return _render(request, "thong_bao.html", 403, page_title="Đang chạy thử",
                   tieu_de="Cổng khách hàng đang chạy thử nội bộ",
                   noi_dung=khach.THONG_BAO_PILOT.format(hotline=config.KHACH_HOTLINE))


def _ip_khoa(request: Request) -> str:
    """Khoá IP cho mọi giới hạn tần suất/khoá (IPv6 gộp /64, IPv4-mapped ⇒ IPv4)."""
    return khach.khoa_ip(web.ip_cua(request))


TURNSTILE_ORIGIN = "https://challenges.cloudflare.com"


async def turnstile_siteverify(secret: str, token: str, remoteip: str) -> dict | None:
    """Gọi siteverify của Cloudflare (async — không chiếm luồng). Test thay thế hàm này."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=config.KHACH_TURNSTILE_TIMEOUT) as c:
            r = await c.post(config.KHACH_TURNSTILE_VERIFY_URL,
                             data={"secret": secret, "response": token, "remoteip": remoteip})
        return r.json() if r.status_code == 200 else None
    except Exception:  # noqa: BLE001 - lỗi mạng ⇒ coi như không vượt
        log.warning("Turnstile siteverify lỗi", exc_info=True)
        return None


TURNSTILE_DONG_THOI_TOI_DA = 16
TURNSTILE_CHO_SLOT_GIAY = 3.0
TURNSTILE_IP_MOI_PHUT = 10
_ts_dang_goi = 0


def _turnstile_qua_tan_suat(request: Request) -> bool:
    conn = db.connect()
    try:
        if khach.vuot_tan_suat(conn, "turnstile_ip", _ip_khoa(request), TURNSTILE_IP_MOI_PHUT, 60):
            khach._ghi_audit(conn, "khach:anon", "khach.turnstile.qua_tan_suat",
                             detail={"ip": _ip_khoa(request)}, request=request,
                             lay_mau=_ip_khoa(request))
            return True
        return False
    finally:
        conn.close()


async def _vuot_turnstile(request: Request, token: str,
                          action: str = khach.TURNSTILE_ACTION) -> str:
    """'ok' | 'sai' | 'qua_tan_suat'.

    - Giới hạn số lượt siteverify theo khoá IP (IPv6 /64) TRƯỚC khi gọi: một IP xả token rác
      không chiếm được các suất gọi của người khác.
    - Hết suất đồng thời ⇒ chờ ngắn (≤ 3 giây) rồi mới coi như chưa vượt.
    """
    global _ts_dang_goi
    if not khach.turnstile_bat() or not token or len(token) > 2048:
        return "sai"
    if await asyncio.to_thread(_turnstile_qua_tan_suat, request):
        return "qua_tan_suat"
    han = time.monotonic() + TURNSTILE_CHO_SLOT_GIAY
    while _ts_dang_goi >= TURNSTILE_DONG_THOI_TOI_DA:
        if time.monotonic() >= han:
            log.warning("Turnstile: hết %s suất siteverify sau %ss chờ", TURNSTILE_DONG_THOI_TOI_DA,
                        TURNSTILE_CHO_SLOT_GIAY)
            return "sai"
        await asyncio.sleep(0.05)
    _ts_dang_goi += 1
    try:
        kq = await turnstile_siteverify(khach.turnstile_secret(), token, web.ip_cua(request))
    finally:
        _ts_dang_goi -= 1
    return "ok" if khach.ket_qua_turnstile_hop_le(kq, request.headers.get("host"), action) else "sai"


def _ua(request: Request) -> str:
    return request.headers.get("user-agent") or ""


def _sang_crm(conn, request: Request, acc: dict, session_id: str,
              tiep: str | None = None) -> RedirectResponse:
    token = khach.phat_launch_token(conn, acc, request, session_id=session_id)
    return RedirectResponse(khach.url_launch(token, khach.kiem_tiep(tiep)), status_code=303)


# ------------------------------------------------------------------ trang
@khach_app.get("/")
def trang_goc(request: Request):
    vai = khach.vai_tro_host(request.headers.get("host"))
    if vai == "dangky":
        return RedirectResponse("/tai-khoan/dang-ky", status_code=303)
    if vai == "dangnhap":
        return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)
    raise StarletteHTTPException(status_code=404)


@khach_app.get("/tai-khoan")
@khach_app.get("/tai-khoan/")
def goc():
    return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)


def _form_dang_ky(request: Request, status: int = 200, **ctx) -> Response:
    """Trang đăng ký; Turnstile bật ⇒ luôn có thử thách (action khach_dang_ky) + CSP mở Cloudflare."""
    tt = khach.turnstile_bat()
    resp = _render(request, "dang_ky.html", status, page_title="Đăng ký tài khoản",
                   thu_thach=tt, turnstile_site_key=config.KHACH_TURNSTILE_SITE_KEY,
                   turnstile_action=khach.TURNSTILE_ACTION_DANG_KY, **ctx)
    if tt:
        resp.headers["x-khach-turnstile"] = "1"
    return resp


@khach_app.get("/tai-khoan/dang-ky")
def dang_ky_form(request: Request):
    return _form_dang_ky(request, form={})


@khach_app.post("/tai-khoan/dang-ky")
async def dang_ky(request: Request, ho_ten: str = Form(""), sdt: str = Form(""),
                  email: str = Form(""), mat_khau: str = Form(""), mat_khau_2: str = Form(""),
                  dong_y: str = Form(""), csrf_form: str = Form("", alias="_csrf"),
                  cf_token: str = Form("", alias="cf-turnstile-response")):
    if not _kiem_csrf(request, csrf_form):
        return _loi_csrf(request)
    # Turnstile cấu hình ⇒ BẮT BUỘC cho mọi lượt đăng ký (chống đăng ký/giữ chỗ hàng loạt);
    # chỉ gọi siteverify sau khi CSRF/cùng nguồn đạt.
    if khach.turnstile_bat():
        kq = (await _vuot_turnstile(request, cf_token, khach.TURNSTILE_ACTION_DANG_KY)
              if cf_token else "sai")
        if kq != "ok":
            form = {"ho_ten": ho_ten[:100], "sdt": sdt[:30], "email": email[:254]}
            if kq == "qua_tan_suat":
                return _form_dang_ky(request, 429, form=form,
                                     loi="Bạn đã thử quá nhiều lần. Vui lòng đợi 1 phút rồi thử lại.")
            return _form_dang_ky(request, 400, form=form,
                                 loi="Vui lòng xác nhận bạn không phải máy rồi gửi lại.")
    return await _chay_kdf(request, _dang_ky, request, ho_ten, sdt, email, mat_khau,
                           mat_khau_2, dong_y)


def _dang_ky(request, ho_ten, sdt, email, mat_khau, mat_khau_2, dong_y) -> Response:
    form = {"ho_ten": ho_ten[:100], "sdt": sdt[:30], "email": email[:254]}
    conn = db.connect()
    try:
        khach.dang_ky(conn, ho_ten=ho_ten, sdt=sdt, email=email, mat_khau=mat_khau[:200],
                      mat_khau_2=mat_khau_2[:200], dong_y=dong_y == "1",
                      ip=_ip_khoa(request), request=request)
    except khach.KhachPilot:
        return _trang_pilot(request)
    except khach.KhachLoi as e:
        return _form_dang_ky(request, e.status, loi=e.message, form=form)
    finally:
        conn.close()
    return RedirectResponse("/tai-khoan/cho-duyet", status_code=303)


# Owner 07/11: bỏ xác minh email — /da-gui-email, /gui-lai-xac-minh, /xac-minh-email không còn
# (404). Đăng ký xong chuyển thẳng tới trang "Đã nhận đăng ký, chờ VIP GROUP duyệt".


@khach_app.get("/tai-khoan/cho-duyet")
def cho_duyet(request: Request):
    return _render(request, "cho_duyet.html", page_title="Chờ duyệt")


@khach_app.get("/tai-khoan/dang-nhap")
def dang_nhap_form(request: Request, tiep: str = ""):
    tiep = tiep if khach.kiem_tiep(tiep) else ""  # không hợp lệ ⇒ bỏ, về vao-cong mặc định
    conn = db.connect()
    try:
        ctx = _ctx_phien(request, conn)
    finally:
        conn.close()
    if ctx:
        return _render(request, "dang_nhap.html", page_title="Đăng nhập", tiep=tiep,
                       da_dang_nhap=ctx["account"], csrf=ctx["session"]["csrf_token"])
    return _render(request, "dang_nhap.html", page_title="Đăng nhập", tiep=tiep)


@khach_app.post("/tai-khoan/dang-nhap")
async def dang_nhap(request: Request, dinh_danh: str = Form(""), mat_khau: str = Form(""),
                    csrf_form: str = Form("", alias="_csrf"),
                    cf_token: str = Form("", alias="cf-turnstile-response"),
                    tiep: str = Form("")):
    dinh_danh = dinh_danh[:40]
    tiep = tiep[:2000] if khach.kiem_tiep(tiep[:2000]) else ""
    thiet_bi = request.cookies.get(khach.COOKIE_THIET_BI)
    ip = _ip_khoa(request)
    ts_ok = False
    # CSRF + lớp chặn rẻ (không băm) chạy trong luồng: ghi giới hạn/audit SQLite không chặn loop.
    ket, e = await asyncio.to_thread(_kiem_truoc_dang_nhap, request, dinh_danh, ip, thiet_bi,
                                     csrf_form)
    if ket == "csrf":
        return _loi_csrf(request)
    if ket == "loi":
        return _loi_dang_nhap(request, e, dinh_danh, tiep)
    thu_thach = e if ket == "thu_thach" else None
    if thu_thach is not None:
        # CHỈ gọi siteverify sau khi CSRF/cùng nguồn đạt VÀ chính lớp chặn đòi thử thách.
        kq = await _vuot_turnstile(request, cf_token) if cf_token else "sai"
        if kq == "qua_tan_suat":
            return _loi_dang_nhap(request, khach.ThuThach(
                "Bạn đã thử quá nhiều lần. Vui lòng đợi 1 phút rồi thử lại.", 429, "THU_THACH"),
                dinh_danh, tiep)
        if kq != "ok":
            return _loi_dang_nhap(request, thu_thach, dinh_danh, tiep)
        ts_ok = True
    return await _chay_kdf(request, _dang_nhap, request, dinh_danh, mat_khau[:200], thiet_bi,
                           ts_ok, tiep)


def _doc_phien(request: Request) -> dict | None:
    conn = db.connect()
    try:
        return _ctx_phien(request, conn)
    finally:
        conn.close()


def _kiem_truoc_dang_nhap(request: Request, dinh_danh: str, ip: str, thiet_bi: str | None,
                          csrf_form: str):
    """('ok'|'csrf'|'loi'|'thu_thach', lỗi). Chạy trong luồng (có đọc/ghi SQLite)."""
    conn = db.connect()
    try:
        if not _kiem_csrf(request, csrf_form):
            ctx = _ctx_phien(request, conn)  # đang đăng nhập: chấp nhận token CSRF của phiên
            if not ctx or not _kiem_csrf(request, csrf_form, ctx["session"]["csrf_token"]):
                return "csrf", None
        try:
            khach.kiem_chan(conn, dinh_danh, ip, thiet_bi, request)
            return "ok", None
        except khach.ThuThach as e:
            return "thu_thach", e
        except khach.KhachLoi as e:
            return "loi", e
    finally:
        conn.close()


def _loi_dang_nhap(request: Request, e: "khach.KhachLoi", dinh_danh: str,
                   tiep: str = "") -> Response:
    if isinstance(e, khach.KhachPilot):
        return _trang_pilot(request)
    thu_thach = isinstance(e, khach.ThuThach)
    resp = _render(request, "dang_nhap.html", e.status, page_title="Đăng nhập", loi=e.message,
                   dinh_danh=dinh_danh, tiep=tiep,
                   thu_thach=thu_thach, turnstile_site_key=config.KHACH_TURNSTILE_SITE_KEY,
                   turnstile_action=khach.TURNSTILE_ACTION)
    if thu_thach:
        resp.headers["x-khach-turnstile"] = "1"  # KhachHeaders mở CSP cho riêng trang này
    return resp


def _dang_nhap(request: Request, dinh_danh: str, mat_khau: str, thiet_bi: str | None,
               ts_ok: bool = False, tiep: str = "") -> Response:
    conn = db.connect()
    try:
        try:
            acc = khach.dang_nhap(conn, dinh_danh, mat_khau, _ip_khoa(request), request,
                                  thiet_bi=thiet_bi, turnstile_ok=ts_ok)
        except khach.ChoDuyet:
            return RedirectResponse("/tai-khoan/cho-duyet", status_code=303)
        except khach.KhachLoi as e:
            return _loi_dang_nhap(request, e, dinh_danh, tiep)
        sess, token = khach.tao_phien(conn, acc, web.ip_cua(request), _ua(request))
        resp = _sang_crm(conn, request, acc, sess["id"], tiep)
    finally:
        conn.close()
    resp.set_cookie(khach.COOKIE_PHIEN, token, max_age=config.KHACH_SESSION_HOURS * 3600,
                    path=khach.COOKIE_PATH, httponly=True, samesite="lax",
                    secure=_secure(request))
    # Thiết bị tin cậy (gắn token_version): miễn giới hạn theo IP và giới hạn toàn cục của
    # đúng tài khoản này; vẫn chịu khoá theo cặp (tài khoản, IP).
    resp.set_cookie(khach.COOKIE_THIET_BI, khach.tao_thiet_bi(acc),
                    max_age=config.KHACH_THIET_BI_NGAY * 86400, path=khach.COOKIE_PATH,
                    httponly=True, samesite="lax", secure=_secure(request))
    return resp


def _dat_cookie_phien(resp: Response, request: Request, token: str, acc: dict) -> None:
    resp.set_cookie(khach.COOKIE_PHIEN, token, max_age=config.KHACH_SESSION_HOURS * 3600,
                    path=khach.COOKIE_PATH, httponly=True, samesite="lax",
                    secure=_secure(request))
    resp.set_cookie(khach.COOKIE_THIET_BI, khach.tao_thiet_bi(acc),
                    max_age=config.KHACH_THIET_BI_NGAY * 86400, path=khach.COOKIE_PATH,
                    httponly=True, samesite="lax", secure=_secure(request))


@khach_app.get("/tai-khoan/ho-so")
def ho_so(request: Request):
    conn = db.connect()
    try:
        ctx = _ctx_phien(request, conn)
    finally:
        conn.close()
    if not ctx:
        return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)
    acc = ctx["account"]
    return _render(request, "ho_so.html", page_title="Tài khoản của tôi",
                   csrf=ctx["session"]["csrf_token"], acc=acc,
                   sdt_che=khach.che_sdt(acc["phone_e164"]),
                   da_doi=request.query_params.get("da_doi") == "1")


@khach_app.get("/tai-khoan/doi-mat-khau")
def doi_mat_khau_form(request: Request):
    conn = db.connect()
    try:
        ctx = _ctx_phien(request, conn)
    finally:
        conn.close()
    if not ctx:
        return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)
    return _render(request, "doi_mat_khau.html", page_title="Đổi mật khẩu",
                   csrf=ctx["session"]["csrf_token"])


@khach_app.post("/tai-khoan/doi-mat-khau")
async def doi_mat_khau(request: Request, mat_khau_cu: str = Form(""), mat_khau: str = Form(""),
                       mat_khau_2: str = Form(""), csrf_form: str = Form("", alias="_csrf")):
    ctx = await asyncio.to_thread(_doc_phien, request)  # SQLite ngoài event loop
    if not ctx:
        return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)
    if not _kiem_csrf(request, csrf_form, ctx["session"]["csrf_token"]):
        return _loi_csrf(request)
    return await _chay_kdf(request, _doi_mat_khau, request, ctx, mat_khau_cu[:200],
                           mat_khau[:200], mat_khau_2[:200])


def _doi_mat_khau(request: Request, ctx: dict, cu: str, moi: str, moi2: str) -> Response:
    conn = db.connect()
    try:
        try:
            sess, token, acc = khach.doi_mat_khau(conn, ctx, cu, moi, moi2, _ip_khoa(request),
                                                  _ua(request), request)
        except khach.KhachLoi as e:
            return _render(request, "doi_mat_khau.html", e.status, page_title="Đổi mật khẩu",
                           csrf=ctx["session"]["csrf_token"], loi=e.message)
    finally:
        conn.close()
    resp = RedirectResponse("/tai-khoan/ho-so?da_doi=1", status_code=303)
    _dat_cookie_phien(resp, request, token, acc)  # phiên mới + cookie thiết bị mới
    return resp


@khach_app.get("/tai-khoan/vao-cong")
def vao_cong(request: Request, tiep: str = ""):
    conn = db.connect()
    try:
        ctx_goc = khach.xac_thuc_phien(conn, request.cookies.get(khach.COOKIE_PHIEN))
        if ctx_goc and not khach.pilot_cho_phep(ctx_goc["account"]["phone_e164"]):
            return _trang_pilot(request)
        ctx = _ctx_phien(request, conn)
        if not ctx:
            return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)
        try:  # phiên được kiểm lại TRONG giao dịch phát token (đua với đăng xuất)
            return _sang_crm(conn, request, ctx["account"], ctx["session"]["id"], tiep[:2000])
        except khach.KhachLoi:
            return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)
    finally:
        conn.close()


@khach_app.get("/tai-khoan/dang-xuat")
def dang_xuat_form(request: Request):
    conn = db.connect()
    try:
        # Đăng xuất luôn dùng được, kể cả tài khoản đã bị rút khỏi pilot.
        ctx = khach.xac_thuc_phien(conn, request.cookies.get(khach.COOKIE_PHIEN))
    finally:
        conn.close()
    if not ctx:
        return _render(request, "thong_bao.html", page_title="Đăng xuất", tieu_de="Bạn đã đăng xuất",
                       noi_dung="Không còn phiên đăng nhập nào trên trình duyệt này.",
                       link_dang_nhap=True)
    return _render(request, "dang_xuat.html", page_title="Đăng xuất",
                   csrf=ctx["session"]["csrf_token"])


@khach_app.post("/tai-khoan/dang-xuat")
def dang_xuat(request: Request, csrf_form: str = Form("", alias="_csrf")):
    conn = db.connect()
    try:
        ctx = khach.xac_thuc_phien(conn, request.cookies.get(khach.COOKIE_PHIEN))  # cả ngoài pilot
        if ctx:
            if not _kiem_csrf(request, csrf_form, ctx["session"]["csrf_token"]):
                return _loi_csrf(request)
            khach.dang_xuat(conn, ctx, request)
    finally:
        conn.close()
    resp = RedirectResponse("/tai-khoan/dang-nhap?da_thoat=1", status_code=303)
    resp.delete_cookie(khach.COOKIE_PHIEN, path=khach.COOKIE_PATH, httponly=True,
                       samesite="lax", secure=_secure(request))
    return resp


@khach_app.get("/tai-khoan/quen-mat-khau")
def quen_form(request: Request):
    # Email tắt (mặc định): khôi phục do nhân viên hỗ trợ — trang chỉ hướng dẫn liên hệ.
    return _render(request, "quen_mat_khau.html", page_title="Quên mật khẩu",
                   email_bat=config.KHACH_EMAIL_ENABLED, hotline=config.KHACH_HOTLINE)


@khach_app.post("/tai-khoan/quen-mat-khau")
def quen(request: Request, dinh_danh: str = Form(""), csrf_form: str = Form("", alias="_csrf")):
    if not config.KHACH_EMAIL_ENABLED:
        raise StarletteHTTPException(status_code=404)
    if not _kiem_csrf(request, csrf_form):
        return _loi_csrf(request)
    conn = db.connect()
    try:
        khach.yeu_cau_khoi_phuc(conn, dinh_danh[:254], _ip_khoa(request), request)
    finally:
        conn.close()
    return _render(request, "quen_mat_khau.html", page_title="Quên mật khẩu", da_gui=True,
                   email_bat=True, hotline=config.KHACH_HOTLINE)


@khach_app.get("/tai-khoan/dat-lai")
def dat_lai_form(request: Request, t: str = ""):
    conn = db.connect()
    try:
        tk = khach.xem_token(conn, t, "khoi_phuc")
        ok = tk is not None
        acc = khach.tai_khoan(conn, tk["account_id"]) if tk else None
    finally:
        conn.close()
    if acc and not khach.pilot_cho_phep(acc["phone_e164"]):
        return _trang_pilot(request)
    return _render(request, "dat_lai.html", 200 if ok else 400, page_title="Đặt lại mật khẩu",
                   token=t if ok else "", hop_le=ok)


@khach_app.post("/tai-khoan/dat-lai")
async def dat_lai(request: Request, t: str = Form(""), mat_khau: str = Form(""),
                  mat_khau_2: str = Form(""), csrf_form: str = Form("", alias="_csrf")):
    if not _kiem_csrf(request, csrf_form):
        return _loi_csrf(request)
    return await _chay_kdf(request, _dat_lai, request, t, mat_khau, mat_khau_2)


def _dat_lai(request: Request, t: str, mat_khau: str, mat_khau_2: str) -> Response:
    conn = db.connect()
    try:
        khach.dat_lai_mat_khau(conn, t, mat_khau[:200], mat_khau_2[:200], request)
    except khach.KhachPilot:
        return _trang_pilot(request)
    except khach.KhachLoi as e:
        hop_le = khach.xem_token(conn, t, "khoi_phuc") is not None
        return _render(request, "dat_lai.html", e.status, page_title="Đặt lại mật khẩu",
                       token=t if hop_le else "", hop_le=hop_le, loi=e.message)
    finally:
        conn.close()
    resp = _render(request, "thong_bao.html", page_title="Đã đặt lại mật khẩu",
                   tieu_de="Đã đặt mật khẩu mới",
                   noi_dung="Mọi phiên đăng nhập cũ đã bị đăng xuất. Hãy đăng nhập lại bằng "
                            "mật khẩu mới.", link_dang_nhap=True)
    resp.delete_cookie(khach.COOKIE_PHIEN, path=khach.COOKIE_PATH)
    return resp


# ------------------------------------------------------------------ API nội bộ (HMAC)
def _jloi(status: int, ma: str, thong_bao: str) -> JSONResponse:
    return JSONResponse(status_code=status,
                        content={"ok": False, "loi": {"ma": ma, "thongBao": thong_bao}})


GIOI_HAN_BODY = 10_000


async def _doc_body(request: Request) -> bytes | None:
    """Kiểm Content-Length TRƯỚC khi đọc; đọc dạng luồng và cắt ở giới hạn."""
    try:
        cl = int(request.headers.get("content-length", ""))
    except ValueError:
        return None
    if cl < 0 or cl > GIOI_HAN_BODY:
        return None
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > GIOI_HAN_BODY:
            return None
    return bytes(buf)


def _noi_bo_dong_bo(request: Request, xu_ly, raw: bytes):
    conn = db.connect()
    try:
        kq_ky = khach.xac_thuc_vao(conn, request.method, request.url.path,
                                   request.headers.get("x-portal-ts"),
                                   request.headers.get("x-portal-sig"), raw)
        if kq_ky == "phat_lai":
            return _jloi(409, "PHAT_LAI", "Chữ ký này đã được dùng; ký lại với X-Portal-Ts mới."), 0, None
        if kq_ky != "ok":
            khach._ghi_audit(conn, "crm", "khach.hmac.sai", detail={"path": request.url.path},
                             request=request, lay_mau=_ip_khoa(request))
            return _jloi(401, "CHU_KY_SAI", "Chữ ký nội bộ không hợp lệ hoặc đã hết hạn."), 0, None
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return _jloi(400, "JSON_SAI", "Body phải là JSON object."), 0, None
        status, kq = xu_ly(conn, data, request)
        return None, status, kq
    finally:
        conn.close()


async def _noi_bo(request: Request, xu_ly) -> JSONResponse:
    raw = await _doc_body(request)
    if raw is None:
        return _jloi(413, "QUA_LON", "Thiếu Content-Length hoặc yêu cầu quá lớn (tối đa 10 KB).")
    # Mọi thao tác SQLite (kiểm/ghi chữ ký đã dùng, audit, xử lý) chạy NGOÀI event loop: một
    # khoá ghi đang bị giữ không làm treo các route async khác (kể cả route nhân viên).
    kq_loi, status, kq = await asyncio.to_thread(_noi_bo_dong_bo, request, xu_ly, raw)
    if kq_loi is not None:
        return kq_loi
    if status >= 400:
        return _jloi(status, kq.get("ma", "LOI"), kq.get("thongBao", ""))
    return JSONResponse({"ok": True, "data": kq})


@khach_app.post("/api/internal/khach/ket-qua-duyet")
async def api_ket_qua_duyet(request: Request):
    return await _noi_bo(request, khach.ket_qua_duyet)


@khach_app.post("/api/internal/khach/tam-khoa")
async def api_tam_khoa(request: Request):
    return await _noi_bo(request, khach.tam_khoa)


@khach_app.post("/api/internal/khach/tao-link-dat-lai")
async def api_tao_link_dat_lai(request: Request):
    return await _noi_bo(request, khach.tao_link_dat_lai)


@khach_app.post("/api/internal/khach/thu-hoi")
async def api_thu_hoi(request: Request):
    return await _noi_bo(request, khach.thu_hoi_tu_crm)


# ------------------------------------------------------------------ lỗi
@khach_app.exception_handler(StarletteHTTPException)
async def _http_loi(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return _jloi(exc.status_code, f"HTTP_{exc.status_code}", "Không tìm thấy."
                     if exc.status_code == 404 else "Yêu cầu không hợp lệ.")
    tieu_de = "Không tìm thấy trang" if exc.status_code == 404 else "Yêu cầu không hợp lệ"
    return _render(request, "thong_bao.html", exc.status_code, page_title=tieu_de,
                   tieu_de=tieu_de, noi_dung="Đường dẫn không tồn tại hoặc đã bị gỡ.",
                   link_dang_nhap=True)


@khach_app.exception_handler(Exception)
async def _he_thong(request: Request, exc: Exception):
    log.exception("Lỗi realm khách tại %s", request.url.path)
    if request.url.path.startswith("/api/"):
        return _jloi(500, "LOI_HE_THONG", "Lỗi hệ thống.")
    return _render(request, "thong_bao.html", 500, page_title="Lỗi hệ thống",
                   tieu_de="Đã xảy ra lỗi", noi_dung="Vui lòng thử lại sau ít phút.")


@khach_app.exception_handler(RequestValidationError)
async def _tham_so(request: Request, exc: RequestValidationError):
    return _jloi(400, "THAM_SO_SAI", "Tham số yêu cầu không hợp lệ.")
