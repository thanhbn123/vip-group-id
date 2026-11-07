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
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

from fastapi import FastAPI, Form, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
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
        if realm == "khach" and config.KHACH_ENABLED:
            await khach_app(scope, receive, send)
        elif realm == "staff":
            await self.app(scope, receive, send)
        else:
            # Host thiếu/lạ/sai cú pháp: KHÔNG BAO GIỜ rơi về realm nhân viên.
            await _sai_host(scope, receive, send)


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
                "BRAND": "CÔNG TY TNHH VIP GROUP"})
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
    return khach.xac_thuc_phien(conn, request.cookies.get(khach.COOKIE_PHIEN))


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


async def _vuot_turnstile(request: Request, token: str) -> bool:
    if not khach.turnstile_bat() or not token or len(token) > 2048:
        return False
    kq = await turnstile_siteverify(khach.turnstile_secret(), token, web.ip_cua(request))
    return khach.ket_qua_turnstile_hop_le(kq, request.headers.get("host"))


def _ua(request: Request) -> str:
    return request.headers.get("user-agent") or ""


def _sang_crm(conn, request: Request, acc: dict) -> RedirectResponse:
    token = khach.phat_launch_token(conn, acc, request)
    return RedirectResponse(khach.url_launch(token), status_code=303)


# ------------------------------------------------------------------ trang
@khach_app.get("/tai-khoan")
@khach_app.get("/tai-khoan/")
def goc():
    return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)


@khach_app.get("/tai-khoan/dang-ky")
def dang_ky_form(request: Request):
    return _render(request, "dang_ky.html", page_title="Đăng ký tài khoản", form={})


@khach_app.post("/tai-khoan/dang-ky")
async def dang_ky(request: Request, ho_ten: str = Form(""), sdt: str = Form(""),
                  email: str = Form(""), mat_khau: str = Form(""), mat_khau_2: str = Form(""),
                  dong_y: str = Form(""), csrf_form: str = Form("", alias="_csrf")):
    if not _kiem_csrf(request, csrf_form):
        return _loi_csrf(request)
    return await _chay_kdf(request, _dang_ky, request, ho_ten, sdt, email, mat_khau,
                           mat_khau_2, dong_y)


def _dang_ky(request, ho_ten, sdt, email, mat_khau, mat_khau_2, dong_y) -> Response:
    form = {"ho_ten": ho_ten[:100], "sdt": sdt[:30], "email": email[:254]}
    conn = db.connect()
    try:
        khach.dang_ky(conn, ho_ten=ho_ten, sdt=sdt, email=email, mat_khau=mat_khau[:200],
                      mat_khau_2=mat_khau_2[:200], dong_y=dong_y == "1",
                      ip=_ip_khoa(request), request=request)
    except khach.KhachLoi as e:
        return _render(request, "dang_ky.html", e.status, page_title="Đăng ký tài khoản",
                       loi=e.message, form=form)
    finally:
        conn.close()
    return RedirectResponse("/tai-khoan/da-gui-email", status_code=303)


@khach_app.get("/tai-khoan/da-gui-email")
def da_gui_email(request: Request):
    return _render(request, "da_gui_email.html", page_title="Kiểm tra email")


@khach_app.get("/tai-khoan/gui-lai-xac-minh")
def gui_lai_form(request: Request):
    return _render(request, "gui_lai.html", page_title="Gửi lại email xác minh")


@khach_app.post("/tai-khoan/gui-lai-xac-minh")
def gui_lai(request: Request, email: str = Form(""), csrf_form: str = Form("", alias="_csrf")):
    if not _kiem_csrf(request, csrf_form):
        return _loi_csrf(request)
    conn = db.connect()
    try:
        khach.gui_lai_xac_minh(conn, email[:254], _ip_khoa(request), request)
    finally:
        conn.close()
    return RedirectResponse("/tai-khoan/da-gui-email", status_code=303)


@khach_app.get("/tai-khoan/xac-minh-email")
def xac_minh_email_form(request: Request, t: str = ""):
    """GET KHÔNG tiêu token (trình quét email mở link trước) — chỉ hiện nút xác nhận."""
    conn = db.connect()
    try:
        ok = khach.xem_token(conn, t, "kich_hoat_email") is not None
    finally:
        conn.close()
    if not ok:
        return _render(request, "xac_minh.html", 400, page_title="Xác minh email", ok=False)
    return _render(request, "xac_minh.html", page_title="Xác minh email", xac_nhan=True,
                   token=t)


@khach_app.post("/tai-khoan/xac-minh-email")
def xac_minh_email(request: Request, t: str = Form(""),
                   csrf_form: str = Form("", alias="_csrf")):
    if not _kiem_csrf(request, csrf_form):
        return _loi_csrf(request)
    conn = db.connect()
    try:
        acc = khach.xac_minh_email(conn, t[:200], request)
    finally:
        conn.close()
    if not acc:
        return _render(request, "xac_minh.html", 400, page_title="Xác minh email", ok=False)
    return _render(request, "xac_minh.html", page_title="Xác minh email", ok=True)


@khach_app.get("/tai-khoan/cho-duyet")
def cho_duyet(request: Request):
    return _render(request, "cho_duyet.html", page_title="Chờ duyệt")


@khach_app.get("/tai-khoan/dang-nhap")
def dang_nhap_form(request: Request):
    conn = db.connect()
    try:
        ctx = _ctx_phien(request, conn)
    finally:
        conn.close()
    if ctx:
        return _render(request, "dang_nhap.html", page_title="Đăng nhập",
                       da_dang_nhap=ctx["account"], csrf=ctx["session"]["csrf_token"])
    return _render(request, "dang_nhap.html", page_title="Đăng nhập")


@khach_app.post("/tai-khoan/dang-nhap")
async def dang_nhap(request: Request, dinh_danh: str = Form(""), mat_khau: str = Form(""),
                    csrf_form: str = Form("", alias="_csrf"),
                    cf_token: str = Form("", alias="cf-turnstile-response")):
    dinh_danh = dinh_danh[:40]
    thiet_bi = request.cookies.get(khach.COOKIE_THIET_BI)
    # Token Turnstile (nếu có) được kiểm phía máy chủ trước; chỉ có tác dụng khi tài khoản đang
    # bị giới hạn toàn cục và client chưa là thiết bị tin cậy.
    ts_ok = await _vuot_turnstile(request, cf_token) if cf_token else False
    conn = db.connect()
    try:
        if not _kiem_csrf(request, csrf_form):
            ctx = _ctx_phien(request, conn)  # đang đăng nhập: chấp nhận token CSRF của phiên
            if not ctx or not _kiem_csrf(request, csrf_form, ctx["session"]["csrf_token"]):
                return _loi_csrf(request)
        # Lớp chặn rẻ chạy ngay (không băm, không vào hàng đợi băm).
        try:
            khach.kiem_chan(conn, dinh_danh, _ip_khoa(request), thiet_bi, request, ts_ok)
        except khach.KhachLoi as e:
            return _loi_dang_nhap(request, e, dinh_danh)
    finally:
        conn.close()
    return await _chay_kdf(request, _dang_nhap, request, dinh_danh, mat_khau[:200], thiet_bi,
                           ts_ok)


def _loi_dang_nhap(request: Request, e: "khach.KhachLoi", dinh_danh: str) -> Response:
    thu_thach = isinstance(e, khach.ThuThach)
    resp = _render(request, "dang_nhap.html", e.status, page_title="Đăng nhập", loi=e.message,
                   dinh_danh=dinh_danh, chua_xac_minh=e.ma == "CHUA_XAC_MINH_EMAIL",
                   thu_thach=thu_thach, turnstile_site_key=config.KHACH_TURNSTILE_SITE_KEY,
                   turnstile_action=khach.TURNSTILE_ACTION)
    if thu_thach:
        resp.headers["x-khach-turnstile"] = "1"  # KhachHeaders mở CSP cho riêng trang này
    return resp


def _dang_nhap(request: Request, dinh_danh: str, mat_khau: str, thiet_bi: str | None,
               ts_ok: bool = False) -> Response:
    conn = db.connect()
    try:
        try:
            acc = khach.dang_nhap(conn, dinh_danh, mat_khau, _ip_khoa(request), request,
                                  thiet_bi=thiet_bi, turnstile_ok=ts_ok)
        except khach.ChoDuyet:
            return RedirectResponse("/tai-khoan/cho-duyet", status_code=303)
        except khach.KhachLoi as e:
            return _loi_dang_nhap(request, e, dinh_danh)
        sess, token = khach.tao_phien(conn, acc, web.ip_cua(request), _ua(request))
        resp = _sang_crm(conn, request, acc)
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


@khach_app.get("/tai-khoan/vao-cong")
def vao_cong(request: Request):
    conn = db.connect()
    try:
        ctx = _ctx_phien(request, conn)
        if not ctx:
            return RedirectResponse("/tai-khoan/dang-nhap", status_code=303)
        return _sang_crm(conn, request, ctx["account"])
    finally:
        conn.close()


@khach_app.get("/tai-khoan/dang-xuat")
def dang_xuat_form(request: Request):
    conn = db.connect()
    try:
        ctx = _ctx_phien(request, conn)
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
        ctx = _ctx_phien(request, conn)
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
    return _render(request, "quen_mat_khau.html", page_title="Quên mật khẩu")


@khach_app.post("/tai-khoan/quen-mat-khau")
def quen(request: Request, dinh_danh: str = Form(""), csrf_form: str = Form("", alias="_csrf")):
    if not _kiem_csrf(request, csrf_form):
        return _loi_csrf(request)
    conn = db.connect()
    try:
        khach.yeu_cau_khoi_phuc(conn, dinh_danh[:254], _ip_khoa(request), request)
    finally:
        conn.close()
    return _render(request, "quen_mat_khau.html", page_title="Quên mật khẩu", da_gui=True)


@khach_app.get("/tai-khoan/dat-lai")
def dat_lai_form(request: Request, t: str = ""):
    conn = db.connect()
    try:
        ok = khach.xem_token(conn, t, "khoi_phuc") is not None
    finally:
        conn.close()
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


async def _noi_bo(request: Request, xu_ly) -> JSONResponse:
    raw = await _doc_body(request)
    if raw is None:
        return _jloi(413, "QUA_LON", "Thiếu Content-Length hoặc yêu cầu quá lớn (tối đa 10 KB).")
    conn = db.connect()
    try:
        kq_ky = khach.xac_thuc_vao(conn, request.method, request.url.path,
                                   request.headers.get("x-portal-ts"),
                                   request.headers.get("x-portal-sig"), raw)
        if kq_ky == "phat_lai":
            return _jloi(409, "PHAT_LAI", "Chữ ký này đã được dùng; ký lại với X-Portal-Ts mới.")
        if kq_ky != "ok":
            khach._ghi_audit(conn, "crm", "khach.hmac.sai", detail={"path": request.url.path},
                             request=request, lay_mau=_ip_khoa(request))
            return _jloi(401, "CHU_KY_SAI", "Chữ ký nội bộ không hợp lệ hoặc đã hết hạn.")
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return _jloi(400, "JSON_SAI", "Body phải là JSON object.")
        status, kq = xu_ly(conn, data, request)
    finally:
        conn.close()
    if status >= 400:
        return _jloi(status, kq.get("ma", "LOI"), kq.get("thongBao", ""))
    return JSONResponse({"ok": True, "data": kq})


@khach_app.post("/api/internal/khach/ket-qua-duyet")
async def api_ket_qua_duyet(request: Request):
    return await _noi_bo(request, khach.ket_qua_duyet)


@khach_app.post("/api/internal/khach/tam-khoa")
async def api_tam_khoa(request: Request):
    return await _noi_bo(request, khach.tam_khoa)


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
