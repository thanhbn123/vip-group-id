"""Lớp web dùng chung: dependency danh tính/quyền, CSRF, render template, flash."""
from __future__ import annotations

import base64
import ipaddress
import json
from datetime import datetime
from urllib.parse import urlsplit

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

from . import APP_CODE, __version__, auth, config, db, rbac
from .errors import AuthRequired, Forbidden

templates = Jinja2Templates(directory=str(config.BASE_DIR / "cowork" / "templates"))


class MustChangePassword(Exception):
    pass


def ip_cua(request) -> str:
    """IP client cho rate limit/audit. CHỈ tin header khi `COWORK_TIN_PROXY=1`.

    Caddy trên VPS ghi đè `X-Real-IP` bằng peer thật. Khi chạy trực tiếp localhost,
    header do client tự gửi là giả mạo nên phải bỏ qua (mặc định TIN_PROXY=0).
    """
    try:
        if config.TIN_PROXY:
            for header in ("x-real-ip", "x-forwarded-for"):
                raw = (request.headers.get(header) or "").split(",")[0].strip()
                if not raw:
                    continue
                try:
                    return str(ipaddress.ip_address(raw))
                except ValueError:
                    continue
        return request.client.host if request.client else "?"
    except Exception:  # noqa: BLE001
        return "?"


def _dt(value: str | None, fmt: str = "%d/%m/%Y %H:%M") -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime(fmt)
    except (TypeError, ValueError):
        return str(value)[:16]


def _ngay(value: str | None) -> str:
    return _dt(value, "%d/%m/%Y")


def _json_pretty(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return value
    return json.dumps(value, ensure_ascii=False, indent=2)


def _initial(name: str | None) -> str:
    name = (name or "?").strip()
    parts = name.split()
    return "".join(p[0] for p in parts[:2]).upper() if parts else "?"


def _cat(text: str | None, n: int = 80) -> str:
    text = text or ""
    return text if len(text) <= n else text[: n - 1] + "…"


templates.env.filters.update({
    "dt": _dt,
    "ngay": _ngay,
    "json_pretty": _json_pretty,
    "initial": _initial,
    "cat": _cat,
})
templates.env.globals.update({
    "APP_NAME": config.APP_NAME,
    "APP_VERSION": __version__,
    "APP_CODE": APP_CODE,
    "ENV": config.ENV,
})


def _doc_flash(raw: str | None):
    if not raw:
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
        if isinstance(data, dict) and data.get("m"):
            return data
    except (ValueError, TypeError, UnicodeDecodeError):
        return None
    return None


class FlashMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        raw = request.cookies.get(config.FLASH_COOKIE)
        request.state.flash = _doc_flash(raw) if raw else None
        response = await call_next(request)
        if raw:
            response.delete_cookie(config.FLASH_COOKIE, path="/")
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy",
                                    "camera=(), microphone=(), geolocation=()")
        # form-action kiểm tra CẢ đích redirect: POST /brain/mo trả 303 sang
        # ai.vipgroup.com.vn, nên chỉ 'self' sẽ bị Chrome/Safari chặn và người dùng
        # ở lại /brain dù server đã tạo ticket. Chỉ mở đúng origin Brain.
        # Tương tự POST /crm/mo → 303 sang crm.vipgroup.com.vn (§15.6).
        def _origin(url: str) -> str:
            try:
                parts = urlsplit(url)
            except ValueError:
                return ""
            if parts.scheme in ("http", "https") and parts.netloc:
                return f"{parts.scheme}://{parts.netloc}"
            return ""
        origins = [o for o in (_origin(config.BRAIN_PUBLIC_URL),
                               _origin(config.CRM_PUBLIC_URL) if config.CRM_ENABLED else "") if o]
        form_action = " ".join(["'self'"] + list(dict.fromkeys(origins)))
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            f"font-src 'self'; connect-src 'self'; form-action {form_action}; "
            "frame-ancestors 'none'; base-uri 'none'; object-src 'none'")
        if auth.la_https(request):
            response.headers.setdefault("Strict-Transport-Security",
                                        "max-age=31536000; includeSubDomains")
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


def set_flash(response, message: str, kind: str = "ok") -> None:
    raw = base64.urlsafe_b64encode(
        json.dumps({"m": message[:500], "k": kind}, ensure_ascii=False).encode("utf-8")
    ).decode("ascii").rstrip("=")
    response.set_cookie(config.FLASH_COOKIE, raw, max_age=60, path="/",
                        httponly=True, samesite="lax",
                        secure=config.COOKIE_SECURE)


def chuyen_huong(url: str, message: str = "", kind: str = "ok") -> RedirectResponse:
    resp = RedirectResponse(url, status_code=303)
    if message:
        set_flash(resp, message, kind)
    return resp


async def nap_danh_tinh(request: Request) -> dict | None:
    """Dependency gốc: đọc phiên, dựng quyền/module, đặt vào request.state."""
    if getattr(request.state, "user", None) is not None:
        return request.state.user
    token = auth.token_tu_request(request)
    conn = db.connect()
    try:
        ctx = auth.xac_thuc(conn, token)
        if not ctx:
            request.state.user = None
            request.state.session = None
            request.state.perms = set()
            request.state.modules = []
            request.state.csrf = auth.csrf_anon(request)
            return None
        user = ctx["user"]
        perms = rbac.quyen_hieu_luc(conn, user)
        modules = rbac.module_hien_thi(conn, user, perms)
        request.state.user = user
        request.state.session = ctx["session"]
        request.state.perms = perms
        request.state.modules = modules
        request.state.csrf = ctx["session"]["csrf_token"]
        return user
    finally:
        conn.close()


async def yeu_cau_dang_nhap(request: Request) -> dict:
    user = await nap_danh_tinh(request)
    if not user:
        raise AuthRequired("Bạn cần đăng nhập để tiếp tục.")
    if user.get("must_change_password") and request.url.path not in (
            "/doi-mat-khau", "/dang-xuat", "/api/health"):
        raise MustChangePassword()
    return user


def yeu_cau_quyen(quyen: str):
    async def _dep(request: Request) -> dict:
        user = await yeu_cau_dang_nhap(request)
        if not rbac.co_quyen(user, request.state.perms, quyen):
            raise Forbidden(f"Bạn không có quyền '{quyen}'.")
        return user
    return _dep


def yeu_cau_module(code: str):
    async def _dep(request: Request) -> dict:
        user = await yeu_cau_dang_nhap(request)
        if not (rbac.la_super(user) or f"{code}.view" in request.state.perms):
            raise Forbidden("Bạn không được cấp module này.")
        return user
    return _dep


async def kiem_csrf(request: Request) -> None:
    """Dependency cho MỌI route POST dạng form."""
    # Nạp danh tính TRƯỚC khi kiểm CSRF: token CSRF của người đã đăng nhập nằm trong
    # phiên, không phải cookie double-submit dành cho khách.
    await nap_danh_tinh(request)
    token = request.headers.get("x-csrf-token")
    if not token:
        try:
            form = await request.form()
            token = form.get("_csrf")
        except Exception:  # noqa: BLE001 - body không phải form thì để route báo lỗi
            token = None
    auth.kiem_csrf(request, token)


def boi_canh(request: Request, *, page_title: str = "", user: dict | None = None,
             **extra) -> dict:
    user = user if user is not None else getattr(request.state, "user", None)
    modules = getattr(request.state, "modules", []) or []
    nav_workspace = [m for m in modules if m["group_code"] == "workspace"]
    nav_admin = [m for m in modules if m["group_code"] == "admin"]
    path = request.url.path
    active = ""
    for m in sorted(modules, key=lambda x: len(x.get("route") or ""), reverse=True):
        route = m.get("route") or ""
        if route == "/":
            continue
        if path == route or path.startswith(route + "/"):
            active = m["code"]
            break
    if not active and path == "/":
        active = "dashboard"
    ctx = {
        "request": request,
        "user": user,
        "perms": getattr(request.state, "perms", set()),
        "modules": modules,
        "nav_workspace": nav_workspace,
        "nav_admin": nav_admin,
        "active_module": active,
        "csrf": getattr(request.state, "csrf", ""),
        "session": getattr(request.state, "session", None),
        "flash": getattr(request.state, "flash", None),
        "page_title": page_title,
        "current_path": path,
        "brain_enabled": config.BRAIN_ENABLED,
        "is_super": bool(user and user.get("is_super")),
    }
    ctx.update(extra)
    return ctx


def render(request: Request, template: str, *, page_title: str = "", user: dict | None = None,
           status_code: int = 200, **extra):
    from fastapi.responses import HTMLResponse
    return templates.TemplateResponse(
        request=request, name=template, status_code=status_code,
        context=boi_canh(request, page_title=page_title, user=user, **extra))


def trang_thai_quyen_module_cho(user: dict) -> list[dict]:
    conn = db.connect()
    try:
        return __import__("cowork.services", fromlist=["services"]).trang_thai_quyen_module(
            conn, user)
    finally:
        conn.close()
