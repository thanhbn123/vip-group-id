"""VIP GROUP COWORK — ứng dụng FastAPI."""
from __future__ import annotations

import logging
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import config, db, web
from .errors import AuthRequired, CoworkError, Forbidden, NotFound, ValidationError
from .routers import (accounts, audit_routes, auth_routes, brain_routes, dashboard, hatang,
                      departments, internal, modules, roles, settings_routes)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("cowork")


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    log.info("COWORK khởi động — DB=%s · public=%s", config.DB_PATH, config.PUBLIC_URL)
    yield


app = FastAPI(title=config.APP_NAME, version=config.APP_VERSION, docs_url=None,
              redoc_url=None, openapi_url=None, lifespan=lifespan)

app.add_middleware(web.FlashMiddleware)
app.add_middleware(web.SecurityHeadersMiddleware)

app.include_router(auth_routes.router, tags=["auth"])
app.include_router(dashboard.router, tags=["dashboard"])
app.include_router(accounts.router, tags=["accounts"])
app.include_router(departments.router, tags=["departments"])
app.include_router(roles.router, tags=["roles"])
app.include_router(modules.router, tags=["modules"])
app.include_router(audit_routes.router, tags=["audit"])
app.include_router(hatang.router, tags=["hatang"])
app.include_router(settings_routes.router, tags=["settings"])
app.include_router(brain_routes.router, tags=["brain"])
app.include_router(internal.router, tags=["internal"])


@app.head("/")
async def head_root():
    """Health check không cần body; tránh 405 khi giám sát dùng HEAD."""
    return Response(status_code=200, headers={"Cache-Control": "no-store"})


_static = config.BASE_DIR / "cowork" / "static"
_static.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static)), name="static")


def _json_duong(path: str) -> bool:
    return path.startswith("/api/")


def _json_loi(status: int, ma: str, thong_bao: str) -> JSONResponse:
    return JSONResponse(status_code=status,
                        content={"ok": False, "loi": {"ma": ma, "thongBao": thong_bao}})


@app.exception_handler(AuthRequired)
async def _chua_dang_nhap(request: Request, exc: AuthRequired):
    if _json_duong(request.url.path):
        return _json_loi(401, "CHUA_DANG_NHAP", exc.message)
    from urllib.parse import quote
    tiep = quote(request.url.path + (("?" + request.url.query) if request.url.query else ""), safe="")
    resp = RedirectResponse(f"/dang-nhap?next={tiep}", status_code=303)
    web.set_flash(resp, "Vui lòng đăng nhập để tiếp tục.", "err")
    return resp


@app.exception_handler(web.MustChangePassword)
async def _phai_doi_mat_khau(request: Request, exc: web.MustChangePassword):
    return RedirectResponse("/doi-mat-khau", status_code=303)


@app.exception_handler(Forbidden)
async def _khong_du_quyen(request: Request, exc: Forbidden):
    if _json_duong(request.url.path):
        return _json_loi(403, "KHONG_DU_QUYEN", exc.message)
    return web.render(request, "403.html", page_title="Không đủ quyền", status_code=403,
                      thong_bao=exc.message)


@app.exception_handler(NotFound)
async def _khong_tim_thay(request: Request, exc: NotFound):
    if _json_duong(request.url.path):
        return _json_loi(404, "KHONG_TIM_THAY", exc.message)
    return web.render(request, "404.html", page_title="Không tìm thấy", status_code=404,
                      thong_bao=exc.message)


@app.exception_handler(ValidationError)
async def _du_lieu_sai(request: Request, exc: ValidationError):
    if _json_duong(request.url.path):
        return _json_loi(400, "DU_LIEU_SAI", exc.message)
    return web.render(request, "400.html", page_title="Dữ liệu chưa đúng", status_code=400,
                      thong_bao=exc.message)


@app.exception_handler(CoworkError)
async def _loi_nghiep_vu(request: Request, exc: CoworkError):
    if _json_duong(request.url.path):
        return _json_loi(exc.status, exc.code, exc.message)
    return web.render(request, "400.html", page_title="Không thực hiện được",
                      status_code=exc.status, thong_bao=exc.message)


@app.exception_handler(StarletteHTTPException)
async def _http_exception(request: Request, exc: StarletteHTTPException):
    """Route không tồn tại / sai method: API trả JSON, trình duyệt nhận trang HTML."""
    chi_tiet = exc.detail if isinstance(exc.detail, str) else "Yêu cầu không hợp lệ."
    if _json_duong(request.url.path):
        return _json_loi(exc.status_code, f"HTTP_{exc.status_code}", chi_tiet)
    if exc.status_code == 404:
        return web.render(request, "404.html", page_title="Không tìm thấy", status_code=404,
                          thong_bao="Đường dẫn không tồn tại hoặc đã bị gỡ.")
    if exc.status_code == 403:
        return web.render(request, "403.html", page_title="Không đủ quyền", status_code=403,
                          thong_bao=chi_tiet)
    return web.render(request, "400.html", page_title="Không thực hiện được",
                      status_code=exc.status_code, thong_bao=chi_tiet)


@app.exception_handler(RequestValidationError)
async def _tham_so_sai(request: Request, exc: RequestValidationError):
    return _json_loi(400, "THAM_SO_SAI", "Tham số yêu cầu không hợp lệ.")


@app.exception_handler(Exception)
async def _loi_he_thong(request: Request, exc: Exception):
    log.error("Lỗi không bắt được tại %s: %s\n%s", request.url.path, exc, traceback.format_exc())
    if _json_duong(request.url.path):
        return _json_loi(500, "LOI_HE_THONG", "Lỗi hệ thống.")
    return web.render(request, "500.html", page_title="Lỗi hệ thống", status_code=500,
                      thong_bao="Đã xảy ra lỗi hệ thống. Sự việc được ghi log để kiểm tra.")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return Response(status_code=204)


@app.get("/robots.txt", include_in_schema=False)
async def robots():
    return Response("User-agent: *\nDisallow: /\n", media_type="text/plain")


if __name__ == "__main__":
    import uvicorn
    db.init_db()
    uvicorn.run("cowork.main:app", host=config.HOST, port=config.PORT, reload=False)
