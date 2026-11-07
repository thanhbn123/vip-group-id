"""Module CRM trong COWORK: mở CRM nội bộ bằng launch token `cowork-launch/1` (§15.6).

Phân quyền tại backend: `crm.view` để thấy trang, `crm.use` để phát token; vai trò dưới mức
nhân viên (đối tác) luôn bị từ chối; tenant chưa ánh xạ sang CRM bị từ chối. Quyền nghiệp vụ
bên trong CRM do CRM quyết định theo membership — COWORK chỉ chứng thực danh tính.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse

from .. import audit, crm_launch, db, rbac, web
from ..errors import Forbidden

router = APIRouter()


def _du_cap(conn, user: dict) -> bool:
    return rbac.la_super(user) or rbac.cap_vai_tro(conn, user["role_code"]) >= crm_launch.CAP_TOI_THIEU


@router.get("/crm")
async def trang_crm(request: Request):
    user = await web.yeu_cau_dang_nhap(request)
    if not rbac.co_quyen(user, request.state.perms, "crm.view"):
        raise Forbidden("Bạn không được cấp module CRM.")
    conn = db.connect()
    try:
        if not _du_cap(conn, user):
            raise Forbidden("Vai trò này không được vào CRM nội bộ.")
        nhat_ky = [dict(r) for r in conn.execute(
            "SELECT * FROM audit_log WHERE tenant_id=? AND actor_id=? AND action='crm.launch' "
            "ORDER BY id DESC LIMIT 8", (user["tenant_id"], user["id"])).fetchall()]
    finally:
        conn.close()
    loi = crm_launch.loi_cau_hinh()
    tenant = crm_launch.tenant_crm(user["tenant_id"])
    if not tenant:
        loi.append("Tenant COWORK này chưa được ánh xạ sang CRM.")
    return web.render(request, "crm/index.html", page_title="CRM VIP GROUP", user=user,
                      loi=loi, co_use=rbac.co_quyen(user, request.state.perms, "crm.use"),
                      subject=crm_launch.subject(user), tenant_crm=tenant,
                      crm_url=crm_launch.config.CRM_PUBLIC_URL, nhat_ky=nhat_ky)


@router.post("/crm/mo", dependencies=[Depends(web.kiem_csrf)])
async def mo_crm(request: Request):
    user = await web.yeu_cau_dang_nhap(request)
    if not rbac.co_quyen(user, request.state.perms, "crm.use"):
        raise Forbidden("Bạn không được cấp quyền mở CRM.")
    conn = db.connect()
    try:
        if not _du_cap(conn, user):
            raise Forbidden("Vai trò này không được vào CRM nội bộ.")
        if crm_launch.loi_cau_hinh() or not crm_launch.tenant_crm(user["tenant_id"]):
            return web.chuyen_huong("/crm", "CRM chưa được cấu hình kết nối. Liên hệ quản trị.", "err")
        token, p = crm_launch.tao_token(user)
        # Không ghi token; nonce đủ để đối chiếu với cowork_nonces phía CRM.
        audit.ghi(conn, user, "crm.launch", target_type="crm", target_id=p["tenant_code"],
                  detail={"sub": p["sub"], "nonce": p["nonce"], "exp": p["exp"],
                          "contract": crm_launch.CONTRACT}, request=request)
    finally:
        conn.close()
    resp = RedirectResponse(crm_launch.url_launch(token), status_code=303)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp
