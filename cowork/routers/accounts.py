"""Quản lý tài khoản: danh sách, tạo, sửa, khoá, mật khẩu, phiên, phân quyền module."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse

from .. import audit, auth, config, db, rbac, security, services, web
from ..errors import Conflict, Forbidden, NotFound, ValidationError



def _chan_ten_danh_rieng(request: Request) -> None:
    """Chạy TRƯỚC kiểm đăng nhập: /tai-khoan/<tên realm khách> luôn 404 trên host nhân viên."""
    if request.path_params.get("user_id") in security.TEN_DANH_RIENG_KHACH:
        raise NotFound("Không tìm thấy tài khoản trong tenant.")


router = APIRouter(dependencies=[Depends(_chan_ten_danh_rieng)])


# ------------------------------------------------------------------ tiện ích
def _target(conn, actor: dict, user_id: str) -> dict:
    row = conn.execute("SELECT * FROM users WHERE id=? AND tenant_id=?",
                       (user_id, actor["tenant_id"])).fetchone()
    if not row:
        raise NotFound("Không tìm thấy tài khoản trong tenant.")
    return dict(row)


def _ds_ban(conn, actor: dict) -> list[dict]:
    scope = rbac.pham_vi_ban(conn, actor)
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM departments WHERE tenant_id=? AND status='active' ORDER BY name",
        (actor["tenant_id"],)).fetchall()]
    if scope is None:
        return rows
    return [r for r in rows if r["id"] in scope]


def _ds_vai_tro(conn, actor: dict) -> list[dict]:
    rows = [dict(r) for r in conn.execute("SELECT * FROM roles ORDER BY level DESC").fetchall()]
    return [r for r in rows if rbac.co_the_gan_vai_tro(conn, actor, r["code"])]


def _co_the_sua(conn, actor: dict, perms: set[str], target: dict) -> bool:
    if target["role_code"] == rbac.SUPER:
        return False
    return rbac.co_the_quan_ly(conn, actor, perms, target, "accounts.update")


# ------------------------------------------------------------------ danh sách
@router.get("/tai-khoan")
async def danh_sach(request: Request, q: str = "", vaiTro: str = "", ban: str = "",
                    trangThai: str = "", page: int = Query(1, ge=1)):
    user = await web.yeu_cau_dang_nhap(request)
    if not rbac.co_quyen(user, request.state.perms, "accounts.view"):
        raise Forbidden("Bạn không có quyền xem danh sách tài khoản.")
    conn = db.connect()
    try:
        where = ["u.tenant_id=?"]
        params: list = [user["tenant_id"]]
        scope = rbac.pham_vi_ban(conn, user)
        if scope is not None:
            if not scope:
                where.append("0=1")
            else:
                where.append("u.department_id IN (" + ",".join("?" * len(scope)) + ")")
                params += list(scope)
        if q.strip():
            where.append("(u.id LIKE ? OR u.display_name LIKE ? OR u.email LIKE ?)")
            like = f"%{q.strip()[:60]}%"
            params += [like, like, like]
        if vaiTro:
            where.append("u.role_code=?")
            params.append(vaiTro)
        if ban:
            where.append("u.department_id=?")
            params.append(ban)
        if trangThai:
            where.append("u.status=?")
            params.append(trangThai)
        else:
            where.append("u.status<>'archived'")
        sql_where = " AND ".join(where)
        total = conn.execute(f"SELECT COUNT(*) FROM users u WHERE {sql_where}", params).fetchone()[0]
        page_size = 20
        offset = (page - 1) * page_size
        rows = [dict(r) for r in conn.execute(
            f"SELECT u.*, r.name AS role_name, r.level AS role_level, d.name AS department_name "
            f"FROM users u JOIN roles r ON r.code=u.role_code "
            f"LEFT JOIN departments d ON d.id=u.department_id "
            f"WHERE {sql_where} ORDER BY r.level DESC, u.id LIMIT ? OFFSET ?",
            (*params, page_size, offset)).fetchall()]
        vai_tro_ds = [dict(r) for r in conn.execute("SELECT * FROM roles ORDER BY level DESC").fetchall()]
        ban_ds = _ds_ban(conn, user)
    finally:
        conn.close()
    return web.render(request, "accounts/list.html", page_title="Tài khoản", user=user,
                      rows=rows, total=int(total), page=page,
                      pages=max(1, (int(total) + 19) // 20), q=q, vaiTro=vaiTro, ban=ban,
                      trangThai=trangThai, vai_tro_ds=vai_tro_ds, ban_ds=ban_ds,
                      co_tao=rbac.co_quyen(user, request.state.perms, "accounts.create"))


@router.get("/phan-quyen")
async def tong_quan_phan_quyen(request: Request, q: str = "", page: int = Query(1, ge=1)):
    """Tổng quan quyền module của từng nhân sự — lối vào màn phân quyền riêng."""
    user = await web.yeu_cau_dang_nhap(request)
    if not (rbac.co_quyen(user, request.state.perms, "permissions.view")
            or rbac.co_quyen(user, request.state.perms, "permissions.grant")):
        raise Forbidden("Bạn không có quyền xem phân quyền module.")
    conn = db.connect()
    try:
        where = ["u.tenant_id=?", "u.status<>'archived'"]
        params: list = [user["tenant_id"]]
        scope = rbac.pham_vi_ban(conn, user)
        if scope is not None:
            if not scope:
                where.append("0=1")
            else:
                where.append("u.department_id IN (" + ",".join("?" * len(scope)) + ")")
                params += list(scope)
        if q.strip():
            where.append("(u.id LIKE ? OR u.display_name LIKE ?)")
            like = f"%{q.strip()[:60]}%"
            params += [like, like]
        sql_where = " AND ".join(where)
        total = conn.execute(f"SELECT COUNT(*) FROM users u WHERE {sql_where}", params).fetchone()[0]
        page_size = 20
        rows = [dict(r) for r in conn.execute(
            f"SELECT u.*, r.name AS role_name, r.level AS role_level, d.name AS department_name "
            f"FROM users u JOIN roles r ON r.code=u.role_code "
            f"LEFT JOIN departments d ON d.id=u.department_id "
            f"WHERE {sql_where} ORDER BY r.level DESC, u.id LIMIT ? OFFSET ?",
            (*params, page_size, (page - 1) * page_size)).fetchall()]
        for row in rows:
            states = services.trang_thai_quyen_module(conn, row)
            row["so_hieu_luc"] = sum(1 for s in states if s["effective"] != "block")
            row["so_uy_quyen"] = sum(1 for s in states if s["mode"] != "default")
            row["so_module"] = len(states)
        co_cap = rbac.co_quyen(user, request.state.perms, "permissions.grant")
    finally:
        conn.close()
    return web.render(request, "accounts/permissions_overview.html", page_title="Phân quyền module",
                      user=user, rows=rows, total=int(total), page=page,
                      pages=max(1, (int(total) + 19) // 20), q=q, co_cap=co_cap)


# ------------------------------------------------------------------ tạo
@router.get("/tai-khoan/tao-moi")
async def trang_tao(request: Request):
    user = await web.yeu_cau_dang_nhap(request)
    if not rbac.co_quyen(user, request.state.perms, "accounts.create"):
        raise Forbidden("Bạn không có quyền tạo tài khoản.")
    conn = db.connect()
    try:
        vai_tro = _ds_vai_tro(conn, user)
        ban_ds = _ds_ban(conn, user)
        co_scope_admin = user["role_code"] == rbac.SUPER
    finally:
        conn.close()
    return web.render(request, "accounts/form.html", page_title="Tạo tài khoản", user=user,
                      target=None, vai_tro=vai_tro, ban_ds=ban_ds, co_scope_admin=co_scope_admin,
                      scope_rows=[])


@router.post("/tai-khoan/tao-moi", dependencies=[Depends(web.kiem_csrf)])
async def xu_ly_tao(request: Request):
    user = await web.yeu_cau_dang_nhap(request)
    form = await request.form()
    data = dict(form)
    data["scope_departments"] = form.getlist("scope_departments")
    conn = db.connect()
    try:
        try:
            moi, temp = services.tao_nguoi_dung(conn, user, request.state.perms, data, request)
        except (ValidationError, Conflict, Forbidden) as e:
            vai_tro = _ds_vai_tro(conn, user)
            ban_ds = _ds_ban(conn, user)
            return web.render(request, "accounts/form.html", page_title="Tạo tài khoản",
                              user=user, target=None, vai_tro=vai_tro, ban_ds=ban_ds,
                              co_scope_admin=user["role_code"] == rbac.SUPER,
                              scope_rows=[], form=data, error=e.message, status_code=400)
    finally:
        conn.close()
    return web.render(request, "accounts/created.html", page_title="Đã tạo tài khoản", user=user,
                      moi=moi, temp=temp)


# ------------------------------------------------------------------ chi tiết
@router.get("/tai-khoan/{user_id}")
async def chi_tiet(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    if not rbac.co_quyen(user, request.state.perms, "accounts.view"):
        raise Forbidden("Bạn không có quyền xem tài khoản.")
    conn = db.connect()
    try:
        target = auth.nguoi_dung_day_du(conn, user_id)
        if not target or target["tenant_id"] != user["tenant_id"]:
            raise NotFound("Không tìm thấy tài khoản trong tenant.")
        if not rbac.la_super(user) and not rbac.trong_pham_vi(
                conn, user, target.get("department_id")) and target["id"] != user["id"]:
            raise Forbidden("Tài khoản này nằm ngoài phạm vi bạn được uỷ quyền.")
        phien = [dict(r) for r in conn.execute(
            "SELECT * FROM sessions WHERE user_id=? AND status='active' ORDER BY created_at DESC",
            (user_id,)).fetchall()]
        nhat_ky = audit.cua_user(conn, user["tenant_id"], user_id, 20)
        quyen_module = services.trang_thai_quyen_module(conn, target)
        scopes = [dict(r) for r in conn.execute(
            "SELECT s.*, d.name AS department_name FROM admin_scopes s "
            "LEFT JOIN departments d ON d.id=s.department_id WHERE s.user_id=?",
            (user_id,)).fetchall()]
        ban_ds = _ds_ban(conn, user)
        vai_tro = _ds_vai_tro(conn, user)
        co_sua = _co_the_sua(conn, user, request.state.perms, target)
        # Nút hành động chỉ hiện khi service tương ứng thực sự cho phép thao tác
        # (đúng cấp, đúng phạm vi, không phải Super Admin/tài khoản đã lưu trữ).
        co_cap_quyen = rbac.co_the_quan_ly(conn, user, request.state.perms, target,
                                          "permissions.grant")
        co_thu_hoi_phien = rbac.co_the_quan_ly(conn, user, request.state.perms, target,
                                              "accounts.revoke_sessions")
        co_dat_mat_khau = rbac.co_the_quan_ly(conn, user, request.state.perms, target,
                                             "accounts.reset_password")
        co_khoa = rbac.co_the_quan_ly(conn, user, request.state.perms, target,
                                      "accounts.suspend")
        co_luu_tru = rbac.co_the_quan_ly(conn, user, request.state.perms, target,
                                         "accounts.archive")
        co_scope = user["role_code"] == rbac.SUPER and target["role_code"] == rbac.ADMIN
    finally:
        conn.close()
    return web.render(request, "accounts/detail.html", page_title=f"Tài khoản · {user_id}",
                      user=user, target=target, phien=phien, nhat_ky=nhat_ky,
                      quyen_module=quyen_module, scopes=scopes, ban_ds=ban_ds, vai_tro=vai_tro,
                      co_sua=co_sua, co_cap_quyen=co_cap_quyen,
                      co_thu_hoi_phien=co_thu_hoi_phien, co_dat_mat_khau=co_dat_mat_khau,
                      co_khoa=co_khoa, co_luu_tru=co_luu_tru, co_scope=co_scope)


@router.post("/tai-khoan/{user_id}", dependencies=[Depends(web.kiem_csrf)])
async def xu_ly_cap_nhat(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    form = await request.form()
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        try:
            services.cap_nhat_nguoi_dung(conn, user, request.state.perms, target, dict(form), request)
        except (ValidationError, Forbidden, Conflict) as e:
            return web.chuyen_huong(f"/tai-khoan/{user_id}", e.message, "err")
    finally:
        conn.close()
    return web.chuyen_huong(f"/tai-khoan/{user_id}", "Đã cập nhật tài khoản.")


# ------------------------------------------------------------------ hành động
@router.post("/tai-khoan/{user_id}/khoa", dependencies=[Depends(web.kiem_csrf)])
async def khoa(request: Request, user_id: str):
    return await _doi_trang_thai(request, user_id, "suspended")


@router.post("/tai-khoan/{user_id}/mo-khoa", dependencies=[Depends(web.kiem_csrf)])
async def mo_khoa(request: Request, user_id: str):
    return await _doi_trang_thai(request, user_id, "active")


async def _doi_trang_thai(request: Request, user_id: str, trang_thai: str):
    user = await web.yeu_cau_dang_nhap(request)
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        try:
            services.doi_trang_thai(conn, user, request.state.perms, target, trang_thai, request)
        except (Forbidden, ValidationError) as e:
            return web.chuyen_huong(f"/tai-khoan/{user_id}", e.message, "err")
    finally:
        conn.close()
    thong_bao = "Đã khoá tài khoản và thu hồi mọi phiên." if trang_thai == "suspended" else "Đã mở khoá tài khoản."
    return web.chuyen_huong(f"/tai-khoan/{user_id}", thong_bao)


@router.post("/tai-khoan/{user_id}/dat-lai-mat-khau", dependencies=[Depends(web.kiem_csrf)])
async def dat_lai_mat_khau(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        try:
            temp = services.dat_lai_mat_khau(conn, user, request.state.perms, target, request)
        except (Forbidden, ValidationError) as e:
            return web.chuyen_huong(f"/tai-khoan/{user_id}", e.message, "err")
        target = auth.nguoi_dung_day_du(conn, user_id)
    finally:
        conn.close()
    return web.render(request, "accounts/created.html", page_title="Mật khẩu tạm mới", user=user,
                      moi=target, temp=temp, reset=True)


@router.post("/tai-khoan/{user_id}/luu-tru", dependencies=[Depends(web.kiem_csrf)])
async def luu_tru(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        try:
            services.luu_tru_nguoi_dung(conn, user, request.state.perms, target, request)
        except (Forbidden, ValidationError) as e:
            return web.chuyen_huong(f"/tai-khoan/{user_id}", e.message, "err")
    finally:
        conn.close()
    return web.chuyen_huong("/tai-khoan", "Đã lưu trữ tài khoản.")


@router.post("/tai-khoan/{user_id}/thu-hoi-phien", dependencies=[Depends(web.kiem_csrf)])
async def thu_hoi_phien(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    if not rbac.co_quyen(user, request.state.perms, "accounts.revoke_sessions"):
        raise Forbidden("Bạn không có quyền thu hồi phiên.")
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        rbac.kiem_tra_quan_ly(conn, user, request.state.perms, target, "accounts.revoke_sessions")
        n = auth.thu_hoi_cua_user(conn, user_id, user["id"], "Quản trị thu hồi phiên")
        from .. import brain
        brain.thu_hoi_phien(conn, user_id, "COWORK thu hồi phiên")
        audit.ghi(conn, user, "account.revoke_sessions", target_type="user", target_id=user_id,
                  detail={"soPhien": n}, request=request)
    finally:
        conn.close()
    return web.chuyen_huong(f"/tai-khoan/{user_id}", f"Đã thu hồi {n} phiên đang hoạt động.")


@router.post("/tai-khoan/{user_id}/phien/{session_id}/thu-hoi", dependencies=[Depends(web.kiem_csrf)])
async def thu_hoi_mot_phien(request: Request, user_id: str, session_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    if not rbac.co_quyen(user, request.state.perms, "accounts.revoke_sessions"):
        raise Forbidden("Bạn không có quyền thu hồi phiên.")
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        rbac.kiem_tra_quan_ly(conn, user, request.state.perms, target, "accounts.revoke_sessions")
        # Phiên phải thuộc đúng tài khoản/tenant đang thao tác; nếu không, một
        # session_id của người khác (VD Super Admin) có thể bị thu hồi qua URL.
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE id=? AND user_id=? AND tenant_id=? AND status='active'",
            (session_id, user_id, user["tenant_id"])).fetchone()
        if row:
            ok = auth.thu_hoi_phien(conn, session_id, user["id"], "Quản trị thu hồi phiên")
            audit.ghi(conn, user, "account.revoke_session", target_type="session",
                      target_id=session_id, detail={"user": user_id, "ok": ok}, request=request)
        else:
            ok = False
            audit.ghi(conn, user, "account.revoke_session", target_type="user",
                      target_id=user_id, detail={"ok": False}, request=request)
    finally:
        conn.close()
    return web.chuyen_huong(f"/tai-khoan/{user_id}",
                            "Đã thu hồi phiên." if ok else "Không tìm thấy phiên đang hoạt động.", "ok" if ok else "err")


# ------------------------------------------------------------------ phân quyền module
@router.get("/tai-khoan/{user_id}/phan-quyen")
async def trang_phan_quyen(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    conn = db.connect()
    try:
        target = auth.nguoi_dung_day_du(conn, user_id)
        if not target or target["tenant_id"] != user["tenant_id"]:
            raise NotFound("Không tìm thấy tài khoản trong tenant.")
        if not (rbac.co_quyen(user, request.state.perms, "permissions.view")
                or rbac.co_quyen(user, request.state.perms, "permissions.grant")):
            raise Forbidden("Bạn không có quyền xem phân quyền module.")
        if target["id"] != user["id"] and not rbac.trong_pham_vi(
                conn, user, target.get("department_id")):
            raise Forbidden("Tài khoản này nằm ngoài phạm vi bạn được uỷ quyền.")
        states = services.trang_thai_quyen_module(conn, target)
        co_cap = rbac.co_the_quan_ly(conn, user, request.state.perms, target,
                                    "permissions.grant")
        vai_tro = rbac.lay_vai_tro(conn, target["role_code"])
    finally:
        conn.close()
    return web.render(request, "accounts/permissions.html", page_title=f"Phân quyền · {user_id}",
                      user=user, target=target, states=states, co_cap=co_cap, vai_tro=vai_tro)


@router.post("/tai-khoan/{user_id}/phan-quyen", dependencies=[Depends(web.kiem_csrf)])
async def xu_ly_phan_quyen(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    form = await request.form()
    lua_chon = {k[len("quyen_"):]: v for k, v in form.items() if k.startswith("quyen_")}
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        try:
            thay_doi = services.dat_quyen_module(conn, user, request.state.perms, target,
                                                 lua_chon, request)
        except (Forbidden, ValidationError) as e:
            return web.chuyen_huong(f"/tai-khoan/{user_id}/phan-quyen", e.message, "err")
    finally:
        conn.close()
    if thay_doi:
        return web.chuyen_huong(f"/tai-khoan/{user_id}", f"Đã cập nhật {len(thay_doi)} module.")
    return web.chuyen_huong(f"/tai-khoan/{user_id}", "Không có thay đổi quyền module.")


@router.post("/tai-khoan/{user_id}/pham-vi", dependencies=[Depends(web.kiem_csrf)])
async def cap_nhat_pham_vi(request: Request, user_id: str):
    user = await web.yeu_cau_dang_nhap(request)
    if user["role_code"] != rbac.SUPER:
        raise Forbidden("Chỉ Super Admin được đặt phạm vi quản trị.")
    form = await request.form()
    conn = db.connect()
    try:
        target = _target(conn, user, user_id)
        if target["role_code"] != rbac.ADMIN:
            return web.chuyen_huong(f"/tai-khoan/{user_id}",
                                    "Chỉ tài khoản quản trị cấp dưới mới có phạm vi.", "err")
        mode = form.get("scope_mode", "tenant")
        conn.execute("DELETE FROM admin_scopes WHERE user_id=?", (user_id,))
        if mode == "tenant":
            conn.execute("INSERT INTO admin_scopes(tenant_id, user_id, department_id, created_at, "
                         "created_by) VALUES(?,?,NULL,?,?)",
                         (user["tenant_id"], user_id, db.now_iso(), user["id"]))
        else:
            for dept_id in form.getlist("scope_departments"):
                if conn.execute("SELECT 1 FROM departments WHERE id=? AND tenant_id=?",
                                (dept_id, user["tenant_id"])).fetchone():
                    conn.execute("INSERT OR IGNORE INTO admin_scopes(tenant_id, user_id, "
                                 "department_id, created_at, created_by) VALUES(?,?,?,?,?)",
                                 (user["tenant_id"], user_id, dept_id, db.now_iso(), user["id"]))
        conn.commit()
        audit.ghi(conn, user, "account.scope", target_type="user", target_id=user_id,
                  detail={"mode": mode, "soBan": len(form.getlist("scope_departments"))},
                  request=request)
    finally:
        conn.close()
    return web.chuyen_huong(f"/tai-khoan/{user_id}", "Đã cập nhật phạm vi quản trị.")
