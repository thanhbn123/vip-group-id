"""CLI quản trị COWORK — tạo Super Admin, tenant, tài khoản, backup.

    .venv/bin/python -m cowork.cli init
    .venv/bin/python -m cowork.cli create-owner --id anh-thanh --name "anh-thanh"
    .venv/bin/python -m cowork.cli create-tenant --id tenant-b --name "Tenant B"
    .venv/bin/python -m cowork.cli list-users
    .venv/bin/python -m cowork.cli backup
    .venv/bin/python -m cowork.cli khach-dong-bo          # cron: thử lại hàng đợi gửi CRM
    .venv/bin/python -m cowork.cli khach-outbox -n 5      # dev: xem email trong outbox

Mật khẩu KHÔNG nhận qua tham số dòng lệnh (tránh lộ trong `ps`/lịch sử shell):
đọc từ biến môi trường hoặc hỏi qua getpass.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

from . import config, db, security, services
from . import audit as audit_mod


def _mat_khau(env_name: str, nhan: str = "Mật khẩu") -> str:
    value = os.environ.get(env_name, "").strip()
    if value:
        return value
    if not sys.stdin.isatty():
        raise SystemExit(f"Thiếu biến môi trường {env_name} (không có TTY để hỏi mật khẩu).")
    mk1 = getpass.getpass(f"{nhan}: ")
    mk2 = getpass.getpass("Nhập lại: ")
    if mk1 != mk2:
        raise SystemExit("Hai lần nhập không khớp.")
    return mk1


def _tao_tenant(conn: sqlite3.Connection, tenant_id: str, name: str) -> bool:
    if conn.execute("SELECT 1 FROM tenants WHERE id=?", (tenant_id,)).fetchone():
        return False
    conn.execute("INSERT INTO tenants(id, name, status, created_at) VALUES(?,?, 'active', ?)",
                 (tenant_id, name, db.now_iso()))
    conn.commit()
    return True


def cmd_init(args) -> int:
    db.init_db()
    print(f"DB sẵn sàng: {config.DB_PATH}")
    return 0


def cmd_create_owner(args) -> int:
    db.init_db()
    pw = _mat_khau(args.password_env or "COWORK_OWNER_PASSWORD")
    conn = db.connect()
    try:
        kq = services.tao_super_admin(conn, args.id, pw, args.name or args.id, reset=args.reset,
                                      tenant_id=args.tenant)
        print(f"{'Đã đặt lại' if kq['reset'] else 'Đã tạo'} Super Admin: {kq['id']} "
              f"(tenant {args.tenant})")
    finally:
        conn.close()
    return 0


def cmd_create_tenant(args) -> int:
    db.init_db()
    conn = db.connect()
    try:
        moi = _tao_tenant(conn, args.id, args.name)
        print(("Đã tạo" if moi else "Đã có") + f" tenant: {args.id}")
        if args.admin_id:
            pw = _mat_khau(args.admin_password_env or "COWORK_TENANT_ADMIN_PASSWORD")
            kq = services.tao_super_admin(conn, args.admin_id, pw, args.admin_name or args.admin_id,
                                          reset=args.reset, tenant_id=args.id)
            print(f"Super Admin tenant {args.id}: {kq['id']}")
    finally:
        conn.close()
    return 0


def cmd_list_users(args) -> int:
    db.init_db()
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT u.id, u.tenant_id, u.display_name, u.role_code, u.status, "
            "d.name AS department FROM users u LEFT JOIN departments d ON d.id=u.department_id "
            "ORDER BY u.tenant_id, u.role_code, u.id").fetchall()
        if not rows:
            print("Chưa có tài khoản nào.")
            return 0
        print(f"{'ID':28} {'TENANT':14} {'VAI TRO':20} {'TRANG THAI':12} BAN")
        for r in rows:
            print(f"{r['id']:28} {r['tenant_id']:14} {r['role_code']:20} {r['status']:12} "
                  f"{r['department'] or '—'}")
    finally:
        conn.close()
    return 0


def cmd_create_user(args) -> int:
    db.init_db()
    pw = _mat_khau(args.password_env or "COWORK_USER_PASSWORD")
    conn = db.connect()
    try:
        actor_row = conn.execute(
            "SELECT * FROM users WHERE tenant_id=? AND role_code='super_admin' AND status='active' "
            "LIMIT 1", (args.tenant,)).fetchone()
        if not actor_row:
            raise SystemExit(f"Tenant {args.tenant} chưa có Super Admin đang hoạt động.")
        from . import auth, rbac
        actor = auth.nguoi_dung_day_du(conn, actor_row["id"])
        perms = rbac.quyen_hieu_luc(conn, actor)
        user, _ = services.tao_nguoi_dung(conn, actor, perms, {
            "id": args.id, "display_name": args.name or args.id, "email": args.email or "",
            "role_code": args.role, "department_id": args.department or "",
            "partner_org": args.partner_org or "", "password": pw, "must_change": "0",
        })
        print(f"Đã tạo {user['id']} · {user['role_code']} · tenant {user['tenant_id']}")
    finally:
        conn.close()
    return 0


def cmd_backup(args) -> int:
    db.init_db()
    backup_dir = config.DATA_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(db.TZ).strftime("%Y%m%d-%H%M%S")
    dest = backup_dir / f"cowork-{stamp}.db"
    src = db.connect()
    try:
        out = sqlite3.connect(str(dest))
        try:
            src.backup(out)
            out.execute("PRAGMA integrity_check")
        finally:
            out.close()
        nguoi = src.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        audit = src.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    finally:
        src.close()
    dest.chmod(0o600)
    print(f"Backup: {dest} · {nguoi} users · {audit} audit · integrity ok")
    return 0


def cmd_mfa_reset(args) -> int:
    """Khôi phục khẩn cấp: tắt MFA + xoá mã dự phòng/challenge của một user."""
    db.init_db()
    conn = db.connect()
    try:
        u = conn.execute("SELECT id, tenant_id, mfa_enabled FROM users WHERE id=?",
                         (args.id,)).fetchone()
        if not u:
            print(f"Không tìm thấy tài khoản: {args.id}")
            return 2
        conn.execute("UPDATE users SET mfa_enabled=0, mfa_secret=NULL, updated_at=? WHERE id=?",
                     (db.now_iso(), args.id))
        conn.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (args.id,))
        conn.execute("DELETE FROM mfa_challenges WHERE user_id=?", (args.id,))
        conn.commit()
        audit_mod.ghi(conn, "cli", "mfa.reset", target_type="user", target_id=args.id,
                      detail={"truocDo": bool(u["mfa_enabled"]), "nguon": "cli"},
                      tenant_id=u["tenant_id"])
        print(f"Đã reset MFA cho {args.id} (trước đó {'bật' if u['mfa_enabled'] else 'tắt'}).")
        return 0
    finally:
        conn.close()


def cmd_show_user(args) -> int:
    db.init_db()
    conn = db.connect()
    try:
        from . import auth
        u = auth.nguoi_dung_day_du(conn, args.id)
        if not u:
            print("Không tìm thấy.")
            return 1
        for k in ("id", "tenant_id", "display_name", "role_code", "status", "department_name",
                  "last_login_at", "must_change_password"):
            print(f"{k}: {u.get(k)}")
    finally:
        conn.close()
    return 0


def cmd_audit_tail(args) -> int:
    db.init_db()
    conn = db.connect()
    try:
        rows = conn.execute(
            "SELECT id, created_at, actor_id, action, target_id FROM audit_log "
            "ORDER BY id DESC LIMIT ?", (args.n,)).fetchall()
        for r in rows:
            print(f"{r['id']:5} {r['created_at']} {r['actor_id']:22} {r['action']:28} "
                  f"{r['target_id'] or ''}")
    finally:
        conn.close()
    return 0


def cmd_khach_dong_bo(args) -> int:
    """Thử lại các mục gửi CRM (signup, thu hồi) chưa thành công. Chạy được từ cron."""
    from . import khach
    db.init_db()
    conn = db.connect()
    try:
        kq = khach.dong_bo_crm(conn, tat_ca=args.tat_ca)
    finally:
        conn.close()
    print(f"Đã thử {kq['thu']} · thành công {kq['thanh_cong']} · còn chờ {kq['con_lai']}")
    return 0 if kq["thanh_cong"] == kq["thu"] else 1


def _chi_dev() -> None:
    if config.ENV == "production":
        raise SystemExit("Lệnh này chỉ dùng cho dev/staging.")


def cmd_khach_outbox(args) -> int:
    """DEV: in email trong customer_outbox (chứa link một lần — KHÔNG dùng ở production)."""
    _chi_dev()
    db.init_db()
    conn = db.connect()
    try:
        rows = db.q(conn, "SELECT * FROM customer_outbox ORDER BY id DESC LIMIT ?", (args.n,))
    finally:
        conn.close()
    for r in reversed(rows):
        print(f"--- #{r['id']} {r['created_at']} [{r['kind']}] → {r['to_email']}\n"
              f"Tiêu đề: {r['subject']}\n{r['body_text']}\n")
    return 0


def cmd_khach_duyet_dev(args) -> int:
    """DEV: mô phỏng CRM duyệt một đăng ký (đi qua đúng hàm xử lý ket-qua-duyet)."""
    from . import khach
    _chi_dev()
    db.init_db()
    conn = db.connect()
    try:
        acc = db.one(conn, "SELECT * FROM customer_accounts WHERE phone_e164=? OR subject=?",
                     (khach.chuan_hoa_sdt(args.ai) or "", args.ai))
        if not acc:
            raise SystemExit("Không có tài khoản khách này.")
        status, kq = khach.ket_qua_duyet(conn, {
            "subject": acc["subject"], "decision": "rejected" if args.tu_choi else "approved",
            "crm_customer_id": "dev-" + acc["id"], "portal_code": args.portal_code,
            "customer_code": args.portal_code, "phone_verified_by": "dev-cli"})
    finally:
        conn.close()
    print(status, kq)
    return 0 if status == 200 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cowork", description="CLI quản trị VIP GROUP COWORK")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="Khởi tạo schema + dữ liệu nền")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("create-owner", help="Tạo/đặt lại Super Admin")
    s.add_argument("--id", required=True)
    s.add_argument("--name", default="")
    s.add_argument("--tenant", default=config.TENANT_MAC_DINH)
    s.add_argument("--reset", action="store_true")
    s.add_argument("--password-env", default="COWORK_OWNER_PASSWORD")
    s.set_defaults(func=cmd_create_owner)

    s = sub.add_parser("create-tenant", help="Tạo tenant mới (và Super Admin nếu có)")
    s.add_argument("--id", required=True)
    s.add_argument("--name", required=True)
    s.add_argument("--admin-id", default="")
    s.add_argument("--admin-name", default="")
    s.add_argument("--reset", action="store_true")
    s.add_argument("--admin-password-env", default="COWORK_TENANT_ADMIN_PASSWORD")
    s.set_defaults(func=cmd_create_tenant)

    s = sub.add_parser("create-user", help="Tạo tài khoản thường (dùng cho kiểm thử/seed)")
    s.add_argument("--id", required=True)
    s.add_argument("--name", default="")
    s.add_argument("--email", default="")
    s.add_argument("--role", required=True)
    s.add_argument("--department", default="")
    s.add_argument("--partner-org", default="")
    s.add_argument("--tenant", default=config.TENANT_MAC_DINH)
    s.add_argument("--password-env", default="COWORK_USER_PASSWORD")
    s.set_defaults(func=cmd_create_user)

    s = sub.add_parser("list-users", help="Liệt kê tài khoản")
    s.set_defaults(func=cmd_list_users)

    s = sub.add_parser("show-user", help="Chi tiết một tài khoản")
    s.add_argument("id")
    s.set_defaults(func=cmd_show_user)

    s = sub.add_parser("mfa-reset", help="Khôi phục khẩn cấp: tắt MFA của một tài khoản")
    s.add_argument("--id", required=True)
    s.set_defaults(func=cmd_mfa_reset)

    s = sub.add_parser("backup", help="Sao lưu DB bằng SQLite backup API")
    s.set_defaults(func=cmd_backup)

    s = sub.add_parser("audit-tail", help="Xem N dòng audit mới nhất")
    s.add_argument("-n", type=int, default=20)
    s.set_defaults(func=cmd_audit_tail)

    s = sub.add_parser("khach-dong-bo", help="Realm khách: thử lại hàng đợi gửi CRM")
    s.add_argument("--tat-ca", action="store_true", help="Bỏ qua lịch chờ, thử mọi mục")
    s.set_defaults(func=cmd_khach_dong_bo)

    s = sub.add_parser("khach-outbox", help="DEV: xem email realm khách trong outbox")
    s.add_argument("-n", type=int, default=5)
    s.set_defaults(func=cmd_khach_outbox)

    s = sub.add_parser("khach-duyet-dev", help="DEV: mô phỏng CRM duyệt/từ chối đăng ký")
    s.add_argument("ai", help="SĐT hoặc subject cust:…")
    s.add_argument("--portal-code", default="VG000001")
    s.add_argument("--tu-choi", action="store_true")
    s.set_defaults(func=cmd_khach_duyet_dev)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
