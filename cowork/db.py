"""Kết nối SQLite, khởi tạo schema và dữ liệu nền."""
from __future__ import annotations

import sqlite3
import threading
from datetime import datetime
from zoneinfo import ZoneInfo

from . import config
from .schema import (BO_PHAN_MAC_DINH, DDL, MODULES, PERMISSIONS, ROLES,
                     ROLE_PERMISSIONS_MAC_DINH, SCHEMA_VERSION, SETTINGS_MAC_DINH)

TZ = ZoneInfo("Asia/Ho_Chi_Minh")
_init_lock = threading.Lock()
_initialized = False


def now_iso() -> str:
    return datetime.now(TZ).replace(microsecond=0).isoformat()


def today_iso() -> str:
    return datetime.now(TZ).date().isoformat()


def connect() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(str(config.DB_PATH), timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def q(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def one(conn: sqlite3.Connection, sql: str, params: tuple | list = ()) -> dict | None:
    row = conn.execute(sql, params).fetchone()
    return dict(row) if row else None


def scalar(conn: sqlite3.Connection, sql: str, params: tuple | list = ()):
    row = conn.execute(sql, params).fetchone()
    return row[0] if row else None


def init_db() -> None:
    """Tạo schema + seed idempotent. An toàn khi nhiều tiến trình cùng khởi động."""
    global _initialized
    if _initialized:
        return
    with _init_lock:
        if _initialized:
            return
        config.ensure_dirs()
        conn = connect()
        try:
            conn.executescript(DDL)
            _migrate(conn)
            conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES('schema_version', ?)",
                         (str(SCHEMA_VERSION),))
            _seed(conn)
            _initialized = True
        finally:
            conn.close()


def _cot(conn: sqlite3.Connection, table: str, col: str) -> bool:
    return any(r["name"] == col for r in conn.execute(f"PRAGMA table_info({table})").fetchall())


def _them_cot(conn: sqlite3.Connection, table: str, col: str, decl: str) -> None:
    if not _cot(conn, table, col):
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")


def _migrate(conn: sqlite3.Connection) -> None:
    """Nâng DB cũ lên schema hiện tại — CHỈ thêm cột/bảng, không xoá dữ liệu."""
    _them_cot(conn, "users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0")
    _them_cot(conn, "users", "mfa_secret", "TEXT")
    conn.commit()


def _seed(conn: sqlite3.Connection) -> None:
    now = now_iso()
    # Hai máy chủ anh Thành chốt 31/10/2026; thêm máy mới = thêm dòng vào
    # hatang_may_chu (INSERT OR IGNORE nên không ghi đè máy đã có/đã tắt).
    for code, name, ip in (
        ("vps-160-22-171-228", "VPS sản xuất VIP Order", "160.22.171.228"),
        ("vps-160-22-170-20", "VPS staging & COWORK", "160.22.170.20"),
    ):
        conn.execute(
            "INSERT OR IGNORE INTO hatang_may_chu(code, name, ip, enabled, created_at) "
            "VALUES(?,?,?,1,?)", (code, name, ip, now))
    conn.execute(
        "INSERT OR IGNORE INTO tenants(id, name, status, created_at) VALUES(?,?, 'active', ?)",
        (config.TENANT_MAC_DINH, "VIP GROUP", now),
    )
    # Vai trò hệ thống: cập nhật mô tả/cấp bậc, KHÔNG ghi đè is_locked của super_admin.
    for code, name, level, is_system, is_locked, desc in ROLES:
        conn.execute(
            "INSERT INTO roles(code, name, level, is_system, is_locked, description) "
            "VALUES(?,?,?,?,?,?) ON CONFLICT(code) DO UPDATE SET "
            "name=excluded.name, level=excluded.level, description=excluded.description",
            (code, name, level, is_system, is_locked, desc),
        )
    for code, name, desc, route, icon, group, sort, requires_brain, min_level in MODULES:
        conn.execute(
            "INSERT INTO modules(code, name, description, route, icon, group_code, sort_order, "
            "status, requires_brain, min_role_level) VALUES(?,?,?,?,?,?,?, 'active', ?, ?) "
            "ON CONFLICT(code) DO UPDATE SET name=excluded.name, description=excluded.description, "
            "route=excluded.route, icon=excluded.icon, group_code=excluded.group_code, "
            "sort_order=excluded.sort_order, requires_brain=excluded.requires_brain, "
            "min_role_level=excluded.min_role_level",
            (code, name, desc, route, icon, group, sort, requires_brain, min_level),
        )
    for module_code, action, name in PERMISSIONS:
        code = f"{module_code}.{action}"
        conn.execute(
            "INSERT INTO permissions(code, module_code, action, name) VALUES(?,?,?,?) "
            "ON CONFLICT(code) DO UPDATE SET name=excluded.name",
            (code, module_code, action, name),
        )
    # Super Admin luôn có đủ quyền (kể cả quyền mới thêm sau này).
    conn.execute(
        "INSERT OR IGNORE INTO role_permissions(role_code, permission_code) "
        "SELECT 'super_admin', code FROM permissions"
    )
    # Các vai trò khác chỉ seed lần đầu — không ghi đè ma trận chủ dự án đã sửa.
    for role_code, perms in ROLE_PERMISSIONS_MAC_DINH.items():
        da_co = scalar(conn, "SELECT COUNT(*) FROM role_permissions WHERE role_code=?", (role_code,))
        if da_co:
            continue
        for perm in perms:
            conn.execute(
                "INSERT OR IGNORE INTO role_permissions(role_code, permission_code) VALUES(?,?)",
                (role_code, perm),
            )
    if not scalar(conn, "SELECT COUNT(*) FROM departments WHERE tenant_id=?",
                  (config.TENANT_MAC_DINH,)):
        for code, name, desc in BO_PHAN_MAC_DINH:
            conn.execute(
                "INSERT INTO departments(id, tenant_id, code, name, parent_id, manager_user_id, "
                "description, status, created_at, updated_at) VALUES(?,?,?,?,NULL,NULL,?, 'active', ?, ?)",
                (code, config.TENANT_MAC_DINH, code, name, desc, now, now),
            )
    for key, value in SETTINGS_MAC_DINH.items():
        conn.execute(
            "INSERT OR IGNORE INTO settings(tenant_id, key, value, updated_at, updated_by) "
            "VALUES(?,?,?,?, 'system')",
            (config.TENANT_MAC_DINH, key, value, now),
        )
    conn.commit()


def get_setting(conn: sqlite3.Connection, key: str, default: str = "") -> str:
    row = conn.execute("SELECT value FROM settings WHERE tenant_id=? AND key=?",
                       (config.TENANT_MAC_DINH, key)).fetchone()
    return row["value"] if row else default


def set_setting(conn: sqlite3.Connection, key: str, value: str, updated_by: str) -> None:
    conn.execute(
        "INSERT INTO settings(tenant_id, key, value, updated_at, updated_by) VALUES(?,?,?,?,?) "
        "ON CONFLICT(tenant_id, key) DO UPDATE SET value=excluded.value, "
        "updated_at=excluded.updated_at, updated_by=excluded.updated_by",
        (config.TENANT_MAC_DINH, key, str(value), now_iso(), updated_by),
    )
    conn.commit()


def brain_config(conn: sqlite3.Connection) -> dict:
    """Cấu hình Brain hiệu lực: DB setting (nếu có) → env mặc định."""
    def _pick(key: str, env_value: str) -> str:
        value = get_setting(conn, key, "").strip()
        return value or env_value

    return {
        "enabled": _pick("brain.enabled", "1" if config.BRAIN_ENABLED else "0") == "1",
        "base_url": _pick("brain.base_url", config.BRAIN_BASE_URL).rstrip("/"),
        "public_url": _pick("brain.public_url", config.BRAIN_PUBLIC_URL).rstrip("/"),
        "allow_mfa_users": _pick("brain.allow_mfa_users", "0") == "1",
        "ticket_ttl": config.BRAIN_TICKET_TTL,
        "launch_path": config.BRAIN_LAUNCH_PATH,
        "revoke_path": config.BRAIN_REVOKE_PATH,
        "health_path": config.BRAIN_HEALTH_PATH,
    }
