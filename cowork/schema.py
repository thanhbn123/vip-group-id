"""Schema + dữ liệu nền COWORK. Idempotent: chạy nhiều lần không nhân đôi dữ liệu."""
from __future__ import annotations

SCHEMA_VERSION = 3

DDL = """
CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tenants(
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS roles(
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    level INTEGER NOT NULL,
    is_system INTEGER NOT NULL DEFAULT 1,
    is_locked INTEGER NOT NULL DEFAULT 0,
    description TEXT
);

CREATE TABLE IF NOT EXISTS modules(
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    route TEXT,
    icon TEXT NOT NULL DEFAULT 'grid',
    group_code TEXT NOT NULL DEFAULT 'workspace',
    sort_order INTEGER NOT NULL DEFAULT 100,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
    requires_brain INTEGER NOT NULL DEFAULT 0,
    min_role_level INTEGER NOT NULL DEFAULT 20
);

CREATE TABLE IF NOT EXISTS permissions(
    code TEXT PRIMARY KEY,
    module_code TEXT NOT NULL REFERENCES modules(code) ON DELETE CASCADE,
    action TEXT NOT NULL,
    name TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions(
    role_code TEXT NOT NULL REFERENCES roles(code) ON DELETE CASCADE,
    permission_code TEXT NOT NULL REFERENCES permissions(code) ON DELETE CASCADE,
    PRIMARY KEY(role_code, permission_code)
);

CREATE TABLE IF NOT EXISTS departments(
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code TEXT NOT NULL,
    name TEXT NOT NULL,
    parent_id TEXT REFERENCES departments(id) ON DELETE SET NULL,
    manager_user_id TEXT,
    description TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','archived')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(tenant_id, code)
);
CREATE INDEX IF NOT EXISTS idx_departments_tenant ON departments(tenant_id, status);

CREATE TABLE IF NOT EXISTS users(
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    role_code TEXT NOT NULL REFERENCES roles(code),
    department_id TEXT REFERENCES departments(id) ON DELETE SET NULL,
    partner_org TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active','suspended','archived','pending')),
    password_hash TEXT,
    password_salt TEXT,
    password_algo TEXT NOT NULL DEFAULT 'scrypt',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    mfa_secret TEXT,
    last_login_at TEXT,
    created_by TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id, status);
CREATE INDEX IF NOT EXISTS idx_users_dept ON users(tenant_id, department_id);

CREATE TABLE IF NOT EXISTS user_permissions(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_code TEXT NOT NULL REFERENCES permissions(code) ON DELETE CASCADE,
    effect TEXT NOT NULL CHECK(effect IN ('allow','deny')),
    granted_by TEXT,
    granted_at TEXT NOT NULL,
    UNIQUE(user_id, permission_code)
);
CREATE INDEX IF NOT EXISTS idx_user_permissions_user ON user_permissions(user_id);

CREATE TABLE IF NOT EXISTS admin_scopes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    department_id TEXT REFERENCES departments(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    created_by TEXT,
    UNIQUE(user_id, department_id)
);
CREATE INDEX IF NOT EXISTS idx_admin_scopes_user ON admin_scopes(user_id);

CREATE TABLE IF NOT EXISTS sessions(
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    csrf_token TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    ip TEXT,
    user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked','expired')),
    revoked_at TEXT,
    revoked_by TEXT,
    revoke_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, status);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token_hash);

CREATE TABLE IF NOT EXISTS mfa_challenges(
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tenant_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    used_at TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mfa_challenges_hash ON mfa_challenges(token_hash);

CREATE TABLE IF NOT EXISTS mfa_backup_codes(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(user_id, code_hash)
);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_user ON mfa_backup_codes(user_id);

CREATE TABLE IF NOT EXISTS login_attempts(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    ip TEXT,
    success INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(user_id, ip, created_at);

CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    detail TEXT,
    ip TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant_time ON audit_log(tenant_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_log(tenant_id, actor_id);

CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log_append_only');
END;

CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log_append_only');
END;

CREATE TABLE IF NOT EXISTS brain_tickets(
    id TEXT PRIMARY KEY,
    ticket_hash TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    session_id TEXT,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL,
    ip TEXT
);
CREATE INDEX IF NOT EXISTS idx_brain_tickets_hash ON brain_tickets(ticket_hash);

CREATE TABLE IF NOT EXISTS settings(
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT,
    PRIMARY KEY(tenant_id, key)
);

-- Hạ tầng: sổ máy chủ được phép báo cáo (danh sách TRẮNG — agent lạ bị từ chối)
-- và ảnh chụp cuối của mỗi máy. V1 chỉ giữ ảnh chụp cuối, không giữ lịch sử.
CREATE TABLE IF NOT EXISTS hatang_may_chu(
    code TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ip TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hatang_bao_cao(
    may_chu TEXT PRIMARY KEY REFERENCES hatang_may_chu(code) ON DELETE CASCADE,
    do_luc TEXT,
    nhan_luc TEXT NOT NULL,
    du_lieu TEXT NOT NULL
);
"""

#: Module registry mặc định. `route` là đường dẫn COWORK; module cần Brain sẽ mở qua ticket.
MODULES = [
    # code, name, description, route, icon, group, sort, requires_brain, min_level
    ("dashboard", "Bảng điều khiển", "Tổng quan hoạt động và lối tắt", "/", "home", "workspace", 10, 0, 20),
    ("brain", "VIP AI Brain", "Trợ lý AI Local trên Mac Studio", "/brain", "spark", "workspace", 20, 1, 20),
    ("tasks", "Công việc", "Nhiệm vụ, tiến độ và báo cáo", "/module/tasks", "check", "workspace", 30, 1, 40),
    ("knowledge", "Tri thức", "Kho tài liệu và tri thức doanh nghiệp", "/module/knowledge", "book", "workspace", 40, 1, 40),
    ("tools", "Công cụ", "Công cụ và quy trình được cấp", "/module/tools", "wrench", "workspace", 50, 1, 60),
    ("usage", "Sử dụng & chi phí", "Mức dùng AI và ngân sách", "/module/usage", "chart", "workspace", 60, 1, 40),
    ("approvals", "Phê duyệt", "Yêu cầu chờ người quyết định", "/module/approvals", "inbox", "workspace", 70, 1, 60),
    ("partner", "Cổng đối tác", "Không gian của đối tác theo hợp đồng", "/doi-tac", "handshake", "workspace", 80, 0, 20),
    ("accounts", "Tài khoản", "Tạo, khoá, đặt lại mật khẩu, thu hồi phiên", "/tai-khoan", "users", "admin", 110, 0, 80),
    ("departments", "Ban / Bộ phận", "Cơ cấu tổ chức và trưởng ban", "/ban", "building", "admin", 120, 0, 60),
    ("roles", "Vai trò", "Ma trận quyền theo vai trò", "/vai-tro", "shield", "admin", 130, 0, 80),
    ("permissions", "Phân quyền module", "Quyền riêng của từng nhân sự", "/phan-quyen", "key", "admin", 140, 0, 80),
    ("modules", "Module", "Bật/tắt và cấu hình module", "/module-registry", "grid", "admin", 150, 0, 80),
    ("hatang", "Hạ tầng", "Cấu hình và trạng thái các máy chủ", "/ha-tang", "server", "admin", 155, 0, 100),
    ("audit", "Nhật ký", "Sổ kiểm toán quản trị", "/nhat-ky", "list", "admin", 160, 0, 80),
    ("settings", "Cài đặt", "Tenant, phiên, kết nối VIP AI Brain", "/cai-dat", "gear", "admin", 170, 0, 80),
]

#: Quyền theo module: (module, action, tên). `view` bắt buộc cho mọi module.
PERMISSIONS = [
    ("dashboard", "view", "Xem bảng điều khiển"),
    ("brain", "view", "Thấy module VIP AI Brain"),
    ("brain", "use", "Mở và sử dụng VIP AI Brain"),
    ("tasks", "view", "Xem công việc"),
    ("tasks", "use", "Cập nhật công việc"),
    ("knowledge", "view", "Xem kho tri thức"),
    ("knowledge", "use", "Thêm/sửa tài liệu"),
    ("tools", "view", "Xem công cụ"),
    ("tools", "use", "Chạy công cụ"),
    ("usage", "view", "Xem mức sử dụng và chi phí"),
    ("approvals", "view", "Xem yêu cầu phê duyệt"),
    ("approvals", "use", "Quyết định phê duyệt"),
    ("partner", "view", "Xem cổng đối tác"),
    ("partner", "use", "Sử dụng chức năng đối tác"),
    ("accounts", "view", "Xem tài khoản"),
    ("accounts", "create", "Tạo tài khoản"),
    ("accounts", "update", "Sửa tài khoản"),
    ("accounts", "suspend", "Khoá/mở khoá tài khoản"),
    ("accounts", "reset_password", "Đặt lại mật khẩu"),
    ("accounts", "revoke_sessions", "Thu hồi phiên"),
    ("accounts", "archive", "Lưu trữ tài khoản"),
    ("departments", "view", "Xem ban/bộ phận"),
    ("departments", "create", "Tạo ban/bộ phận"),
    ("departments", "update", "Sửa ban/bộ phận"),
    ("departments", "delete", "Lưu trữ ban/bộ phận"),
    ("roles", "view", "Xem vai trò"),
    ("roles", "manage", "Sửa quyền vai trò"),
    ("permissions", "view", "Xem phân quyền module"),
    ("permissions", "grant", "Cấp/thu hồi quyền module"),
    ("modules", "view", "Xem module registry"),
    ("modules", "manage", "Bật/tắt và cấu hình module"),
    ("hatang", "view", "Xem hạ tầng máy chủ"),
    ("audit", "view", "Xem nhật ký quản trị"),
    ("settings", "view", "Xem cài đặt"),
    ("settings", "manage", "Sửa cài đặt"),
]

ROLE_PERMISSIONS_MAC_DINH = {
    "admin": [
        "dashboard.view", "brain.view", "brain.use",
        "tasks.view", "tasks.use", "knowledge.view", "knowledge.use",
        "tools.view", "tools.use", "usage.view", "approvals.view", "approvals.use",
        "accounts.view", "accounts.create", "accounts.update", "accounts.suspend",
        "accounts.reset_password", "accounts.revoke_sessions",
        "departments.view", "departments.create", "departments.update",
        "roles.view", "permissions.view", "modules.view", "audit.view",
    ],
    "department_manager": [
        "dashboard.view", "brain.view", "brain.use",
        "tasks.view", "tasks.use", "knowledge.view", "knowledge.use",
        "tools.view", "tools.use", "usage.view", "approvals.view", "approvals.use",
        "accounts.view", "accounts.create", "departments.view", "permissions.view",
    ],
    "employee": [
        "dashboard.view", "brain.view", "brain.use",
        "tasks.view", "tasks.use", "knowledge.view", "usage.view",
    ],
    "partner": [
        "dashboard.view", "partner.view", "partner.use",
    ],
}

ROLES = [
    ("super_admin", "Super Admin", 100, 1, 1, "Toàn quyền hệ thống; không ai được sửa hoặc xoá."),
    ("admin", "Quản trị cấp dưới", 80, 1, 0, "Quản trị trong phạm vi được uỷ quyền; không thể tự nâng quyền."),
    ("department_manager", "Trưởng ban", 60, 1, 0, "Quản lý nhân sự và công việc trong ban của mình."),
    ("employee", "Nhân viên", 40, 1, 0, "Chỉ dùng các module được cấp."),
    ("partner", "Đối tác", 20, 1, 0, "Chỉ truy cập cổng đối tác theo hợp đồng."),
]

BO_PHAN_MAC_DINH = [
    ("ban-dieu-hanh", "Ban Điều hành", "Điều hành chung và ra quyết định"),
    ("kinh-doanh", "Ban Kinh doanh", "Kinh doanh, khách hàng và đối tác"),
    ("ky-thuat", "Ban Kỹ thuật", "Kỹ thuật, hệ thống và AI"),
    ("ke-toan", "Ban Kế toán", "Tài chính, kế toán và chứng từ"),
]

SETTINGS_MAC_DINH = {
    "tenant.display_name": "VIP GROUP",
    "security.session_hours": "12",
    "security.idle_minutes": "60",
    "security.password_min": "10",
    "brain.enabled": "1",
    "brain.base_url": "",
    "brain.public_url": "",
    "brain.allow_mfa_users": "0",
    "branding.support_note": "Hệ thống nội bộ VIP GROUP — mọi truy cập được ghi nhật ký.",
}
