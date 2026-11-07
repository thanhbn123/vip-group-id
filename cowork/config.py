"""Cấu hình COWORK — local-first, đọc biến môi trường và .env, không phụ thuộc dịch vụ ngoài."""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _doc_env(path: Path) -> None:
    """Đọc .env đơn giản (KEY=VALUE), KHÔNG ghi đè biến đã có trong môi trường."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


_doc_env(BASE_DIR / ".env")


def _path(name: str, default: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    return Path(raw).expanduser().resolve() if raw else default


DATA_DIR = _path("COWORK_DATA_DIR", BASE_DIR / "data")
DB_PATH = _path("COWORK_DB_PATH", DATA_DIR / "cowork.db")
SECRET_FILE = DATA_DIR / "secret.key"
BRAIN_SECRET_FILE = DATA_DIR / "brain_secret.key"
HATANG_SECRET_FILE = DATA_DIR / "hatang_secret.key"

APP_NAME = "VIP GROUP COWORK"
APP_VERSION = "1.0.0"
TENANT_MAC_DINH = os.environ.get("COWORK_TENANT", "vip-group").strip() or "vip-group"

HOST = os.environ.get("COWORK_HOST", "127.0.0.1").strip()
PORT = int(os.environ.get("COWORK_PORT", "8899"))
PUBLIC_URL = os.environ.get("COWORK_PUBLIC_URL", f"http://127.0.0.1:{PORT}").rstrip("/")
INTERNAL_URL = os.environ.get("COWORK_INTERNAL_URL", "http://127.0.0.1:8899").rstrip("/")

COOKIE_NAME = "cowork_session"
CSRF_COOKIE = "cowork_csrf"
FLASH_COOKIE = "cowork_flash"
COOKIE_SECURE = os.environ.get("COWORK_COOKIE_SECURE", "0").strip() == "1"
SESSION_HOURS = int(os.environ.get("COWORK_SESSION_HOURS", "12"))
IDLE_MINUTES = int(os.environ.get("COWORK_IDLE_MINUTES", "60"))
PASSWORD_MIN = int(os.environ.get("COWORK_PASSWORD_MIN", "10"))
LOGIN_MAX_FAIL = int(os.environ.get("COWORK_LOGIN_MAX_FAIL", "5"))
LOGIN_WINDOW_MIN = int(os.environ.get("COWORK_LOGIN_WINDOW_MIN", "10"))

# ---- VIP AI BRAIN (chỉ là URL; không đọc/ghi DB Brain) ----
BRAIN_ENABLED = os.environ.get("COWORK_BRAIN_ENABLED", "1").strip() == "1"
BRAIN_BASE_URL = os.environ.get("COWORK_BRAIN_BASE_URL", "http://127.0.0.1:18892").rstrip("/")
BRAIN_PUBLIC_URL = os.environ.get("COWORK_BRAIN_PUBLIC_URL", "http://127.0.0.1:18892").rstrip("/")
BRAIN_HEALTH_PATH = "/api/health"
BRAIN_TIMEOUT = float(os.environ.get("COWORK_BRAIN_TIMEOUT", "3"))
BRAIN_TICKET_TTL = int(os.environ.get("COWORK_BRAIN_TICKET_TTL", "60"))
BRAIN_LAUNCH_PATH = "/cowork/vao"
BRAIN_REVOKE_PATH = "/api/cowork/thu-hoi"
BRAIN_HEALTH_INTERNAL_PATH = "/api/cowork/suc-khoe"

ENV = os.environ.get("COWORK_ENV", "local").strip().lower() or "local"

#: Tin header proxy (X-Real-IP/X-Forwarded-For) — CHỈ bật khi chạy sau Caddy đã GHI ĐÈ.
TIN_PROXY = os.environ.get("COWORK_TIN_PROXY", "0").strip() == "1"


def _secret(path: Path, env_name: str, size: int = 48) -> str:
    """Bí mật ổn định: env → tệp 0600 → sinh mới. Tệp nằm trong data/ (gitignore)."""
    value = os.environ.get(env_name, "").strip()
    if value:
        return value
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(size)
    # Tạo NGUYÊN TỬ với quyền 0600 (không có khoảnh khắc tệp đọc được bởi người khác).
    try:
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Tiến trình khác vừa tạo: dùng giá trị của nó.
        existing = path.read_text(encoding="utf-8").strip()
        if existing:
            return existing
        fd = os.open(str(path), os.O_WRONLY | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(value + "\n")
    return value


SECRET_KEY = _secret(SECRET_FILE, "COWORK_SECRET_KEY")
BRAIN_SHARED_SECRET = _secret(BRAIN_SECRET_FILE, "COWORK_BRAIN_SHARED_SECRET")

# Hạ tầng: bí mật HMAC riêng cho các agent máy chủ (KHÔNG dùng chung với Brain —
# lộ một bên thì bên kia còn), và ngưỡng coi một máy là MẤT TÍN HIỆU.
# Agent đo 10 phút/lượt (anh Thành chốt 31/10); trễ = 2,5 chu kỳ.
HATANG_SHARED_SECRET = _secret(HATANG_SECRET_FILE, "COWORK_HATANG_SHARED_SECRET")
HATANG_TRE_PHUT = int(os.environ.get("COWORK_HATANG_TRE_PHUT", "25"))


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


# ---- REALM KHÁCH (cổng khách hàng P1 — docs KIEN_TRUC_P1 mục 3, 4) ----
# Mặc định TẮT: khi tắt, không route nào của realm khách tồn tại (404).
KHACH_ENABLED = os.environ.get("COWORK_KHACH_ENABLED", "0").strip() == "1"
#: Host (có thể kèm cổng) phục vụ realm khách. Request tới host này CHỈ thấy /tai-khoan/*
#: của khách và /api/internal/khach/*; mọi route nhân viên trả 404. Host khác thì ngược lại.
#: Tên host khách và host nhân viên PHẢI khác nhau (không chỉ khác cổng): cookie không tách
#: theo cổng. Mặc định dev: khach.localhost:8898.
KHACH_HOSTS = [h.strip().lower() for h in os.environ.get(
    "COWORK_KHACH_HOSTS", "khach.localhost:8898").split(",") if h.strip()]
#: Danh sách TRẮNG host nhân viên. Khi realm khách bật, Host không thuộc hai danh sách ⇒ 421
#: (không bao giờ rơi về realm nhân viên). Bỏ trống ⇒ lấy host của PUBLIC_URL, INTERNAL_URL.
#: Realm khách tắt và biến này không đặt ⇒ không kiểm Host (giữ hành vi cũ).
STAFF_HOSTS_RAW = os.environ.get("COWORK_STAFF_HOSTS", "").strip()
STAFF_HOSTS = [h.strip().lower() for h in STAFF_HOSTS_RAW.split(",") if h.strip()]
#: URL công khai của realm khách — dùng để dựng link trong email.
KHACH_PUBLIC_URL = os.environ.get("COWORK_KHACH_PUBLIC_URL",
                                  "http://khach.localhost:8898").rstrip("/")
CRM_PORTAL_INTERNAL_URL = os.environ.get("CRM_PORTAL_INTERNAL_URL",
                                         "http://127.0.0.1:8897").rstrip("/")
CRM_PORTAL_PUBLIC_URL = os.environ.get("CRM_PORTAL_PUBLIC_URL",
                                       "http://127.0.0.1:8897").rstrip("/")
CRM_PORTAL_TIMEOUT = float(os.environ.get("CRM_PORTAL_TIMEOUT", "3"))
#: Bí mật HMAC/launch token VIP ID ⇄ CRM portal. Nạp LƯỜI (chỉ khi realm bật) qua
#: `khach.portal_secret()`: env VIPID_PORTAL_SECRET → tệp 0600 → sinh mới (chỉ dev).
PORTAL_SECRET_FILE = _path("VIPID_PORTAL_SECRET_FILE", DATA_DIR / "portal_secret.key")
#: Kênh gửi email. CHỈ có 'outbox' (ghi bảng customer_outbox, không gửi thật).
#: Production + realm bật + chưa có kênh thật ⇒ ứng dụng TỪ CHỐI khởi động (chặn A8).
KHACH_MAIL_TRANSPORT = os.environ.get("COWORK_KHACH_MAIL_TRANSPORT", "outbox").strip() or "outbox"
KHACH_PASSWORD_MIN = 12
KHACH_TOKEN_TTL_MIN = int(os.environ.get("COWORK_KHACH_TOKEN_TTL_MIN", "30"))
KHACH_LAUNCH_TTL = min(60, int(os.environ.get("COWORK_KHACH_LAUNCH_TTL", "60")))
KHACH_SESSION_HOURS = int(os.environ.get("COWORK_KHACH_SESSION_HOURS", "12"))
KHACH_IDLE_MINUTES = int(os.environ.get("COWORK_KHACH_IDLE_MINUTES", "120"))
KHACH_LOGIN_MAX_FAIL = int(os.environ.get("COWORK_KHACH_LOGIN_MAX_FAIL", "5"))
KHACH_LOGIN_IP_MAX_FAIL = int(os.environ.get("COWORK_KHACH_LOGIN_IP_MAX_FAIL", "20"))
KHACH_LOGIN_WINDOW_MIN = int(os.environ.get("COWORK_KHACH_LOGIN_WINDOW_MIN", "15"))
KHACH_LOCK_MIN = int(os.environ.get("COWORK_KHACH_LOCK_MIN", "15"))
KHACH_SIGNUP_IP_PER_HOUR = int(os.environ.get("COWORK_KHACH_SIGNUP_IP_PER_HOUR", "5"))
KHACH_FORGOT_IP_PER_HOUR = int(os.environ.get("COWORK_KHACH_FORGOT_IP_PER_HOUR", "10"))
#: scrypt riêng cho realm khách (mạnh hơn nhân viên). Tham số lưu trong password_algo nên
#: hash cũ vẫn xác minh được. Giới hạn số lượt băm đồng thời để chặn DoS bộ nhớ (128 MiB/lượt).
KHACH_SCRYPT_LOG2_N = int(os.environ.get("COWORK_KHACH_SCRYPT_LOG2_N", "17"))
KHACH_SCRYPT_DONG_THOI = int(os.environ.get("COWORK_KHACH_SCRYPT_DONG_THOI", "2"))
#: Cookie thiết bị tin cậy (đặt sau lần đăng nhập đúng), số ngày hiệu lực.
KHACH_THIET_BI_NGAY = int(os.environ.get("COWORK_KHACH_THIET_BI_NGAY", "180"))
KHACH_RESET_ACC_IP_PER_HOUR = int(os.environ.get("COWORK_KHACH_RESET_ACC_IP_PER_HOUR", "3"))
KHACH_TOKEN_TOI_DA = 3
#: Cloudflare Turnstile cho thử thách đăng nhập khi tài khoản bị dò từ nhiều nơi.
#: Site key công khai (env); secret: env COWORK_KHACH_TURNSTILE_SECRET hoặc tệp 0600
#: (COWORK_KHACH_TURNSTILE_SECRET_FILE) — KHÔNG tự sinh. Thiếu một trong hai ⇒ tắt thử thách.
KHACH_TURNSTILE_SITE_KEY = os.environ.get("COWORK_KHACH_TURNSTILE_SITE_KEY", "").strip()
KHACH_TURNSTILE_SECRET_FILE = _path("COWORK_KHACH_TURNSTILE_SECRET_FILE",
                                    DATA_DIR / "turnstile_secret.key")
KHACH_TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
KHACH_TURNSTILE_TIMEOUT = 5.0
#: Owner 07/11: KHÔNG xác minh email/SĐT khi đăng ký; email chỉ là thông tin liên hệ tuỳ chọn.
#: Email tự phục vụ (khôi phục mật khẩu, thông báo) chỉ chạy khi bật cờ này VÀ có kênh gửi thật.
KHACH_EMAIL_ENABLED = os.environ.get("COWORK_KHACH_EMAIL_ENABLED", "0").strip() == "1"
#: Hotline/Zalo hiển thị trên trang quên mật khẩu (khôi phục do nhân viên hỗ trợ).
KHACH_HOTLINE = os.environ.get("COWORK_KHACH_HOTLINE", "0961 102 655").strip() or "0961 102 655"
#: Trần đăng ký toàn hệ thống mỗi giờ (chống đăng ký ồ ạt / giữ chỗ SĐT hàng loạt).
KHACH_SIGNUP_GLOBAL_PER_HOUR = int(os.environ.get("COWORK_KHACH_SIGNUP_GLOBAL_PER_HOUR", "200"))
#: Chu kỳ (giây) của vòng nền gửi hàng đợi sang CRM. Request KHÔNG BAO GIỜ gọi CRM trực tiếp.
KHACH_SYNC_GIAY = float(os.environ.get("COWORK_KHACH_SYNC_GIAY", "5"))
#: PILOT có kiểm soát (owner duyệt): chỉ SĐT trong danh sách trắng mới đăng ký/đăng nhập/khôi phục.
#: Production BẮT BUỘC đặt tường minh COWORK_KHACH_PILOT=0 hoặc 1 (thiếu ⇒ từ chối khởi động).
KHACH_PILOT_RAW = os.environ.get("COWORK_KHACH_PILOT", "").strip()
KHACH_PILOT = KHACH_PILOT_RAW == "1"
KHACH_PILOT_PHONES = [p.strip() for p in os.environ.get("COWORK_KHACH_PILOT_PHONES", "").split(",")
                      if p.strip()]
KHACH_PILOT_FILE = _path("COWORK_KHACH_PILOT_FILE", DATA_DIR / "khach_pilot.txt")
#: Công tắc khẩn: tệp này TỒN TẠI ⇒ mọi request host khách trả 503 bảo trì (không cần khởi động
#: lại). `touch` để đóng cổng, `rm` để mở lại. Realm nhân viên không bị ảnh hưởng.
KHACH_MAINTENANCE_FILE = _path("COWORK_KHACH_MAINTENANCE_FILE", DATA_DIR / "khach_bao_tri.flag")

# ---- §15: hai tên miền realm khách ----
#: Host chỉ đăng ký (dangky.vipgroup.com.vn) và host đăng nhập/tài khoản (dangnhap.vipgroup.com.vn).
#: Để trống cả hai ⇒ chế độ một host cũ (COWORK_KHACH_HOSTS phục vụ mọi route khách).
KHACH_HOST_DANGKY = os.environ.get("COWORK_KHACH_HOST_DANGKY", "").strip().lower()
KHACH_HOST_DANGNHAP = os.environ.get("COWORK_KHACH_HOST_DANGNHAP", "").strip().lower()
#: URL tuyệt đối dùng cho liên kết chéo giữa hai host (mặc định suy từ host).
KHACH_DANGKY_URL = os.environ.get("COWORK_KHACH_DANGKY_URL", "").strip().rstrip("/")
KHACH_DANGNHAP_URL = os.environ.get("COWORK_KHACH_DANGNHAP_URL", "").strip().rstrip("/")
#: Danh sách tiền tố URL được phép cho `tiep` sau đăng nhập (vd https://khachhang.vipgroup.com.vn/portal).
#: Trống ⇒ mặc định CRM_PORTAL_PUBLIC_URL + "/portal".
KHACH_TIEP_CHO_PHEP = [u.strip() for u in os.environ.get("COWORK_KHACH_TIEP_CHO_PHEP", "").split(",")
                       if u.strip()]
