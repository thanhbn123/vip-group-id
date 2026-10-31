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

ENV = os.environ.get("COWORK_ENV", "local").strip() or "local"

#: Tin header proxy (X-Real-IP/X-Forwarded-For) — CHỈ bật khi chạy sau Caddy đã GHI ĐÈ.
TIN_PROXY = os.environ.get("COWORK_TIN_PROXY", "0").strip() == "1"


def _secret(path: Path, env_name: str, size: int = 48) -> str:
    """Bí mật ổn định: env → tệp 0600 → sinh mới. Tệp nằm trong data/ (gitignore)."""
    value = os.environ.get(env_name, "").strip()
    if value:
        return value
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_file():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(size)
    path.write_text(value + "\n", encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
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
