"""Băm mật khẩu, token, chữ ký HMAC và kiểm tra đầu vào."""
from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import string
import struct
import time
import unicodedata
from urllib.parse import quote, urlsplit

from . import config

# scrypt: n=2^14, r=8, p=1 — đủ cho ứng dụng nội bộ, nhanh trên Apple Silicon.
_SCRYPT_N = 2 ** 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_DKLEN = 32
_SALT_GIA = b"cowork-gia-000001"  # 16 byte, cố định cho lượt băm giả (cân bằng thời gian)

ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,39}$")
ID_CAM = {"admin", "root", "system", "cowork", "brain", "superadmin", "super-admin", "api"}
#: Tên đường dẫn của realm khách dưới /tai-khoan/* — KHÔNG được làm ID nhân viên, và route
#: nhân viên /tai-khoan/{user_id} trả 404 cho các tên này (tránh nhập nhằng với cổng khách).
TEN_DANH_RIENG_KHACH = {
    "dang-ky", "dang-nhap", "dang-xuat", "quen-mat-khau", "dat-lai", "xac-minh-email",
    "vao-cong", "static", "da-gui-email", "gui-lai-xac-minh", "cho-duyet",
}
MAT_KHAU_CAM = {
    "1234567890", "123456789", "password", "matkhau123", "vipgroup123",
    "admin12345", "cowork123", "qwerty12345", "1111111111",
}


def bam_mat_khau(mat_khau: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(mat_khau.encode("utf-8"), salt=salt, n=_SCRYPT_N,
                            r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DKLEN)
    return base64.b64encode(digest).decode("ascii"), base64.b64encode(salt).decode("ascii")


def kiem_mat_khau(mat_khau: str, hash_b64: str | None, salt_b64: str | None) -> bool:
    if not hash_b64 or not salt_b64:
        # Vẫn tốn một lượt scrypt để không lộ user tồn tại qua thời gian trả lời.
        bam_mat_khau(mat_khau, _SALT_GIA)
        return False
    try:
        salt = base64.b64decode(salt_b64)
        digest = hashlib.scrypt(mat_khau.encode("utf-8"), salt=salt, n=_SCRYPT_N,
                                r=_SCRYPT_R, p=_SCRYPT_P, dklen=_DKLEN)
        return hmac.compare_digest(base64.b64encode(digest).decode("ascii"), hash_b64)
    except (ValueError, TypeError):
        return False


def bam_gia(mat_khau: str) -> None:
    bam_mat_khau(mat_khau, _SALT_GIA)


def token_moi(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def gen_mat_khau(length: int = 14) -> str:
    """Mật khẩu tạm mạnh, bỏ ký tự dễ nhầm (0/O, 1/l/I)."""
    chu = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%&*"
    while True:
        pw = "".join(secrets.choice(chu) for _ in range(length))
        if kiem_tra_do_manh(pw) is None:
            return pw


def kiem_tra_do_manh(mat_khau: str, user_id: str = "", min_len: int | None = None) -> str | None:
    minimum = min_len or config.PASSWORD_MIN
    if len(mat_khau or "") < minimum:
        return f"Mật khẩu phải có ít nhất {minimum} ký tự."
    if mat_khau.lower() in MAT_KHAU_CAM or mat_khau == user_id:
        return "Mật khẩu quá phổ biến hoặc trùng với ID đăng nhập."
    nhom = sum([
        bool(re.search(r"[a-z]", mat_khau)),
        bool(re.search(r"[A-Z]", mat_khau)),
        bool(re.search(r"\d", mat_khau)),
        bool(re.search(r"[^A-Za-z0-9]", mat_khau)),
    ])
    if nhom < 2:
        return "Mật khẩu cần ít nhất 2 nhóm ký tự (chữ thường, chữ hoa, số, ký tự đặc biệt)."
    return None


def chuan_hoa_id(user_id: str) -> str:
    return (user_id or "").strip().lower()


def kiem_tra_id(user_id: str) -> str | None:
    if not ID_RE.match(user_id or ""):
        return "ID phải dài 3–40 ký tự, bắt đầu bằng chữ/số, chỉ gồm a-z, 0-9, dấu chấm, gạch ngang, gạch dưới."
    if user_id in ID_CAM or user_id in TEN_DANH_RIENG_KHACH:
        return "ID này được dành riêng cho hệ thống."
    return None


def slug(text: str, max_len: int = 40) -> str:
    text = unicodedata.normalize("NFD", text or "")
    text = "".join(c for c in text if unicodedata.category(c) != "Mn")
    text = text.replace("đ", "d").replace("Đ", "D").lower()
    text = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return (text[:max_len].strip("-") or "muc")


def safe_next(url: str | None) -> str:
    """Chỉ cho phép đường dẫn nội bộ, chặn open-redirect."""
    if not url:
        return "/"
    url = url.strip()
    if not url.startswith("/") or url.startswith("//") or "\\" in url:
        return "/"
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        return "/"
    return url[:500]


# ----------------------------- HMAC nội bộ COWORK ↔ BRAIN -----------------------------
def _canonical(direction: str, ts: str, body: bytes) -> bytes:
    return f"{direction}.{ts}.".encode("utf-8") + body


def ky_hmac(direction: str, body: bytes, secret: str | None = None) -> dict[str, str]:
    """Sinh header chữ ký cho một chiều (`cowork->brain` hoặc `brain->cowork`)."""
    ts = str(int(time.time()))
    sig = hmac.new((secret or config.BRAIN_SHARED_SECRET).encode("utf-8"),
                   _canonical(direction, ts, body), hashlib.sha256).hexdigest()
    return {"X-Cowork-Ts": ts, "X-Cowork-Sig": sig, "X-Cowork-Direction": direction}


def xac_thuc_hmac(direction: str, ts: str | None, sig: str | None, body: bytes,
                  secret: str | None = None, cua_so: int = 300) -> bool:
    if not ts or not sig:
        return False
    try:
        ts_int = int(ts)
    except (TypeError, ValueError):
        return False
    if abs(time.time() - ts_int) > cua_so:
        return False
    mong = hmac.new((secret or config.BRAIN_SHARED_SECRET).encode("utf-8"),
                    _canonical(direction, ts, body), hashlib.sha256).hexdigest()
    return hmac.compare_digest(mong, sig)


# ----------------------------- MFA TOTP (RFC 6238) -----------------------------
TOTP_BUOC = 30
TOTP_DIGITS = 6
CHU_MA_DU_PHONG = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # bỏ 0/O, 1/I


def tao_bi_mat_totp(nbytes: int = 20) -> str:
    """Sinh secret base32 (160-bit) để đưa vào authenticator."""
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def _khoa_totp(secret: str) -> bytes:
    s = re.sub(r"\s+", "", secret or "").upper()
    if not s:
        raise ValueError("Secret TOTP rỗng")
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + pad, casefold=True)


def totp(secret: str, at: float | None = None, buoc: int = TOTP_BUOC,
         digits: int = TOTP_DIGITS) -> str:
    """Mã TOTP 6 số tại thời điểm `at` (mặc định hiện tại)."""
    counter = int((time.time() if at is None else at) // buoc)
    msg = struct.pack(">Q", counter)
    h = hmac.new(_khoa_totp(secret), msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def kiem_totp(secret: str, ma: str, cua_so: int = 1, at: float | None = None) -> bool:
    """Chấp nhận mã hiện tại ±`cua_so` bước 30 giây; so sánh hằng thời gian."""
    ma = re.sub(r"\D", "", str(ma or ""))
    if len(ma) != TOTP_DIGITS or not secret:
        return False
    now = time.time() if at is None else at
    for delta in range(-cua_so, cua_so + 1):
        try:
            if hmac.compare_digest(totp(secret, now + delta * TOTP_BUOC), ma):
                return True
        except (ValueError, TypeError):
            return False
    return False


def otpauth_uri(secret: str, user_id: str, issuer: str = "VIP GROUP COWORK") -> str:
    """URI để nhập thủ công vào Google Authenticator/Authy/1Password."""
    label = quote(f"{issuer}:{user_id}", safe="")
    return (f"otpauth://totp/{label}?secret={quote(secret)}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_BUOC}")


def tao_ma_du_phong(n: int = 10) -> str:
    raw = "".join(secrets.choice(CHU_MA_DU_PHONG) for _ in range(n))
    return f"{raw[:5]}-{raw[5:]}"


def chuan_ma_du_phong(ma: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", ma or "").upper()


def bam_ma_du_phong(ma: str) -> str:
    return hashlib.sha256(chuan_ma_du_phong(ma).encode("utf-8")).hexdigest()
