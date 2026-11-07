"""Realm KHÁCH của VIP ID — cổng khách hàng P1 (docs KIEN_TRUC_P1 §3, §4, §11).

Nguyên tắc:
- Bảng riêng `customer_*`, không bao giờ chạm `users` của nhân viên. subject = 'cust:' + id.
- Không lộ tài khoản: đăng ký / quên mật khẩu luôn trả cùng một phản hồi; đăng nhập sai
  luôn cùng một thông báo, có lượt băm giả khi không có tài khoản.
- Chống khoá ác ý (§11.6): khoá tạm theo cặp (tài khoản, IP); giới hạn theo IP; trên mọi
  IP cộng lại tài khoản chỉ bị LÀM CHẬM dần (tối đa vài chục giây), không bao giờ khoá dài.
- Token email một lần, chỉ lưu sha256, TTL 30 phút.
- Email chỉ ghi `customer_outbox` (không gửi thật). Production bị chặn khởi động (A8).
- Mọi sự kiện bảo mật ghi `audit_log` với tenant_id='khach'.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import re
import secrets
import sqlite3
import time
import unicodedata
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from . import audit, config, db, security

log = logging.getLogger("cowork.khach")

TENANT = "khach"
AUD_LAUNCH = "vip-crm-portal"
HUONG_RA = "vipid->crm"
HUONG_VAO = "crm->vipid"
PATH_SIGNUP = "/api/internal/portal/signups"
PATH_THU_HOI = "/api/internal/portal/thu-hoi"
COOKIE_PHIEN = "vg_khach"
COOKIE_CSRF = "vg_khach_csrf"
COOKIE_PATH = "/tai-khoan"
PORTAL_CODE_RE = re.compile(r"^VG\d{6}$")
EMAIL_RE = re.compile(r"^[^@\s<>\"'(),;:\\]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                      r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
#: Kênh gửi email đã cài thật. Hiện CHƯA có kênh nào ⇒ production luôn bị chặn (A8).
KENH_EMAIL_THAT: set[str] = set()
#: Sau ngần này lần sai (mọi IP cộng lại) trong cửa sổ thì bắt đầu làm chậm.
LAM_CHAM_SAU = 10
LAM_CHAM_TOI_DA_GIAY = 30

THONG_BAO_SAI = "Thông tin đăng nhập không đúng hoặc tài khoản chưa thể đăng nhập."
THONG_BAO_TAM_KHOA = ("Bạn đã thử đăng nhập sai nhiều lần từ thiết bị này. "
                      "Vui lòng thử lại sau {phut} phút hoặc đặt lại mật khẩu.")


class KhachLoi(Exception):
    """Lỗi nghiệp vụ realm khách: `status` HTTP + thông báo an toàn để hiển thị."""

    def __init__(self, message: str, status: int = 400, ma: str = "LOI"):
        super().__init__(message)
        self.message = message
        self.status = status
        self.ma = ma


class ChoDuyet(KhachLoi):
    pass


# ------------------------------------------------------------------ cấu hình / bí mật
_bi_mat_cache: str | None = None


def portal_secret() -> str:
    """VIPID_PORTAL_SECRET: env → tệp 0600 → sinh mới (dev). Nạp lười, chỉ khi cần."""
    global _bi_mat_cache
    if _bi_mat_cache is None:
        _bi_mat_cache = config._secret(config.PORTAL_SECRET_FILE, "VIPID_PORTAL_SECRET")
    return _bi_mat_cache


def _host_cua_url(url: str) -> str:
    try:
        return (urlsplit(url).netloc or "").lower()
    except ValueError:
        return ""


def kiem_cau_hinh() -> None:
    """Gọi lúc khởi động. Realm bật mà cấu hình không an toàn ⇒ RuntimeError (từ chối chạy)."""
    if not config.KHACH_ENABLED:
        return
    loi: list[str] = []
    if config.ENV == "production" and config.KHACH_MAIL_TRANSPORT not in KENH_EMAIL_THAT:
        loi.append("A8: production chưa có kênh gửi email thật (COWORK_KHACH_MAIL_TRANSPORT="
                   f"{config.KHACH_MAIL_TRANSPORT!r}) — không được bật realm khách.")
    if not config.KHACH_HOSTS:
        loi.append("COWORK_KHACH_HOSTS rỗng.")
    host_nv = {_host_cua_url(config.PUBLIC_URL), _host_cua_url(config.INTERNAL_URL)}
    if any(h in host_nv for h in config.KHACH_HOSTS):
        loi.append("COWORK_KHACH_HOSTS trùng host nhân viên (PUBLIC_URL/INTERNAL_URL).")
    bi_mat = portal_secret()
    if len(bi_mat.encode("utf-8")) < 32:
        loi.append("VIPID_PORTAL_SECRET phải dài ít nhất 32 byte.")
    import os
    khac = [config.BRAIN_SHARED_SECRET, config.SECRET_KEY, config.HATANG_SHARED_SECRET,
            os.environ.get("VIPID_SHARED_SECRET", ""), os.environ.get("COWORK_SHARED_SECRET", "")]
    if any(k and hmac.compare_digest(k, bi_mat) for k in khac):
        loi.append("VIPID_PORTAL_SECRET phải KHÁC mọi bí mật khác (Brain, phiên, hạ tầng).")
    if config.ENV == "production":
        for ten, url in (("CRM_PORTAL_PUBLIC_URL", config.CRM_PORTAL_PUBLIC_URL),
                         ("COWORK_KHACH_PUBLIC_URL", config.KHACH_PUBLIC_URL)):
            if not url.startswith("https://"):
                loi.append(f"{ten} phải là https ở production.")
    if loi:
        raise RuntimeError("Realm khách bị chặn: " + " | ".join(loi))


def la_host_khach(host: str | None) -> bool:
    h = (host or "").strip().lower()
    if not h:
        return False
    ten = h
    if not h.startswith("[") and h.count(":") == 1:
        ten = h.split(":", 1)[0]
    for e in config.KHACH_HOSTS:
        if h == e or (":" not in e and ten == e):
            return True
    return False


# ------------------------------------------------------------------ tiện ích
def _bay_gio() -> datetime:
    return datetime.now(db.TZ).replace(microsecond=0)


def _iso(dt: datetime) -> str:
    return dt.isoformat()


def _truoc(**kw) -> str:
    return _iso(_bay_gio() - timedelta(**kw))


def che_sdt(phone: str | None) -> str:
    p = phone or ""
    return p[:5] + "****" + p[-3:] if len(p) > 8 else "***"


def che_email(email: str | None) -> str:
    e = email or ""
    if "@" not in e:
        return "***"
    ten, mien = e.split("@", 1)
    return (ten[:1] + "***@" + mien) if ten else "***@" + mien


def chuan_hoa_sdt(raw: str | None) -> str | None:
    """SĐT di động Việt Nam → E.164 (+84 + 9 số, đầu 3/5/7/8/9). Sai ⇒ None."""
    s = re.sub(r"[\s.\-()]", "", raw or "")
    if not s:
        return None
    if s.startswith("+"):
        s = s[1:]
        if not s.startswith("84"):
            return None
        so = s[2:]
    elif s.startswith("0084"):
        so = s[4:]
    elif s.startswith("84") and len(s) == 11:
        so = s[2:]
    elif s.startswith("0"):
        so = s[1:]
    else:
        return None
    if not re.fullmatch(r"[35789]\d{8}", so):
        return None
    return "+84" + so


def chuan_hoa_email(raw: str | None) -> str | None:
    e = unicodedata.normalize("NFKC", (raw or "")).strip().lower()
    if not e or len(e) > 254 or not EMAIL_RE.match(e):
        return None
    return e


def chuan_hoa_ten(raw: str | None) -> str | None:
    t = unicodedata.normalize("NFC", raw or "")
    t = "".join(c for c in t if unicodedata.category(c)[0] != "C")
    t = re.sub(r"\s+", " ", t).strip()
    if len(t) < 2 or len(t) > 100 or re.search(r"[<>]", t):
        return None
    return t


def chuan_hoa_portal_code(raw: str | None) -> str | None:
    c = (raw or "").strip().upper()
    return c if PORTAL_CODE_RE.match(c) else None


def _ghi_audit(conn, actor: str, action: str, *, target_id: str | None = None,
               detail: dict | None = None, request=None) -> None:
    try:
        audit.ghi(conn, actor or "khach:anon", action, target_type="customer",
                  target_id=target_id, detail=detail, request=request, tenant_id=TENANT)
    except Exception:  # noqa: BLE001 - audit không được làm hỏng luồng; nhưng phải ghi log
        log.exception("Không ghi được audit %s", action)


def vuot_tan_suat(conn, bucket: str, key: str, toi_da: int, giay: int) -> bool:
    """True nếu đã đủ `toi_da` sự kiện trong `giay` giây; ngược lại ghi thêm một sự kiện."""
    conn.execute("DELETE FROM customer_rate_events WHERE created_at<?", (_truoc(days=2),))
    n = conn.execute("SELECT COUNT(*) FROM customer_rate_events WHERE bucket=? AND key=? "
                     "AND created_at>=?", (bucket, key, _truoc(seconds=giay))).fetchone()[0]
    if n >= toi_da:
        conn.commit()
        return True
    conn.execute("INSERT INTO customer_rate_events(bucket, key, created_at) VALUES(?,?,?)",
                 (bucket, key, _iso(_bay_gio())))
    conn.commit()
    return False


def tai_khoan(conn, account_id: str) -> dict | None:
    return db.one(conn, "SELECT * FROM customer_accounts WHERE id=?", (account_id,))


def tai_khoan_theo_subject(conn, subject: str) -> dict | None:
    return db.one(conn, "SELECT * FROM customer_accounts WHERE subject=?", (subject,))


# ------------------------------------------------------------------ outbox email
def gui_email(conn, account_id: str | None, to_email: str, kind: str, tieu_de: str,
              noi_dung: str) -> int:
    """Chỉ ghi outbox. Không có kênh gửi thật (A8)."""
    cur = conn.execute(
        "INSERT INTO customer_outbox(account_id, kind, to_email, subject, body_text, created_at) "
        "VALUES(?,?,?,?,?,?)", (account_id, kind, to_email, tieu_de, noi_dung, db.now_iso()))
    conn.commit()
    return int(cur.lastrowid)


def _link(path: str) -> str:
    return f"{config.KHACH_PUBLIC_URL}{path}"


_CHAN_THU = ("\n\n—\nCÔNG TY TNHH VIP GROUP\nEmail tự động, vui lòng không trả lời. "
             "Nếu bạn không thực hiện yêu cầu này, hãy bỏ qua email.")


# ------------------------------------------------------------------ token một lần
def tao_token(conn, account_id: str, purpose: str) -> str:
    raw = security.token_moi(32)
    now = _bay_gio()
    # Token mới vô hiệu mọi token cùng mục đích còn treo.
    conn.execute("UPDATE customer_tokens SET used_at=? WHERE account_id=? AND purpose=? "
                 "AND used_at IS NULL", (_iso(now), account_id, purpose))
    conn.execute(
        "INSERT INTO customer_tokens(id, token_hash, account_id, purpose, expires_at, created_at) "
        "VALUES(?,?,?,?,?,?)",
        (security.token_moi(12), security.sha256(raw), account_id, purpose,
         _iso(now + timedelta(minutes=config.KHACH_TOKEN_TTL_MIN)), _iso(now)))
    conn.commit()
    return raw


def xem_token(conn, raw: str | None, purpose: str) -> dict | None:
    """Kiểm token còn hiệu lực, KHÔNG tiêu (dùng cho trang GET đặt lại)."""
    if not raw or len(raw) > 200:
        return None
    return db.one(conn, "SELECT * FROM customer_tokens WHERE token_hash=? AND purpose=? "
                  "AND used_at IS NULL AND expires_at>?",
                  (security.sha256(raw), purpose, _iso(_bay_gio())))


def tieu_token(conn, raw: str | None, purpose: str) -> str | None:
    """Tiêu token nguyên tử. Trả account_id hoặc None (sai / đã dùng / hết hạn)."""
    if not raw or len(raw) > 200:
        return None
    h = security.sha256(raw)
    cur = conn.execute("UPDATE customer_tokens SET used_at=? WHERE token_hash=? AND purpose=? "
                       "AND used_at IS NULL AND expires_at>?",
                       (_iso(_bay_gio()), h, purpose, _iso(_bay_gio())))
    conn.commit()
    if cur.rowcount != 1:
        return None
    return db.scalar(conn, "SELECT account_id FROM customer_tokens WHERE token_hash=?", (h,))


# ------------------------------------------------------------------ đăng ký
def _gui_link_kich_hoat(conn, acc: dict) -> None:
    raw = tao_token(conn, acc["id"], "kich_hoat_email")
    gui_email(conn, acc["id"], acc["email_norm"], "kich_hoat_email",
              "VIP GROUP — Xác minh email đăng ký cổng khách hàng",
              f"Chào {acc['display_name']},\n\nBấm liên kết sau để xác minh email (hiệu lực "
              f"{config.KHACH_TOKEN_TTL_MIN} phút, dùng một lần):\n"
              f"{_link('/tai-khoan/xac-minh-email?t=' + raw)}\n\nSau khi xác minh, nhân viên "
              "VIP GROUP sẽ gọi điện xác minh số điện thoại rồi kích hoạt tài khoản." + _CHAN_THU)


def dang_ky(conn, *, ho_ten: str, sdt: str, email: str, mat_khau: str, mat_khau_2: str,
            dong_y: bool, ip: str, request=None) -> None:
    """Ném KhachLoi khi dữ liệu SAI ĐỊNH DẠNG. Trùng SĐT/email ⇒ im lặng (không lộ tài khoản)."""
    ten = chuan_hoa_ten(ho_ten)
    phone = chuan_hoa_sdt(sdt)
    em = chuan_hoa_email(email)
    if not ten:
        raise KhachLoi("Họ tên cần từ 2 đến 100 ký tự.")
    if not phone:
        raise KhachLoi("Số điện thoại di động Việt Nam không hợp lệ (ví dụ 0901 234 567).")
    if not em:
        raise KhachLoi("Địa chỉ email không hợp lệ.")
    loi_mk = security.kiem_tra_do_manh(mat_khau or "", phone[3:], min_len=config.KHACH_PASSWORD_MIN)
    if loi_mk:
        raise KhachLoi(loi_mk)
    if mat_khau != mat_khau_2:
        raise KhachLoi("Hai lần nhập mật khẩu không khớp.")
    if not dong_y:
        raise KhachLoi("Bạn cần đồng ý với chính sách bảo mật và điều khoản sử dụng.")
    if vuot_tan_suat(conn, "dang_ky_ip", ip, config.KHACH_SIGNUP_IP_PER_HOUR, 3600):
        _ghi_audit(conn, "khach:anon", "khach.dang_ky.qua_tan_suat", detail={"ip": ip},
                   request=request)
        raise KhachLoi("Bạn đã gửi quá nhiều yêu cầu đăng ký. Vui lòng thử lại sau.", 429,
                       "QUA_TAN_SUAT")

    trung = db.q(conn, "SELECT * FROM customer_accounts WHERE phone_e164=? OR email_norm=?",
                 (phone, em))
    # Giải phóng đăng ký "giữ chỗ" chưa từng xác minh email và đã quá hạn.
    han = _truoc(hours=config.KHACH_UNVERIFIED_TTL_HOURS)
    con_lai = []
    for acc in trung:
        if acc["status"] == "cho_xac_minh_email" and acc["created_at"] < han:
            conn.execute("DELETE FROM customer_accounts WHERE id=?", (acc["id"],))
            conn.commit()
            _ghi_audit(conn, "system", "khach.dang_ky.giai_phong_qua_han", target_id=acc["subject"],
                       detail={"phone": che_sdt(acc["phone_e164"])}, request=request)
        else:
            con_lai.append(acc)
    if con_lai:
        _xu_ly_trung(conn, con_lai, em, mat_khau, request)
        return

    hash_b64, salt_b64 = security.bam_mat_khau(mat_khau)
    acc_id = "kh_" + _ngau_nhien_26()
    now = db.now_iso()
    try:
        conn.execute(
            "INSERT INTO customer_accounts(id, subject, phone_e164, email_norm, display_name, "
            "password_hash, password_salt, password_algo, status, consent_at, token_version, "
            "failed_attempts, created_at, updated_at) VALUES(?,?,?,?,?,?,?, 'scrypt', "
            "'cho_xac_minh_email', ?, 1, 0, ?, ?)",
            (acc_id, "cust:" + acc_id, phone, em, ten, hash_b64, salt_b64, now, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        # Đua đăng ký cùng lúc: xử lý như trùng.
        conn.rollback()
        return
    acc = tai_khoan(conn, acc_id)
    _gui_link_kich_hoat(conn, acc)
    _ghi_audit(conn, acc["subject"], "khach.dang_ky", target_id=acc["subject"],
               detail={"phone": che_sdt(phone), "email": che_email(em)}, request=request)


def _ngau_nhien_26() -> str:
    chu = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(chu) for _ in range(26))


def _xu_ly_trung(conn, trung: list[dict], email_moi: str, mat_khau: str, request) -> None:
    security.bam_gia(mat_khau)  # cân bằng thời gian với nhánh tạo mới
    for acc in trung:
        _ghi_audit(conn, "khach:anon", "khach.dang_ky.trung", target_id=acc["subject"],
                   request=request)
        # Mỗi tài khoản nhận tối đa 1 email loại này / giờ (chống dùng form để spam).
        if vuot_tan_suat(conn, "thong_bao_trung", acc["id"], 1, 3600):
            continue
        if acc["status"] == "cho_xac_minh_email" and acc["email_norm"] == email_moi:
            # Chính chủ đăng ký lại vì mất email: gửi lại link (tới email ĐÃ ĐĂNG KÝ).
            _gui_link_kich_hoat(conn, acc)
            continue
        gui_email(conn, acc["id"], acc["email_norm"], "dang_ky_trung",
                  "VIP GROUP — Có người vừa đăng ký bằng thông tin của bạn",
                  "Có người vừa thử đăng ký cổng khách hàng VIP GROUP bằng số điện thoại hoặc "
                  "email đã gắn với tài khoản của bạn. Tài khoản của bạn không bị thay đổi.\n\n"
                  "Nếu bạn quên mật khẩu, hãy dùng chức năng Quên mật khẩu:\n"
                  f"{_link('/tai-khoan/quen-mat-khau')}" + _CHAN_THU)


def gui_lai_xac_minh(conn, email: str, ip: str, request=None) -> None:
    """Luôn im lặng. Chỉ gửi khi email thuộc tài khoản đang chờ xác minh."""
    em = chuan_hoa_email(email)
    if vuot_tan_suat(conn, "gui_lai_ip", ip, config.KHACH_FORGOT_IP_PER_HOUR, 3600) or not em:
        return
    acc = db.one(conn, "SELECT * FROM customer_accounts WHERE email_norm=?", (em,))
    if not acc or acc["status"] != "cho_xac_minh_email":
        return
    if vuot_tan_suat(conn, "gui_lai_acc", acc["id"], 3, 3600):
        return
    _gui_link_kich_hoat(conn, acc)
    _ghi_audit(conn, acc["subject"], "khach.gui_lai_xac_minh", target_id=acc["subject"],
               request=request)


def xac_minh_email(conn, raw: str | None, request=None) -> dict | None:
    """Tiêu token kích hoạt → `cho_duyet` + gửi signup sang CRM. Trả account hoặc None."""
    acc_id = tieu_token(conn, raw, "kich_hoat_email")
    if not acc_id:
        _ghi_audit(conn, "khach:anon", "khach.xac_minh_email.token_sai", request=request)
        return None
    acc = tai_khoan(conn, acc_id)
    if not acc:
        return None
    if acc["status"] == "cho_xac_minh_email":
        now = db.now_iso()
        conn.execute("UPDATE customer_accounts SET status='cho_duyet', email_verified_at=?, "
                     "updated_at=? WHERE id=? AND status='cho_xac_minh_email'",
                     (now, now, acc_id))
        conn.commit()
        acc = tai_khoan(conn, acc_id)
        _ghi_audit(conn, acc["subject"], "khach.xac_minh_email", target_id=acc["subject"],
                   request=request)
        xep_hang_crm(conn, "signup", "signup:" + acc["subject"], acc["subject"], PATH_SIGNUP, {
            "subject": acc["subject"], "display_name": acc["display_name"],
            "phone_e164": acc["phone_e164"], "email": acc["email_norm"],
        })
    return acc


# ------------------------------------------------------------------ đăng nhập
def _tim_theo_dinh_danh(conn, dinh_danh: str) -> tuple[dict | None, str]:
    """Trả (account|None, khoá đếm). Định danh: SĐT E.164 hoặc portal_code VGxxxxxx."""
    raw = (dinh_danh or "").strip()
    code = chuan_hoa_portal_code(raw)
    if code:
        acc = db.one(conn, "SELECT * FROM customer_accounts WHERE portal_code=?", (code,))
        return acc, (acc["id"] if acc else "code:" + code)
    phone = chuan_hoa_sdt(raw)
    if phone:
        acc = db.one(conn, "SELECT * FROM customer_accounts WHERE phone_e164=?", (phone,))
        return acc, (acc["id"] if acc else "phone:" + phone)
    return None, "raw:" + security.sha256(raw.lower())[:32]


def _dem_sai(conn, where: str, params: tuple, phut: int) -> int:
    return int(conn.execute(
        f"SELECT COUNT(*) FROM customer_login_attempts WHERE success=0 AND created_at>=? AND {where}",
        (_truoc(minutes=phut), *params)).fetchone()[0])


def _ghi_lan(conn, key: str, ip: str, ok: bool) -> None:
    conn.execute("INSERT INTO customer_login_attempts(account_key, ip, success, created_at) "
                 "VALUES(?,?,?,?)", (key, ip, 1 if ok else 0, db.now_iso()))
    conn.execute("DELETE FROM customer_login_attempts WHERE created_at<?", (_truoc(days=2),))
    conn.commit()


def thoi_gian_cho_lam_cham(conn, key: str) -> int:
    """Số giây còn phải chờ do làm chậm toàn cục theo tài khoản (mọi IP). 0 = không chờ."""
    w = config.KHACH_LOGIN_WINDOW_MIN
    n = _dem_sai(conn, "account_key=?", (key,), w)
    if n < LAM_CHAM_SAU:
        return 0
    cho = min(LAM_CHAM_TOI_DA_GIAY, 2 ** min(10, n - LAM_CHAM_SAU + 1))
    cuoi = db.scalar(conn, "SELECT MAX(created_at) FROM customer_login_attempts "
                     "WHERE account_key=? AND success=0", (key,))
    try:
        da_qua = (_bay_gio() - datetime.fromisoformat(cuoi)).total_seconds()
    except (TypeError, ValueError):
        return 0
    return max(0, int(cho - da_qua))


def dang_nhap(conn, dinh_danh: str, mat_khau: str, ip: str, request=None) -> dict:
    """Trả account khi được phép đăng nhập. Ném KhachLoi/ChoDuyet nếu không."""
    w = config.KHACH_LOGIN_WINDOW_MIN
    mat_khau = mat_khau or ""
    acc, key = _tim_theo_dinh_danh(conn, dinh_danh)
    actor = acc["subject"] if acc else "khach:anon"
    # 1) Giới hạn theo IP (mọi tài khoản).
    if _dem_sai(conn, "ip=?", (ip,), w) >= config.KHACH_LOGIN_IP_MAX_FAIL:
        security.bam_gia(mat_khau)
        _ghi_audit(conn, actor, "khach.dang_nhap.chan_ip", detail={"ip": ip}, request=request)
        raise KhachLoi("Quá nhiều lần đăng nhập sai từ mạng của bạn. Vui lòng thử lại sau "
                       f"{w} phút.", 429, "QUA_TAN_SUAT")
    # 2) Khoá tạm theo cặp (tài khoản, IP) — kẻ lạ ở IP khác không khoá được chủ tài khoản.
    if _dem_sai(conn, "account_key=? AND ip=?", (key, ip), w) >= config.KHACH_LOGIN_MAX_FAIL:
        security.bam_gia(mat_khau)
        _ghi_audit(conn, actor, "khach.dang_nhap.khoa_cap_ip", detail={"ip": ip}, request=request)
        raise KhachLoi(THONG_BAO_TAM_KHOA.format(phut=config.KHACH_LOCK_MIN), 429, "TAM_KHOA")
    # 3) Mọi IP cộng lại: chỉ làm chậm dần (tối đa LAM_CHAM_TOI_DA_GIAY giây).
    cho = thoi_gian_cho_lam_cham(conn, key)
    if cho > 0:
        security.bam_gia(mat_khau)
        raise KhachLoi(f"Vui lòng đợi {cho} giây rồi thử lại.", 429, "LAM_CHAM")

    hop_le = False
    if acc:
        hop_le = security.kiem_mat_khau(mat_khau, acc["password_hash"], acc["password_salt"])
    else:
        security.bam_gia(mat_khau)
    if not hop_le:
        _ghi_lan(conn, key, ip, False)
        if acc:
            conn.execute("UPDATE customer_accounts SET failed_attempts=failed_attempts+1 "
                         "WHERE id=?", (acc["id"],))
            conn.commit()
        n_tk = _dem_sai(conn, "account_key=?", (key,), w)
        _ghi_audit(conn, actor, "khach.dang_nhap.sai", detail={"ip": ip, "lan": n_tk},
                   request=request)
        if n_tk == LAM_CHAM_SAU:
            # Sự kiện để cảnh báo: tài khoản bị dò từ nhiều nơi.
            _ghi_audit(conn, actor, "khach.canh_bao.do_mat_khau", detail={"lan": n_tk},
                       request=request)
            log.warning("CANH_BAO khach: tài khoản %s bị dò mật khẩu (%s lần/%s phút)",
                        actor, n_tk, w)
        raise KhachLoi(THONG_BAO_SAI, 401, "SAI_THONG_TIN")

    # Mật khẩu đúng ⇒ có thể nói trạng thái cho chính chủ.
    if acc["status"] == "cho_xac_minh_email":
        raise KhachLoi("Bạn chưa xác minh email. Hãy mở liên kết trong email đăng ký "
                       "hoặc yêu cầu gửi lại.", 403, "CHUA_XAC_MINH_EMAIL")
    if acc["status"] == "cho_duyet" or (acc["status"] == "hoat_dong"
                                        and not acc["phone_verified_at"]):
        raise ChoDuyet("Tài khoản đang chờ VIP GROUP duyệt.", 403, "CHO_DUYET")
    if acc["status"] != "hoat_dong" or not acc["phone_verified_at"] or not acc["crm_customer_id"]:
        _ghi_audit(conn, actor, "khach.dang_nhap.bi_tu_choi", detail={"status": acc["status"]},
                   request=request)
        raise KhachLoi("Tài khoản hiện không thể đăng nhập. Vui lòng liên hệ VIP GROUP.",
                       403, "KHONG_DUOC_PHEP")
    conn.execute("DELETE FROM customer_login_attempts WHERE account_key=? AND ip=? AND success=0",
                 (key, ip))
    _ghi_lan(conn, key, ip, True)
    now = db.now_iso()
    conn.execute("UPDATE customer_accounts SET last_login_at=?, failed_attempts=0, "
                 "locked_until=NULL, updated_at=? WHERE id=?", (now, now, acc["id"]))
    conn.commit()
    _ghi_audit(conn, acc["subject"], "khach.dang_nhap", target_id=acc["subject"],
               detail={"ip": ip}, request=request)
    return tai_khoan(conn, acc["id"])


# ------------------------------------------------------------------ phiên
def tao_phien(conn, acc: dict, ip: str | None, ua: str | None) -> tuple[dict, str]:
    token = security.token_moi(32)
    csrf = security.token_moi(24)
    now = _bay_gio()
    het = now + timedelta(hours=config.KHACH_SESSION_HOURS)
    sid = security.token_moi(12)
    conn.execute(
        "INSERT INTO customer_sessions(id, token_hash, csrf_token, account_id, token_version, "
        "created_at, last_seen_at, expires_at, ip, user_agent, status) "
        "VALUES(?,?,?,?,?,?,?,?,?,?, 'active')",
        (sid, security.sha256(token), csrf, acc["id"], acc["token_version"], _iso(now), _iso(now),
         _iso(het), ip, (ua or "")[:400] or None))
    # Tối đa 5 phiên sống / khách.
    rows = conn.execute("SELECT id FROM customer_sessions WHERE account_id=? AND status='active' "
                        "AND id<>? ORDER BY created_at DESC, rowid DESC", (acc["id"], sid)).fetchall()
    for r in rows[4:]:
        conn.execute("UPDATE customer_sessions SET status='revoked', revoked_at=?, "
                     "revoke_reason='Vượt giới hạn phiên' WHERE id=?", (db.now_iso(), r["id"]))
    conn.commit()
    return {"id": sid, "csrf_token": csrf, "expires_at": _iso(het)}, token


def xac_thuc_phien(conn, token: str | None) -> dict | None:
    if not token or len(token) > 200:
        return None
    s = db.one(conn, "SELECT * FROM customer_sessions WHERE token_hash=? AND status='active'",
               (security.sha256(token),))
    if not s:
        return None
    now = _bay_gio()
    try:
        het = datetime.fromisoformat(s["expires_at"])
        seen = datetime.fromisoformat(s["last_seen_at"])
    except (TypeError, ValueError):
        return None
    if now >= het or now >= seen + timedelta(minutes=config.KHACH_IDLE_MINUTES):
        conn.execute("UPDATE customer_sessions SET status='expired' WHERE id=?", (s["id"],))
        conn.commit()
        return None
    acc = tai_khoan(conn, s["account_id"])
    if (not acc or acc["status"] != "hoat_dong" or not acc["phone_verified_at"]
            or int(acc["token_version"]) != int(s["token_version"])):
        conn.execute("UPDATE customer_sessions SET status='revoked', revoked_at=?, "
                     "revoke_reason='Tài khoản không còn hiệu lực' WHERE id=?",
                     (db.now_iso(), s["id"]))
        conn.commit()
        return None
    if (now - seen).total_seconds() >= 60:
        conn.execute("UPDATE customer_sessions SET last_seen_at=? WHERE id=?", (_iso(now), s["id"]))
        conn.commit()
    s.pop("token_hash", None)
    return {"session": s, "account": acc}


def thu_hoi_phien(conn, session_id: str, reason: str) -> bool:
    cur = conn.execute("UPDATE customer_sessions SET status='revoked', revoked_at=?, "
                       "revoke_reason=? WHERE id=? AND status='active'",
                       (db.now_iso(), reason[:200], session_id))
    conn.commit()
    return cur.rowcount > 0


def thu_hoi_moi_phien(conn, account_id: str, reason: str) -> int:
    cur = conn.execute("UPDATE customer_sessions SET status='revoked', revoked_at=?, "
                       "revoke_reason=? WHERE account_id=? AND status='active'",
                       (db.now_iso(), reason[:200], account_id))
    conn.commit()
    return int(cur.rowcount)


def dang_xuat(conn, ctx: dict, request=None) -> None:
    acc = ctx["account"]
    thu_hoi_phien(conn, ctx["session"]["id"], "Khách đăng xuất")
    _ghi_audit(conn, acc["subject"], "khach.dang_xuat", target_id=acc["subject"], request=request)
    bao_crm_thu_hoi(conn, acc["subject"], "dang_xuat")


# ------------------------------------------------------------------ launch token (HS256)
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def phat_launch_token(conn, acc: dict, request=None) -> str:
    if acc["status"] != "hoat_dong" or not acc["phone_verified_at"] or not acc["crm_customer_id"]:
        raise KhachLoi("Tài khoản chưa được kích hoạt.", 403, "KHONG_DUOC_PHEP")
    iat = int(time.time())
    payload = {
        "ver": 1, "aud": AUD_LAUNCH, "sub": acc["subject"],
        "crm_customer_id": acc["crm_customer_id"], "portal_code": acc["portal_code"],
        "iat": iat, "exp": iat + max(1, config.KHACH_LAUNCH_TTL), "nonce": security.token_moi(18),
    }
    header = {"alg": "HS256", "typ": "JWT"}
    phan = (_b64u(json.dumps(header, separators=(",", ":")).encode()) + "."
            + _b64u(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()))
    sig = hmac.new(portal_secret().encode("utf-8"), phan.encode("ascii"), hashlib.sha256).digest()
    _ghi_audit(conn, acc["subject"], "khach.launch", target_id=acc["subject"],
               detail={"nonceHash": security.sha256(payload["nonce"])[:16]}, request=request)
    return phan + "." + _b64u(sig)


def url_launch(token: str) -> str:
    return f"{config.CRM_PORTAL_PUBLIC_URL}/portal/auth/launch?token={token}"


# ------------------------------------------------------------------ HMAC VIP ID ⇄ CRM
def ky_portal(direction: str, body: bytes, ts: int | None = None) -> dict[str, str]:
    t = str(int(time.time()) if ts is None else ts)
    sig = hmac.new(portal_secret().encode("utf-8"), security._canonical(direction, t, body),
                   hashlib.sha256).hexdigest()
    return {"X-Portal-Ts": t, "X-Portal-Sig": sig}


def xac_thuc_vao(conn, ts: str | None, sig: str | None, body: bytes) -> str:
    """HMAC chiều CRM → VIP ID, lệch ±300 giây, mỗi chữ ký chỉ dùng MỘT lần.

    Trả 'ok' | 'sai' (chữ ký sai/thiếu/hết hạn) | 'phat_lai' (đúng nhưng đã dùng).
    """
    sig = (sig or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", sig):
        return "sai"
    if not security.xac_thuc_hmac(HUONG_VAO, ts, sig, body, secret=portal_secret(), cua_so=300):
        return "sai"
    conn.execute("DELETE FROM customer_hmac_seen WHERE ts<?", (int(time.time()) - 900,))
    try:
        conn.execute("INSERT INTO customer_hmac_seen(sig, ts, created_at) VALUES(?,?,?)",
                     (sig, int(ts), db.now_iso()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        _ghi_audit(conn, "crm", "khach.hmac.phat_lai", detail={"sig": sig[:16]})
        return "phat_lai"
    return "ok"


def _http_post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str]:
    """Điểm gửi HTTP duy nhất (test thay thế). Trả (status, mô tả)."""
    import httpx
    r = httpx.post(url, content=body, headers=headers, timeout=config.CRM_PORTAL_TIMEOUT)
    return r.status_code, r.text[:200]


def xep_hang_crm(conn, kind: str, idem_key: str, subject: str, path: str, payload: dict,
                 gui_ngay: bool = True) -> int:
    now = db.now_iso()
    conn.execute(
        "INSERT OR IGNORE INTO crm_sync_pending(idem_key, kind, subject, path, body, attempts, "
        "next_at, created_at) VALUES(?,?,?,?,?,0,?,?)",
        (idem_key, kind, subject, path, json.dumps(payload, ensure_ascii=False,
                                                   separators=(",", ":")), now, now))
    conn.commit()
    row_id = int(db.scalar(conn, "SELECT id FROM crm_sync_pending WHERE idem_key=?", (idem_key,)))
    if gui_ngay:
        thu_gui(conn, row_id)
    return row_id


def thu_gui(conn, row_id: int) -> bool:
    row = db.one(conn, "SELECT * FROM crm_sync_pending WHERE id=?", (row_id,))
    if not row or row["done_at"]:
        return bool(row)
    body = row["body"].encode("utf-8")
    headers = {"Content-Type": "application/json", "Idempotency-Key": row["idem_key"],
               **ky_portal(HUONG_RA, body)}
    try:
        status, mo_ta = _http_post(config.CRM_PORTAL_INTERNAL_URL + row["path"], body, headers)
        ok = 200 <= status < 300 or status == 409  # 409 = CRM đã có (idempotent)
        loi = None if ok else f"HTTP {status}: {mo_ta}"
    except Exception as exc:  # noqa: BLE001 - CRM lỗi mạng ⇒ để lại hàng đợi
        ok, loi = False, f"{type(exc).__name__}: {str(exc)[:150]}"
    n = int(row["attempts"]) + 1
    if ok:
        conn.execute("UPDATE crm_sync_pending SET attempts=?, done_at=?, last_error=NULL "
                     "WHERE id=?", (n, db.now_iso(), row_id))
    else:
        tre = min(3600, 30 * 2 ** min(n, 7))
        conn.execute("UPDATE crm_sync_pending SET attempts=?, last_error=?, next_at=? WHERE id=?",
                     (n, loi, _iso(_bay_gio() + timedelta(seconds=tre)), row_id))
        log.warning("Gửi CRM %s thất bại (lần %s): %s", row["idem_key"], n, loi)
    conn.commit()
    return ok


def dong_bo_crm(conn, tat_ca: bool = False, gioi_han: int = 100) -> dict:
    """Thử lại các mục chưa gửi được (CLI/cron: `python -m cowork.cli khach-dong-bo`)."""
    sql = "SELECT id FROM crm_sync_pending WHERE done_at IS NULL"
    params: tuple = ()
    if not tat_ca:
        sql += " AND next_at<=?"
        params = (db.now_iso(),)
    ids = [r["id"] for r in db.q(conn, sql + " ORDER BY id LIMIT ?", (*params, gioi_han))]
    ok = sum(1 for i in ids if thu_gui(conn, i))
    con = int(db.scalar(conn, "SELECT COUNT(*) FROM crm_sync_pending WHERE done_at IS NULL"))
    return {"thu": len(ids), "thanh_cong": ok, "con_lai": con}


def bao_crm_thu_hoi(conn, subject: str, reason: str) -> None:
    xep_hang_crm(conn, "thu_hoi", f"thu-hoi:{subject}:{reason}:{security.token_moi(6)}",
                 subject, PATH_THU_HOI, {"subject": subject, "reason": reason})


# ------------------------------------------------------------------ CRM → VIP ID
def ket_qua_duyet(conn, data: dict, request=None) -> tuple[int, dict]:
    subject = str(data.get("subject") or "")
    decision = data.get("decision")
    acc = tai_khoan_theo_subject(conn, subject) if subject.startswith("cust:") else None
    if not acc:
        return 404, {"ma": "KHONG_TIM_THAY", "thongBao": "Không có tài khoản khách này."}
    if decision == "approved":
        crm_id = str(data.get("crm_customer_id") or "").strip()
        code = chuan_hoa_portal_code(str(data.get("portal_code") or ""))
        cust_code = str(data.get("customer_code") or "").strip() or None
        nguoi = str(data.get("phone_verified_by") or "").strip()
        if (not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", crm_id) or not code or not nguoi
                or len(nguoi) > 120 or (cust_code and len(cust_code) > 40)):
            return 400, {"ma": "DU_LIEU_SAI",
                         "thongBao": "Thiếu/sai crm_customer_id, portal_code hoặc phone_verified_by."}
        if acc["status"] in ("hoat_dong", "tam_khoa") and acc["crm_customer_id"]:
            if acc["crm_customer_id"] == crm_id and acc["portal_code"] == code:
                return 200, {"subject": subject, "status": acc["status"], "idempotent": True}
            return 409, {"ma": "XUNG_DOT", "thongBao": "Tài khoản đã liên kết hồ sơ CRM khác."}
        if acc["status"] != "cho_duyet":
            return 409, {"ma": "XUNG_DOT", "thongBao": f"Trạng thái {acc['status']} không duyệt được."}
        now = db.now_iso()
        try:
            conn.execute(
                "UPDATE customer_accounts SET status='hoat_dong', phone_verified_at=?, "
                "phone_verified_by=?, crm_customer_id=?, customer_code=?, portal_code=?, "
                "updated_at=? WHERE id=? AND status='cho_duyet'",
                (now, nguoi, crm_id, cust_code, code, now, acc["id"]))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return 409, {"ma": "XUNG_DOT", "thongBao": "crm_customer_id hoặc portal_code đã dùng."}
        _ghi_audit(conn, "crm", "khach.duyet", target_id=subject,
                   detail={"crm_customer_id": crm_id, "portal_code": code,
                           "phone_verified_by": nguoi}, request=request)
        gui_email(conn, acc["id"], acc["email_norm"], "kich_hoat_xong",
                  "VIP GROUP — Tài khoản cổng khách hàng đã được kích hoạt",
                  f"Chào {acc['display_name']},\n\nTài khoản của bạn đã được kích hoạt.\n"
                  f"Mã khách hàng: {code}\n\nĐăng nhập bằng số điện thoại hoặc mã khách hàng tại:\n"
                  f"{_link('/tai-khoan/dang-nhap')}" + _CHAN_THU)
        return 200, {"subject": subject, "status": "hoat_dong"}
    if decision == "rejected":
        if acc["status"] == "tu_choi":
            return 200, {"subject": subject, "status": "tu_choi", "idempotent": True}
        if acc["status"] != "cho_duyet":
            return 409, {"ma": "XUNG_DOT", "thongBao": f"Trạng thái {acc['status']} không từ chối được."}
        conn.execute("UPDATE customer_accounts SET status='tu_choi', updated_at=? WHERE id=?",
                     (db.now_iso(), acc["id"]))
        conn.commit()
        thu_hoi_moi_phien(conn, acc["id"], "Bị từ chối")
        _ghi_audit(conn, "crm", "khach.tu_choi", target_id=subject,
                   detail={"reason": str(data.get("reason") or "")[:200]}, request=request)
        return 200, {"subject": subject, "status": "tu_choi"}
    return 400, {"ma": "DU_LIEU_SAI", "thongBao": "decision phải là approved hoặc rejected."}


def tam_khoa(conn, data: dict, request=None) -> tuple[int, dict]:
    """Body {subject, action: 'khoa'|'mo_khoa', reason}."""
    subject = str(data.get("subject") or "")
    action = data.get("action")
    reason = str(data.get("reason") or "")[:200]
    acc = tai_khoan_theo_subject(conn, subject) if subject.startswith("cust:") else None
    if not acc:
        return 404, {"ma": "KHONG_TIM_THAY", "thongBao": "Không có tài khoản khách này."}
    now = db.now_iso()
    if action == "khoa":
        if acc["status"] != "tam_khoa":
            conn.execute("UPDATE customer_accounts SET status='tam_khoa', "
                         "token_version=token_version+1, updated_at=? WHERE id=?", (now, acc["id"]))
            conn.commit()
        n = thu_hoi_moi_phien(conn, acc["id"], "CRM tạm khoá")
        _ghi_audit(conn, "crm", "khach.tam_khoa", target_id=subject,
                   detail={"reason": reason, "phien": n}, request=request)
        return 200, {"subject": subject, "status": "tam_khoa"}
    if action == "mo_khoa":
        if acc["status"] == "tam_khoa":
            moi = ("hoat_dong" if acc["phone_verified_at"] and acc["crm_customer_id"]
                   else ("cho_duyet" if acc["email_verified_at"] else "cho_xac_minh_email"))
            conn.execute("UPDATE customer_accounts SET status=?, updated_at=? WHERE id=?",
                         (moi, now, acc["id"]))
            conn.commit()
            _ghi_audit(conn, "crm", "khach.mo_khoa", target_id=subject,
                       detail={"reason": reason, "status": moi}, request=request)
        return 200, {"subject": subject, "status": tai_khoan(conn, acc["id"])["status"]}
    return 400, {"ma": "DU_LIEU_SAI", "thongBao": "action phải là khoa hoặc mo_khoa."}


def thu_hoi_tu_crm(conn, data: dict, request=None) -> tuple[int, dict]:
    subject = str(data.get("subject") or "")
    acc = tai_khoan_theo_subject(conn, subject) if subject.startswith("cust:") else None
    if not acc:
        return 404, {"ma": "KHONG_TIM_THAY", "thongBao": "Không có tài khoản khách này."}
    n = thu_hoi_moi_phien(conn, acc["id"], "CRM thu hồi: " + str(data.get("reason") or "")[:150])
    _ghi_audit(conn, "crm", "khach.thu_hoi", target_id=subject,
               detail={"reason": str(data.get("reason") or "")[:200], "phien": n}, request=request)
    return 200, {"subject": subject, "phien_thu_hoi": n}


# ------------------------------------------------------------------ quên / đặt lại mật khẩu
def yeu_cau_khoi_phuc(conn, dinh_danh: str, ip: str, request=None) -> None:
    """Luôn im lặng. Nhận email, SĐT hoặc mã khách."""
    if vuot_tan_suat(conn, "quen_ip", ip, config.KHACH_FORGOT_IP_PER_HOUR, 3600):
        _ghi_audit(conn, "khach:anon", "khach.quen_mat_khau.qua_tan_suat", detail={"ip": ip},
                   request=request)
        return
    em = chuan_hoa_email(dinh_danh)
    if em:
        acc = db.one(conn, "SELECT * FROM customer_accounts WHERE email_norm=?", (em,))
    else:
        acc, _ = _tim_theo_dinh_danh(conn, dinh_danh)
    if not acc or acc["status"] not in ("hoat_dong", "cho_duyet"):
        return
    if vuot_tan_suat(conn, "quen_acc", acc["id"], 3, 3600):
        return
    raw = tao_token(conn, acc["id"], "khoi_phuc")
    gui_email(conn, acc["id"], acc["email_norm"], "khoi_phuc",
              "VIP GROUP — Đặt lại mật khẩu cổng khách hàng",
              f"Chào {acc['display_name']},\n\nBấm liên kết sau để đặt mật khẩu mới (hiệu lực "
              f"{config.KHACH_TOKEN_TTL_MIN} phút, dùng một lần):\n"
              f"{_link('/tai-khoan/dat-lai?t=' + raw)}" + _CHAN_THU)
    _ghi_audit(conn, acc["subject"], "khach.quen_mat_khau", target_id=acc["subject"],
               request=request)


def dat_lai_mat_khau(conn, raw: str | None, mat_khau: str, mat_khau_2: str,
                     request=None) -> dict:
    tk = xem_token(conn, raw, "khoi_phuc")
    if not tk:
        raise KhachLoi("Liên kết đặt lại mật khẩu không hợp lệ, đã dùng hoặc đã hết hạn.", 400,
                       "TOKEN_SAI")
    acc = tai_khoan(conn, tk["account_id"])
    loi = security.kiem_tra_do_manh(mat_khau or "", (acc or {}).get("phone_e164", "")[3:],
                                    min_len=config.KHACH_PASSWORD_MIN)
    if loi:
        raise KhachLoi(loi)
    if mat_khau != mat_khau_2:
        raise KhachLoi("Hai lần nhập mật khẩu không khớp.")
    acc_id = tieu_token(conn, raw, "khoi_phuc")
    if not acc_id or acc_id != tk["account_id"]:
        raise KhachLoi("Liên kết đặt lại mật khẩu không hợp lệ, đã dùng hoặc đã hết hạn.", 400,
                       "TOKEN_SAI")
    hash_b64, salt_b64 = security.bam_mat_khau(mat_khau)
    now = db.now_iso()
    conn.execute("UPDATE customer_accounts SET password_hash=?, password_salt=?, "
                 "token_version=token_version+1, failed_attempts=0, locked_until=NULL, "
                 "updated_at=? WHERE id=?", (hash_b64, salt_b64, now, acc_id))
    conn.execute("UPDATE customer_tokens SET used_at=? WHERE account_id=? AND purpose='khoi_phuc' "
                 "AND used_at IS NULL", (now, acc_id))
    # Đặt lại thành công ⇒ xoá bộ đếm sai của tài khoản (mọi IP).
    conn.execute("DELETE FROM customer_login_attempts WHERE account_key=? AND success=0", (acc_id,))
    conn.commit()
    n = thu_hoi_moi_phien(conn, acc_id, "Đặt lại mật khẩu")
    acc = tai_khoan(conn, acc_id)
    _ghi_audit(conn, acc["subject"], "khach.dat_lai_mat_khau", target_id=acc["subject"],
               detail={"phien_thu_hoi": n}, request=request)
    gui_email(conn, acc_id, acc["email_norm"], "doi_mat_khau",
              "VIP GROUP — Mật khẩu của bạn vừa được đổi",
              "Mật khẩu cổng khách hàng VIP GROUP vừa được đặt lại và mọi phiên đăng nhập đã bị "
              "đăng xuất. Nếu không phải bạn, hãy liên hệ VIP GROUP ngay." + _CHAN_THU)
    bao_crm_thu_hoi(conn, acc["subject"], "dat_lai_mat_khau")
    return acc
