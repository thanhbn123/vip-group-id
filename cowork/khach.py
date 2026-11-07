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
import threading
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
COOKIE_THIET_BI = "vg_khach_tb"
COOKIE_PATH = "/tai-khoan"
#: Mã khách VG + số ≥ 1001, không số 0 đầu, 4–9 chữ số (VG1001, VG1002, … VG10000, …).
PORTAL_CODE_RE = re.compile(r"^VG([1-9][0-9]{3,8})$")
PORTAL_CODE_MIN = 1001
EMAIL_RE = re.compile(r"^[^@\s<>\"'(),;:\\]{1,64}@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                      r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")
#: Kênh gửi email đã cài thật. Hiện CHƯA có kênh nào ⇒ production luôn bị chặn (A8).
KENH_EMAIL_THAT: set[str] = set()
#: Sau ngần này lần sai (mọi IP cộng lại) trong cửa sổ thì bắt đầu làm chậm.
LAM_CHAM_SAU = 10

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


class KhachPilot(KhachLoi):
    """Đang chạy thử nội bộ: SĐT/tài khoản không thuộc danh sách pilot."""


THONG_BAO_PILOT = ("Cổng khách hàng VIP GROUP đang chạy thử nội bộ, sẽ mở sớm. "
                   "Liên hệ hotline/Zalo {hotline}.")


# ------------------------------------------------------------------ pilot (danh sách trắng)
_pilot_cache: dict = {"khoa": None, "ds": frozenset()}


def _doc_tep_pilot() -> frozenset:
    """Đọc tệp pilot (mỗi dòng một SĐT, '#' là chú thích); chỉ đọc lại khi tệp đổi (mtime/size)."""
    p = config.KHACH_PILOT_FILE
    try:
        st = p.stat()
    except OSError:
        _pilot_cache.update(khoa=None, ds=frozenset())
        return frozenset()
    khoa = (str(p), st.st_mtime_ns, st.st_size)
    if _pilot_cache["khoa"] != khoa:
        ds = set()
        for dong in p.read_text(encoding="utf-8").splitlines():
            dong = dong.split("#", 1)[0].strip()
            ph = chuan_hoa_sdt(dong)
            if ph:
                ds.add(ph)
        _pilot_cache.update(khoa=khoa, ds=frozenset(ds))
    return _pilot_cache["ds"]


def ds_pilot() -> dict[str, str]:
    """{sđt E.164: nguồn ('env'|'tep')}."""
    kq = {ph: "tep" for ph in _doc_tep_pilot()}
    for raw in config.KHACH_PILOT_PHONES:
        ph = chuan_hoa_sdt(raw)
        if ph:
            kq[ph] = "env"
    return kq


def pilot_cho_phep(phone: str | None) -> bool:
    """Pilot tắt ⇒ luôn cho. Bật ⇒ chỉ SĐT trong danh sách (env ∪ tệp)."""
    if not config.KHACH_PILOT:
        return True
    return bool(phone) and phone in ds_pilot()


def chan_pilot(phone: str | None) -> None:
    if not pilot_cho_phep(phone):
        raise KhachPilot(THONG_BAO_PILOT.format(hotline=config.KHACH_HOTLINE), 403, "PILOT")


def sua_tep_pilot(phone_raw: str, them: bool, actor: str = "cli") -> tuple[bool, str]:
    """Thêm/bớt một SĐT trong tệp pilot (ghi nguyên tử, 0600) + audit. Trả (đổi?, sđt)."""
    import os
    ph = chuan_hoa_sdt(phone_raw)
    if not ph:
        raise ValueError("SĐT không hợp lệ.")
    p = config.KHACH_PILOT_FILE
    hien = set(_doc_tep_pilot())
    if (ph in hien) == them:
        return False, ph
    hien = hien | {ph} if them else hien - {ph}
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tam = p.with_name(p.name + ".tmp")
    fd = os.open(str(tam), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("# Danh sách SĐT pilot cổng khách hàng (quản lý bằng cowork.cli khach-pilot)\n")
        for x in sorted(hien):
            fh.write(x + "\n")
    os.replace(tam, p)
    _pilot_cache.update(khoa=None)
    conn = db.connect()
    try:
        _ghi_audit(conn, actor, "khach.pilot.them" if them else "khach.pilot.bot",
                   target_id=ph, detail={"phone": che_sdt(ph)})
    finally:
        conn.close()
    return True, ph


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


ENV_HOP_LE = {"local", "dev", "development", "test", "staging", "prod", "production"}


def realm_bat() -> bool:
    """Realm khách thực sự phục vụ: cờ bật VÀ DB realm khách sẵn sàng (nâng cấp không lỗi)."""
    return config.KHACH_ENABLED and not db.KHACH_LOI


def la_production() -> bool:
    return config.ENV.strip().lower() in ("prod", "production")


def kiem_cau_hinh() -> None:
    """Gọi lúc khởi động. Realm bật mà cấu hình không an toàn ⇒ RuntimeError (từ chối chạy)."""
    if not config.KHACH_ENABLED:
        return
    loi: list[str] = []
    env = config.ENV.strip().lower()
    if env not in ENV_HOP_LE:
        loi.append(f"COWORK_ENV={config.ENV!r} không hợp lệ (cho phép: {sorted(ENV_HOP_LE)}).")
    if (la_production() and config.KHACH_EMAIL_ENABLED
            and config.KHACH_MAIL_TRANSPORT not in KENH_EMAIL_THAT):
        loi.append("A8: production bật COWORK_KHACH_EMAIL_ENABLED=1 nhưng chưa có kênh gửi email "
                   f"thật (COWORK_KHACH_MAIL_TRANSPORT={config.KHACH_MAIL_TRANSPORT!r}).")
    if not host_khach():
        loi.append("Chưa có host realm khách (COWORK_KHACH_HOSTS hoặc COWORK_KHACH_HOST_DANGKY/"
                   "COWORK_KHACH_HOST_DANGNHAP).")
    if not host_nhan_vien():
        loi.append("Không xác định được host nhân viên (COWORK_STAFF_HOSTS).")
    if la_production():
        if config.KHACH_PILOT_RAW not in ("0", "1"):
            loi.append("Production bật realm khách phải đặt tường minh COWORK_KHACH_PILOT=0 hoặc 1 "
                       "(quyết định có chạy thử giới hạn hay không).")
        if not config.TIN_PROXY:
            loi.append("Production bật realm khách phải chạy sau Caddy với COWORK_TIN_PROXY=1 "
                       "(IP thật cho giới hạn tần suất, X-Forwarded-Proto cho https).")
        if not config.COOKIE_SECURE:
            loi.append("Production bật realm khách phải đặt COWORK_COOKIE_SECURE=1.")
        if not turnstile_bat():
            loi.append("Production bật realm khách phải cấu hình Cloudflare Turnstile "
                       "(COWORK_KHACH_TURNSTILE_SITE_KEY + secret) cho thử thách đăng nhập.")
        elif (config.KHACH_TURNSTILE_SITE_KEY in TURNSTILE_KHOA_THU
              or turnstile_secret() in TURNSTILE_KHOA_THU):
            loi.append("Production không được dùng khoá Turnstile thử nghiệm của Cloudflare.")
    if not config.STAFF_HOSTS:
        if la_production():
            loi.append("COWORK_STAFF_HOSTS chưa đặt — production bắt buộc khai báo danh sách "
                       "trắng host nhân viên khi bật realm khách.")
        else:
            log.warning("CANH_BAO CAU HINH: realm khách BẬT nhưng COWORK_STAFF_HOSTS chưa đặt — "
                        "đang suy ra host nhân viên từ COWORK_PUBLIC_URL/INTERNAL_URL: %s. "
                        "Hãy đặt COWORK_STAFF_HOSTS tường minh (production sẽ từ chối khởi động).",
                        ", ".join(host_nhan_vien()) or "(rỗng)")
    # So TÊN host (bỏ cổng): cookie không tách theo cổng.
    ten_kh = {_ten_host(h) for h in host_khach()}
    ten_nv = {_ten_host(h) for h in host_nhan_vien()}
    if ten_kh & ten_nv:
        loi.append("COWORK_KHACH_HOSTS trùng tên host nhân viên: " + ", ".join(sorted(ten_kh & ten_nv)))
    bi_mat = portal_secret()
    if len(bi_mat.encode("utf-8")) < 32:
        loi.append("VIPID_PORTAL_SECRET phải dài ít nhất 32 byte.")
    import os
    khac = [config.BRAIN_SHARED_SECRET, config.SECRET_KEY, config.HATANG_SHARED_SECRET,
            os.environ.get("VIPID_SHARED_SECRET", ""), os.environ.get("COWORK_SHARED_SECRET", "")]
    if any(k and hmac.compare_digest(k, bi_mat) for k in khac):
        loi.append("VIPID_PORTAL_SECRET phải KHÁC mọi bí mật khác (Brain, phiên, hạ tầng).")
    if la_production():
        for ten, url in (("CRM_PORTAL_PUBLIC_URL", config.CRM_PORTAL_PUBLIC_URL),
                         ("COWORK_KHACH_PUBLIC_URL", config.KHACH_PUBLIC_URL),
                         ("URL dangky", url_dangky()), ("URL dangnhap", url_dangnhap()),
                         *(("COWORK_KHACH_TIEP_CHO_PHEP", u) for u in ds_tiep_cho_phep())):
            if not url.startswith("https://"):
                loi.append(f"{ten} phải là https ở production.")
    if loi:
        raise RuntimeError("Realm khách bị chặn: " + " | ".join(loi))


_HOST_RE = re.compile(r"^(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(:\d{1,5})?$")


def chuan_hoa_host(host: str | None) -> str | None:
    """Chữ thường, bỏ dấu chấm cuối tên, cổng bỏ số 0 đầu. Sai cú pháp ⇒ None."""
    h = (host or "").strip().lower()
    m = _HOST_RE.match(h)
    if not m:
        return None
    ten = m.group(1)
    if not ten.startswith("["):
        ten = ten.rstrip(".")
        if not ten or ".." in ten:
            return None
    cong = m.group(2)
    if cong:
        n = int(cong[1:])
        if not 0 < n < 65536:
            return None
        return f"{ten}:{n}"
    return ten


_CO_CONG = re.compile(r"(^[^:\[]+|\]):\d+$")


def _ten_host(h: str) -> str:
    return h.rsplit(":", 1)[0] if _CO_CONG.search(h) else h


def host_khach() -> list[str]:
    ds = list(config.KHACH_HOSTS) + [h for h in (config.KHACH_HOST_DANGKY,
                                                 config.KHACH_HOST_DANGNHAP) if h]
    return [x for x in (chuan_hoa_host(h) for h in ds) if x]


def vai_tro_host(host: str | None) -> str | None:
    """'dangky' | 'dangnhap' | 'tat_ca' (chế độ một host cũ) | None (không phải host khách)."""
    h = chuan_hoa_host(host)
    if not h:
        return None
    for vai, cau_hinh in (("dangky", config.KHACH_HOST_DANGKY),
                          ("dangnhap", config.KHACH_HOST_DANGNHAP)):
        x = chuan_hoa_host(cau_hinh) if cau_hinh else None
        if x and _khop(h, [x]):
            return vai
    ds = [x for x in (chuan_hoa_host(e) for e in config.KHACH_HOSTS) if x]
    return "tat_ca" if _khop(h, ds) else None


def _url_host(url_cau_hinh: str, host: str) -> str:
    if url_cau_hinh:
        return url_cau_hinh
    if host:
        return f"{'https' if la_production() else 'http'}://{host}"
    return config.KHACH_PUBLIC_URL


def url_dangky() -> str:
    return _url_host(config.KHACH_DANGKY_URL, config.KHACH_HOST_DANGKY)


def url_dangnhap() -> str:
    return _url_host(config.KHACH_DANGNHAP_URL, config.KHACH_HOST_DANGNHAP)


def ds_tiep_cho_phep() -> list[str]:
    return config.KHACH_TIEP_CHO_PHEP or [config.CRM_PORTAL_PUBLIC_URL + "/portal"]


_TIEP_MA_HOA_CAM = re.compile(r"%(2f|5c|2e|00|09|0a|0d|20|40)", re.I)


def kiem_tiep(raw: str | None) -> str | None:
    """Kiểm `tiep` (URL tuyệt đối) theo danh sách cho phép; trả ĐƯỜNG DẪN (path) hoặc None.

    Chặn open-redirect: chỉ https (http chỉ ngoài production), đúng host (không userinfo, không
    cổng lạ, không dấu chấm cuối), path bắt đầu bằng path cho phép (theo ranh giới '/'), không
    '\\', '//', '.'/'..', ký tự điều khiển hay mã hoá đánh lừa (%2F %5C %2E %00 …)."""
    if not raw or len(raw) > 2000:
        return None
    if any(ord(c) < 0x21 or ord(c) == 0x7F or c == "\\" for c in raw):
        return None
    try:
        u = urlsplit(raw)
    except ValueError:
        return None
    if u.scheme not in ("https", "http") or (u.scheme == "http" and la_production()):
        return None
    if not raw.lower().startswith(u.scheme + "://"):
        return None
    if "@" in u.netloc or "%" in u.netloc or not u.netloc:
        return None
    path = u.path
    if (not path.startswith("/") or "//" in path or _TIEP_MA_HOA_CAM.search(path)
            or any(seg in (".", "..") for seg in path.split("/"))):
        return None
    for cho in ds_tiep_cho_phep():
        try:
            a = urlsplit(cho)
        except ValueError:
            continue
        if u.scheme != a.scheme or u.netloc.lower() != a.netloc.lower():
            continue
        goc = a.path.rstrip("/")
        if path == goc or path.startswith(goc + "/"):
            return path
    return None


def host_nhan_vien() -> list[str]:
    ds = config.STAFF_HOSTS or [_host_cua_url(config.PUBLIC_URL), _host_cua_url(config.INTERNAL_URL)]
    return [x for x in (chuan_hoa_host(h) for h in ds) if x]


def _khop(h: str, ds: list[str]) -> bool:
    # Mục có cổng ⇒ khớp đúng host:cổng; mục không cổng ⇒ khớp tên host với mọi cổng.
    return any(h == e or (not _CO_CONG.search(e) and _ten_host(h) == e) for e in ds)


def chon_realm(host: str | None) -> str | None:
    """'khach' | 'staff' | None (Host lạ/thiếu/sai ⇒ không phục vụ)."""
    h = chuan_hoa_host(host)
    if not h:
        return None
    if _khop(h, host_khach()):
        return "khach"
    if _khop(h, host_nhan_vien()):
        return "staff"
    return None


def la_host_khach(host: str | None) -> bool:
    return chon_realm(host) == "khach"


def khoa_ip(ip: str | None) -> str:
    """Khoá IP cho giới hạn tần suất/khoá: IPv4 giữ nguyên; IPv4-mapped IPv6 ⇒ IPv4;
    IPv6 gộp theo /64 (một khách hàng/thuê bao thường nắm cả /64)."""
    import ipaddress
    try:
        a = ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return (ip or "?")[:64]
    if a.version == 6:
        if a.ipv4_mapped:
            return str(a.ipv4_mapped)
        return str(ipaddress.ip_network(f"{a}/64", strict=False))
    return str(a)


# ------------------------------------------------------------------ Turnstile
def turnstile_secret() -> str:
    import os
    v = os.environ.get("COWORK_KHACH_TURNSTILE_SECRET", "").strip()
    if v:
        return v
    try:
        return config.KHACH_TURNSTILE_SECRET_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def turnstile_bat() -> bool:
    return bool(config.KHACH_TURNSTILE_SITE_KEY and turnstile_secret())


#: Khoá thử nghiệm Cloudflare (luôn qua) — CHỈ dùng trong test/dev.
TURNSTILE_KHOA_THU = ("1x00000000000000000000AA", "1x0000000000000000000000000000000AA",
                      "2x00000000000000000000AB", "3x00000000000000000000FF",
                      "2x0000000000000000000000000000000AA")
TURNSTILE_ACTION = "khach_login"


TURNSTILE_ACTION_DANG_KY = "khach_dang_ky"


def ket_qua_turnstile_hop_le(kq: dict | None, host: str | None,
                             action: str = TURNSTILE_ACTION) -> bool:
    """Kiểm phản hồi siteverify: success, action đúng, hostname khớp host khách đang phục vụ."""
    if not isinstance(kq, dict) or kq.get("success") is not True:
        return False
    if kq.get("action") != action:
        return False
    h = chuan_hoa_host(host)
    ten = _ten_host(h) if h else None
    return bool(ten) and str(kq.get("hostname") or "").lower().rstrip(".") == ten


# ------------------------------------------------------------------ scrypt realm khách
_scrypt_sem = threading.BoundedSemaphore(max(1, config.KHACH_SCRYPT_DONG_THOI))
SCRYPT_CHO_TOI_DA_GIAY = 2.0


class HeThongBan(Exception):
    """Quá tải băm mật khẩu ⇒ 503 (không xếp hàng vô hạn, không chiếm luồng của realm khác)."""
_SALT_GIA_KHACH = b"vipid-khach-gia1"


def _algo_moi() -> str:
    return f"scrypt:n={2 ** config.KHACH_SCRYPT_LOG2_N},r=8,p=1"


def _tham_so(algo: str | None) -> tuple[int, int, int]:
    m = re.fullmatch(r"scrypt:n=(\d+),r=(\d+),p=(\d+)", algo or "")
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return 2 ** 14, 8, 1  # 'scrypt' cũ = tham số của security.bam_mat_khau


def _scrypt(mat_khau: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    if not _scrypt_sem.acquire(timeout=SCRYPT_CHO_TOI_DA_GIAY):
        raise HeThongBan()
    try:
        return hashlib.scrypt(mat_khau.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32,
                              maxmem=256 * 1024 * 1024)
    finally:
        _scrypt_sem.release()


def bam_mk(mat_khau: str) -> tuple[str, str, str]:
    algo = _algo_moi()
    n, r, p = _tham_so(algo)
    salt = secrets.token_bytes(16)
    return (base64.b64encode(_scrypt(mat_khau, salt, n, r, p)).decode("ascii"),
            base64.b64encode(salt).decode("ascii"), algo)


def bam_gia(mat_khau: str) -> None:
    n, r, p = _tham_so(_algo_moi())
    _scrypt(mat_khau or "", _SALT_GIA_KHACH, n, r, p)


def kiem_mk(mat_khau: str, acc: dict | None) -> bool:
    if not acc or not acc.get("password_hash") or not acc.get("password_salt"):
        bam_gia(mat_khau)
        return False
    try:
        n, r, p = _tham_so(acc.get("password_algo"))
        d = _scrypt(mat_khau, base64.b64decode(acc["password_salt"]), n, r, p)
        return hmac.compare_digest(base64.b64encode(d).decode("ascii"), acc["password_hash"])
    except (ValueError, TypeError):
        return False


# ------------------------------------------------------------------ CSRF ký + thiết bị tin cậy
def _ky(muc_dich: str, du_lieu: str) -> str:
    return hmac.new(config.SECRET_KEY.encode("utf-8"), f"{muc_dich}.{du_lieu}".encode("utf-8"),
                    hashlib.sha256).hexdigest()[:40]


PS_RE = re.compile(r"^[A-Za-z0-9_-]{24,64}$")


def tao_csrf(ps_id: str) -> str:
    """Token CSRF ẩn danh gắn với id tiền-phiên (cookie riêng của trình duyệt này)."""
    ng = security.token_moi(18)
    return f"{ng}.{_ky('khach-csrf', ps_id + '.' + ng)}"


def csrf_hop_le(tok: str | None, ps_id: str | None) -> bool:
    if not tok or not ps_id or not PS_RE.match(ps_id) or len(tok) > 120 or tok.count(".") != 1:
        return False
    ng, sig = tok.split(".")
    return bool(ng) and hmac.compare_digest(_ky("khach-csrf", ps_id + "." + ng), sig)


def tao_thiet_bi(acc: dict) -> str:
    """Cookie thiết bị tin cậy: ký (id tài khoản, token_version, thời điểm, ngẫu nhiên).
    Đặt lại mật khẩu / khoá tài khoản tăng token_version ⇒ mọi cookie cũ mất hiệu lực."""
    du = f"{acc['id']}.{int(acc['token_version'])}.{int(time.time())}.{security.token_moi(9)}"
    return f"{du}.{_ky('khach-thiet-bi', du)}"


def thiet_bi_hop_le(raw: str | None, acc: dict | None) -> bool:
    if not raw or not acc or len(raw) > 200:
        return False
    phan = raw.split(".")
    if len(phan) != 5:
        return False
    du, sig = ".".join(phan[:4]), phan[4]
    if not hmac.compare_digest(_ky("khach-thiet-bi", du), sig) or phan[0] != acc["id"]:
        return False
    try:
        return (int(phan[1]) == int(acc["token_version"])
                and time.time() - int(phan[2]) <= config.KHACH_THIET_BI_NGAY * 86400)
    except (ValueError, TypeError):
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
    m = PORTAL_CODE_RE.match(c)
    return c if m and int(m.group(1)) >= PORTAL_CODE_MIN else None


def _ghi_audit(conn, actor: str, action: str, *, target_id: str | None = None,
               detail: dict | None = None, request=None, lay_mau: str | None = None) -> None:
    """`lay_mau`=khoá (vd IP): sự kiện thất bại/vô danh chỉ ghi tối đa 1 dòng/khoá/phút."""
    if lay_mau is not None:
        try:
            if vuot_tan_suat(conn, "audit:" + action, lay_mau, 1, 60):
                return
        except Exception:  # noqa: BLE001
            return
    try:
        audit.ghi(conn, actor or "khach:anon", action, target_type="customer",
                  target_id=target_id, detail=detail, request=request, tenant_id=TENANT)
    except Exception:  # noqa: BLE001 - audit không được làm hỏng luồng; nhưng phải ghi log
        log.exception("Không ghi được audit %s", action)


def vuot_tan_suat(conn, bucket: str, key: str, toi_da: int, giay: int) -> bool:
    """True nếu đã đủ `toi_da` sự kiện trong `giay` giây; ngược lại ghi thêm một sự kiện.

    Đếm + ghi trong MỘT giao dịch ghi (BEGIN IMMEDIATE) ⇒ nguyên tử giữa các luồng/tiến trình:
    loạt request đồng thời không vượt được ngưỡng."""
    rieng = not conn.in_transaction
    if rieng:
        conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("DELETE FROM customer_rate_events WHERE created_at<?", (_truoc(days=2),))
        n = conn.execute("SELECT COUNT(*) FROM customer_rate_events WHERE bucket=? AND key=? "
                         "AND created_at>=?", (bucket, key, _truoc(seconds=giay))).fetchone()[0]
        vuot = n >= toi_da
        if not vuot:
            conn.execute("INSERT INTO customer_rate_events(bucket, key, created_at) VALUES(?,?,?)",
                         (bucket, key, _iso(_bay_gio())))
        if rieng:
            conn.execute("COMMIT")
        return vuot
    except Exception:
        if rieng and conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def tai_khoan(conn, account_id: str) -> dict | None:
    return db.one(conn, "SELECT * FROM customer_accounts WHERE id=?", (account_id,))


def tai_khoan_theo_subject(conn, subject: str) -> dict | None:
    return db.one(conn, "SELECT * FROM customer_accounts WHERE subject=?", (subject,))


# ------------------------------------------------------------------ outbox email
def gui_email(conn, account_id: str | None, to_email: str | None, kind: str, tieu_de: str,
              noi_dung: str) -> int | None:
    """Chỉ ghi outbox (không gửi thật). Email tắt (mặc định) hoặc khách không có email ⇒ bỏ qua."""
    if not config.KHACH_EMAIL_ENABLED or not to_email:
        return None
    cur = conn.execute(
        "INSERT INTO customer_outbox(account_id, kind, to_email, subject, body_text, created_at) "
        "VALUES(?,?,?,?,?,?)", (account_id, kind, to_email, tieu_de, noi_dung, db.now_iso()))
    conn.commit()
    return int(cur.lastrowid)


def _link(path: str) -> str:
    """Liên kết trong email / link đặt lại: luôn về host đăng nhập."""
    return f"{url_dangnhap()}{path}"


_CHAN_THU = ("\n\n—\nCÔNG TY TNHH VIP GROUP\nEmail tự động, vui lòng không trả lời. "
             "Nếu bạn không thực hiện yêu cầu này, hãy bỏ qua email.")


# ------------------------------------------------------------------ token một lần
def so_token_con_hieu_luc(conn, account_id: str, purpose: str) -> int:
    return int(conn.execute(
        "SELECT COUNT(*) FROM customer_tokens WHERE account_id=? AND purpose=? AND used_at IS NULL "
        "AND expires_at>?", (account_id, purpose, _iso(_bay_gio()))).fetchone()[0])


def tao_token(conn, account_id: str, purpose: str) -> str | None:
    """Phát token mới KHÔNG thu hồi token cũ (kẻ lạ yêu cầu hộ không làm hỏng link của chủ).

    Đã có đủ KHACH_TOKEN_TOI_DA token còn hiệu lực ⇒ không phát thêm (trả None): mọi token
    đều nằm trong hộp thư của chủ tài khoản nên chủ vẫn dùng được link đã nhận.
    """
    if so_token_con_hieu_luc(conn, account_id, purpose) >= config.KHACH_TOKEN_TOI_DA:
        return None
    raw = security.token_moi(32)
    now = _bay_gio()
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
    acc_id = db.scalar(conn, "SELECT account_id FROM customer_tokens WHERE token_hash=?", (h,))
    # Dùng thành công ⇒ vô hiệu mọi token cùng mục đích còn lại.
    conn.execute("UPDATE customer_tokens SET used_at=? WHERE account_id=? AND purpose=? "
                 "AND used_at IS NULL", (_iso(_bay_gio()), acc_id, purpose))
    conn.commit()
    return acc_id


# ------------------------------------------------------------------ đăng ký
def dang_ky(conn, *, ho_ten: str, sdt: str, email: str, mat_khau: str, mat_khau_2: str,
            dong_y: bool, ip: str, request=None) -> None:
    """Owner 07/11: ghi nhận đăng ký NGAY ở `cho_duyet` và gửi signup sang CRM; nhân viên duyệt là
    cổng duy nhất. Email tuỳ chọn (kiểm định dạng nếu có, không unique).

    Ném KhachLoi khi dữ liệu SAI ĐỊNH DẠNG. SĐT đã tồn tại ⇒ không tạo, phản hồi y hệt
    (không lộ tài khoản), ghi audit và đánh dấu xung đột gửi CRM nếu tài khoản kia đang chờ duyệt.
    """
    ten = chuan_hoa_ten(ho_ten)
    phone = chuan_hoa_sdt(sdt)
    em = None
    if (email or "").strip():
        em = chuan_hoa_email(email)
        if not em:
            raise KhachLoi("Địa chỉ email không hợp lệ (có thể để trống).")
    if not ten:
        raise KhachLoi("Họ tên cần từ 2 đến 100 ký tự.")
    if not phone:
        raise KhachLoi("Số điện thoại di động Việt Nam không hợp lệ (ví dụ 0901 234 567).")
    loi_mk = security.kiem_tra_do_manh(mat_khau or "", phone[3:], min_len=config.KHACH_PASSWORD_MIN)
    if loi_mk:
        raise KhachLoi(loi_mk)
    if mat_khau != mat_khau_2:
        raise KhachLoi("Hai lần nhập mật khẩu không khớp.")
    if not dong_y:
        raise KhachLoi("Bạn cần đồng ý với chính sách bảo mật và điều khoản sử dụng.")
    # Pilot: chỉ SĐT trong danh sách trắng. Quyết định chỉ dựa trên danh sách ⇒ không lộ việc SĐT
    # đã có tài khoản hay chưa; không tạo tài khoản, không gửi CRM.
    chan_pilot(phone)
    if vuot_tan_suat(conn, "dang_ky_ip", ip, config.KHACH_SIGNUP_IP_PER_HOUR, 3600):
        _ghi_audit(conn, "khach:anon", "khach.dang_ky.qua_tan_suat", detail={"ip": ip},
                   request=request, lay_mau=ip)
        raise KhachLoi("Bạn đã gửi quá nhiều yêu cầu đăng ký. Vui lòng thử lại sau.", 429,
                       "QUA_TAN_SUAT")

    if vuot_tan_suat(conn, "dang_ky_toan_cuc", "*", config.KHACH_SIGNUP_GLOBAL_PER_HOUR, 3600):
        if not vuot_tan_suat(conn, "canh_bao_dang_ky", "*", 1, 3600):
            _ghi_audit(conn, "system", "khach.canh_bao.dang_ky_tang_dot_bien",
                       detail={"tran_gio": config.KHACH_SIGNUP_GLOBAL_PER_HOUR}, request=request)
            log.warning("CANH_BAO khach: đăng ký vượt %s/giờ — tạm ngừng nhận",
                        config.KHACH_SIGNUP_GLOBAL_PER_HOUR)
        raise KhachLoi("Hệ thống đang nhận quá nhiều đăng ký. Vui lòng thử lại sau ít phút hoặc "
                       f"liên hệ hotline/Zalo {config.KHACH_HOTLINE}.", 503, "QUA_TAI")

    trung = db.one(conn, "SELECT * FROM customer_accounts WHERE phone_e164=?", (phone,))
    if trung:
        _xu_ly_trung(conn, trung, em, mat_khau, ip, request)
        return

    hash_b64, salt_b64, algo = bam_mk(mat_khau)
    acc_id = "kh_" + _ngau_nhien_26()
    now = db.now_iso()
    try:
        conn.execute(
            "INSERT INTO customer_accounts(id, subject, phone_e164, email_norm, display_name, "
            "password_hash, password_salt, password_algo, status, consent_at, token_version, "
            "failed_attempts, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?, "
            "'cho_duyet', ?, 1, 0, ?, ?)",
            (acc_id, "cust:" + acc_id, phone, em, ten, hash_b64, salt_b64, algo, now, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()  # đua đăng ký cùng SĐT: xử lý như trùng
        return
    acc = tai_khoan(conn, acc_id)
    _ghi_audit(conn, acc["subject"], "khach.dang_ky", target_id=acc["subject"],
               detail={"phone": che_sdt(phone), "email": che_email(em) if em else None},
               request=request)
    _gui_signup(conn, acc)


def _ngau_nhien_26() -> str:
    chu = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(secrets.choice(chu) for _ in range(26))


def _xu_ly_trung(conn, acc: dict, email_moi: str | None, mat_khau: str, ip: str,
                 request) -> None:
    """Trùng SĐT: không tạo, không thông báo ra ngoài. Tài khoản kia đang chờ duyệt ⇒ đánh dấu
    xung đột và gửi lại signup cho CRM để nhân viên kiểm trước khi duyệt (chống giữ chỗ SĐT)."""
    bam_gia(mat_khau)  # cân bằng thời gian với nhánh tạo mới
    _ghi_audit(conn, "khach:anon", "khach.dang_ky.trung", target_id=acc["subject"],
               request=request, lay_mau=f"{ip}:{acc['id']}")
    if acc["status"] not in ("cho_duyet", "cho_xac_minh_email"):
        return
    conn.execute("UPDATE customer_accounts SET phone_conflict_count=phone_conflict_count+1, "
                 "updated_at=? WHERE id=?", (db.now_iso(), acc["id"]))
    conn.commit()
    moi = tai_khoan(conn, acc["id"])
    _ghi_audit(conn, "khach:anon", "khach.dang_ky.xung_dot_sdt", target_id=acc["subject"],
               detail={"lan": moi["phone_conflict_count"],
                       "emailKhac": che_email(email_moi) if email_moi else None}, request=request,
               lay_mau=f"{ip}:{acc['id']}")
    # Gộp: tối đa 1 bản cập nhật xung đột / subject / giờ (số đếm vẫn tăng tại chỗ; lần gửi sau
    # mang số mới nhất).
    if not vuot_tan_suat(conn, "xung_dot_crm", acc["id"], 1, 3600):
        _gui_signup(conn, moi)


def _gui_signup(conn, acc: dict) -> None:
    """Signup sang CRM (ngay khi đăng ký). Mỗi lần số xung đột SĐT tăng ⇒ một bản cập nhật mới
    (CRM upsert theo subject) để nhân viên thấy `phone_conflict` trước khi duyệt. Email có thể null."""
    n = int(acc.get("phone_conflict_count") or 0)
    idem = "signup:" + acc["subject"] + (f":xung-dot-{n}" if n else "")
    xep_hang_crm(conn, "signup", idem, acc["subject"], PATH_SIGNUP, {
        "subject": acc["subject"], "display_name": acc["display_name"],
        "phone_e164": acc["phone_e164"], "email": acc["email_norm"],
        "phone_conflict": n > 0, "phone_conflict_count": n,
    })


# ------------------------------------------------------------------ đăng nhập
def _tim_theo_dinh_danh(conn, dinh_danh: str) -> tuple[dict | None, str]:
    """Trả (account|None, khoá đếm). Định danh: SĐT E.164 hoặc portal_code (VG1001…)."""
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


def dang_gioi_han_toan_cuc(conn, key: str) -> bool:
    """Tài khoản bị dò từ nhiều nơi: >= LAM_CHAM_SAU lượt sai (mọi IP) trong cửa sổ."""
    return _dem_sai(conn, "account_key=?", (key,), config.KHACH_LOGIN_WINDOW_MIN) >= LAM_CHAM_SAU


THONG_BAO_GIOI_HAN = ("Tài khoản này đang tạm giới hạn đăng nhập vì có nhiều lần thử sai. "
                      "Vui lòng thử lại sau {phut} phút trên thiết bị đã dùng trước đây, hoặc "
                      "đặt lại mật khẩu qua email để đăng nhập ngay.")


class ThuThach(KhachLoi):
    """Cần vượt thử thách Turnstile trước khi mật khẩu được kiểm."""


def kiem_chan(conn, dinh_danh: str, ip: str, thiet_bi: str | None = None,
              request=None, turnstile_ok: bool = False) -> tuple[dict | None, str, bool]:
    """Các lớp chặn TRƯỚC khi kiểm mật khẩu — rẻ, KHÔNG băm (chống làm nghẽn bằng lượt bị chặn).

    Phản hồi chặn không phụ thuộc mật khẩu hay việc tài khoản có tồn tại (khoá đếm theo định
    danh đã chuẩn hoá), nên không lộ gì. Trả (acc, key, tin_cay) khi được đi tiếp.
      1. Khoá tạm theo cặp (tài khoản, IP) — áp cho mọi client, kể cả thiết bị tin cậy.
      2. Giới hạn theo IP — miễn cho thiết bị tin cậy của đúng tài khoản (chung NAT).
      3. Giới hạn toàn cục theo tài khoản (mọi IP) — client KHÔNG có cookie thiết bị tin cậy
         nhận 429 giống hệt dù mật khẩu đúng hay sai (không đăng nhập, không lộ đúng/sai).
         Thiết bị tin cậy đi qua. Chủ ở thiết bị mới: đặt lại mật khẩu qua email (xoá bộ đếm).
    """
    w = config.KHACH_LOGIN_WINDOW_MIN
    acc, key = _tim_theo_dinh_danh(conn, dinh_danh)
    # Pilot: chặn trước mọi kiểm tra (không kiểm mật khẩu, không đếm lượt). Quyết định theo SĐT
    # của định danh (hoặc của tài khoản mang mã VG…): mã/SĐT không tồn tại cũng nhận cùng trang.
    if config.KHACH_PILOT:
        chan_pilot(acc["phone_e164"] if acc else chuan_hoa_sdt(dinh_danh))
    actor = acc["subject"] if acc else "khach:anon"
    tin_cay = thiet_bi_hop_le(thiet_bi, acc)
    if _dem_sai(conn, "account_key=? AND ip=?", (key, ip), w) >= config.KHACH_LOGIN_MAX_FAIL:
        _ghi_audit(conn, actor, "khach.dang_nhap.khoa_cap_ip", detail={"ip": ip}, request=request,
                   lay_mau=f"{ip}:{key}")
        raise KhachLoi(THONG_BAO_TAM_KHOA.format(phut=config.KHACH_LOCK_MIN), 429, "TAM_KHOA")
    if not tin_cay and _dem_sai(conn, "ip=?", (ip,), w) >= config.KHACH_LOGIN_IP_MAX_FAIL:
        _ghi_audit(conn, actor, "khach.dang_nhap.chan_ip", detail={"ip": ip}, request=request,
                   lay_mau=ip)
        raise KhachLoi("Quá nhiều lần đăng nhập sai từ mạng của bạn. Vui lòng thử lại sau "
                       f"{w} phút.", 429, "QUA_TAN_SUAT")
    if not tin_cay and dang_gioi_han_toan_cuc(conn, key):
        if turnstile_bat():
            # Thiết bị mới của chủ tài khoản: vượt thử thách thì mới kiểm mật khẩu
            # (lượt sai vẫn được đếm). Không vượt ⇒ cùng một trang thử thách, không lộ gì.
            if turnstile_ok:
                return acc, key, tin_cay
            _ghi_audit(conn, actor, "khach.dang_nhap.thu_thach", detail={"ip": ip},
                       request=request, lay_mau=f"{ip}:{key}")
            raise ThuThach("Vì có nhiều lần đăng nhập sai vào tài khoản này, vui lòng xác nhận "
                           "bạn không phải máy rồi đăng nhập lại.", 429, "THU_THACH")
        _ghi_audit(conn, actor, "khach.dang_nhap.gioi_han_toan_cuc", detail={"ip": ip},
                   request=request, lay_mau=f"{ip}:{key}")
        raise KhachLoi(THONG_BAO_GIOI_HAN.format(phut=w), 429, "GIOI_HAN")
    return acc, key, tin_cay


def dang_nhap(conn, dinh_danh: str, mat_khau: str, ip: str, request=None,
              thiet_bi: str | None = None, turnstile_ok: bool = False) -> dict:
    """Trả account khi được phép đăng nhập. Ném KhachLoi/ChoDuyet nếu không (xem kiem_chan)."""
    w = config.KHACH_LOGIN_WINDOW_MIN
    mat_khau = mat_khau or ""
    acc, key, _tin_cay = kiem_chan(conn, dinh_danh, ip, thiet_bi, request, turnstile_ok)
    actor = acc["subject"] if acc else "khach:anon"

    hop_le = kiem_mk(mat_khau, acc)
    if not hop_le:
        _ghi_lan(conn, key, ip, False)
        if acc:
            conn.execute("UPDATE customer_accounts SET failed_attempts=failed_attempts+1 "
                         "WHERE id=?", (acc["id"],))
            conn.commit()
        n_tk = _dem_sai(conn, "account_key=?", (key,), w)
        _ghi_audit(conn, actor, "khach.dang_nhap.sai", detail={"ip": ip, "lan": n_tk},
                   request=request, lay_mau=f"{ip}:{key}")
        if n_tk == LAM_CHAM_SAU:
            # Sự kiện để cảnh báo: tài khoản bị dò từ nhiều nơi.
            _ghi_audit(conn, actor, "khach.canh_bao.do_mat_khau", detail={"lan": n_tk},
                       request=request)
            log.warning("CANH_BAO khach: tài khoản %s bị dò mật khẩu (%s lần/%s phút)",
                        actor, n_tk, w)
        raise KhachLoi(THONG_BAO_SAI, 401, "SAI_THONG_TIN")

    # Mật khẩu đúng ⇒ có thể nói trạng thái cho chính chủ.
    if acc["status"] in ("cho_duyet", "cho_xac_minh_email") or (acc["status"] == "hoat_dong"
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
    if acc.get("password_algo") != _algo_moi():  # nâng tham số băm khi đăng nhập đúng
        h, sa, al = bam_mk(mat_khau)
        conn.execute("UPDATE customer_accounts SET password_hash=?, password_salt=?, "
                     "password_algo=? WHERE id=?", (h, sa, al, acc["id"]))
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
    rv_ms = moc_thu_hoi(conn, acc["id"], session_id=ctx["session"]["id"], ly_do="Khách đăng xuất")
    bao_crm_thu_hoi(conn, acc["subject"], "dang_xuat", rv_ms)
    _ghi_audit(conn, acc["subject"], "khach.dang_xuat", target_id=acc["subject"], request=request)


# ------------------------------------------------------------------ launch token (HS256)
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def phat_launch_token(conn, acc: dict, request=None, session_id: str | None = None) -> str:
    """Phát launch token. Gán iat_ms NGUYÊN TỬ (một giao dịch ghi, một UPDATE…RETURNING):
    iat_ms = MAX(launch_at_ms cũ, revoked_at_ms + 1, now) — luôn > lần thu hồi đã ghi. Có
    `session_id` ⇒ kiểm phiên VIP ID còn sống TRONG CÙNG giao dịch: đăng xuất (cũng một giao dịch,
    ghi revoked_at_ms + thu hồi phiên) hoặc xảy ra trước ⇒ từ chối, hoặc sau ⇒ revoked_at_ms >
    iat_ms ⇒ CRM từ chối token. Không có khe đọc-rồi-ghi."""
    if acc["status"] != "hoat_dong" or not acc["phone_verified_at"] or not acc["crm_customer_id"]:
        raise KhachLoi("Tài khoản chưa được kích hoạt.", 403, "KHONG_DUOC_PHEP")
    now = _ms_hien_tai()
    tran = now + MOC_TRAN_MS
    conn.execute("BEGIN IMMEDIATE")
    try:
        if session_id is not None and not conn.execute(
                "SELECT 1 FROM customer_sessions WHERE id=? AND account_id=? AND status='active'",
                (session_id, acc["id"])).fetchone():
            conn.execute("ROLLBACK")
            raise KhachLoi("Phiên đăng nhập đã kết thúc. Vui lòng đăng nhập lại.", 401, "HET_PHIEN")
        row = conn.execute(
            "UPDATE customer_accounts SET launch_at_ms = MIN(MAX(COALESCE(launch_at_ms, 0), "
            "COALESCE(revoked_at_ms, 0) + 1, ?), ?) WHERE id=? AND status='hoat_dong' "
            "RETURNING launch_at_ms", (now, tran, acc["id"])).fetchone()
        if not row:
            conn.execute("ROLLBACK")
            raise KhachLoi("Tài khoản chưa được kích hoạt.", 403, "KHONG_DUOC_PHEP")
        conn.execute("COMMIT")
    except KhachLoi:
        raise
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    iat_ms = int(row[0])
    if iat_ms >= tran:
        _canh_bao_dong_ho(conn, acc["subject"], "launch_at_ms", iat_ms, now)
    iat = iat_ms // 1000
    payload = {
        "ver": 1, "aud": AUD_LAUNCH, "sub": acc["subject"],
        "crm_customer_id": acc["crm_customer_id"], "portal_code": acc["portal_code"],
        "iat": iat, "iat_ms": iat_ms, "exp": iat + max(1, config.KHACH_LAUNCH_TTL),
        "nonce": security.token_moi(18),
    }
    header = {"alg": "HS256", "typ": "JWT"}
    phan = (_b64u(json.dumps(header, separators=(",", ":")).encode()) + "."
            + _b64u(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()))
    sig = hmac.new(portal_secret().encode("utf-8"), phan.encode("ascii"), hashlib.sha256).digest()
    _ghi_audit(conn, acc["subject"], "khach.launch", target_id=acc["subject"],
               detail={"nonceHash": security.sha256(payload["nonce"])[:16]}, request=request)
    return phan + "." + _b64u(sig)


def url_launch(token: str, tiep: str | None = None) -> str:
    """`tiep` (đã qua kiem_tiep) chỉ là ĐƯỜNG DẪN; CRM tự quyết có dùng hay không."""
    from urllib.parse import quote
    url = f"{config.CRM_PORTAL_PUBLIC_URL}/portal/auth/launch?token={token}"
    return url + ("&tiep=" + quote(tiep, safe="/") if tiep else "")


# ------------------------------------------------------------------ HMAC VIP ID ⇄ CRM
def chuoi_ky(direction: str, method: str, path: str, ts: str, body: bytes) -> bytes:
    """Chuỗi ký chuẩn: "<direction>.<METHOD>.<path>.<ts>." + body (gắn chữ ký với đúng
    phương thức và đường dẫn — chữ ký cho /thu-hoi không dùng được ở /tam-khoa)."""
    return f"{direction}.{method.upper()}.{path}.{ts}.".encode("utf-8") + body


def ky_portal(direction: str, method: str, path: str, body: bytes,
              ts: int | None = None) -> dict[str, str]:
    t = str(int(time.time()) if ts is None else ts)
    sig = hmac.new(portal_secret().encode("utf-8"), chuoi_ky(direction, method, path, t, body),
                   hashlib.sha256).hexdigest()
    return {"X-Portal-Ts": t, "X-Portal-Sig": sig}


def xac_thuc_vao(conn, method: str, path: str, ts: str | None, sig: str | None,
                 body: bytes) -> str:
    """HMAC chiều CRM → VIP ID, lệch ±300 giây, mỗi chữ ký chỉ dùng MỘT lần.

    Trả 'ok' | 'sai' (chữ ký sai/thiếu/hết hạn) | 'phat_lai' (đúng nhưng đã dùng).
    """
    sig = (sig or "").strip().lower()
    ts = (ts or "").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", sig) or not re.fullmatch(r"\d{1,12}", ts):
        return "sai"
    if abs(time.time() - int(ts)) > 300:
        return "sai"
    mong = hmac.new(portal_secret().encode("utf-8"), chuoi_ky(HUONG_VAO, method, path, ts, body),
                    hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mong, sig):
        return "sai"
    conn.execute("DELETE FROM customer_hmac_seen WHERE ts<?", (int(time.time()) - 900,))
    try:
        conn.execute("INSERT INTO customer_hmac_seen(sig, ts, created_at) VALUES(?,?,?)",
                     (sig, int(ts), db.now_iso()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.rollback()
        _ghi_audit(conn, "crm", "khach.hmac.phat_lai", detail={"sig": sig[:16]}, lay_mau="crm")
        return "phat_lai"
    return "ok"


def _http_post(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str]:
    """Điểm gửi HTTP duy nhất (test thay thế). Trả (status, mô tả)."""
    import httpx
    t = config.CRM_PORTAL_TIMEOUT
    r = httpx.post(url, content=body, headers=headers,
                   timeout=httpx.Timeout(connect=t, read=t, write=t, pool=t))
    return r.status_code, r.text[:200]


def xep_hang_crm(conn, kind: str, idem_key: str, subject: str, path: str, payload: dict,
                 gui_ngay: bool = False) -> int:
    """CHỈ xếp hàng. Gửi do vòng nền (`khach_web.vong_dong_bo_crm`) hoặc CLI `khach-dong-bo`:
    request không bao giờ chờ CRM (không lộ nhánh qua thời gian phản hồi, không treo khi CRM chậm)."""
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


def crm_lease_giay() -> float:
    """Thời hạn nhận dòng: max(60, 2×timeout + 10) — luôn dài hơn hạn chót mỗi lần gửi."""
    return max(60.0, 2 * config.CRM_PORTAL_TIMEOUT + 10)


def crm_han_chot_giay() -> float:
    """Hạn chót CỨNG cho một lần gửi (mọi pha: kết nối, ghi, đọc, chờ pool), ngắn hơn lease."""
    return 2 * config.CRM_PORTAL_TIMEOUT + 2


_crm_pool = None


def _gui_co_han(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, str]:
    """Gọi `_http_post` với hạn chót tổng; quá hạn ⇒ TimeoutError (dòng được thử lại sau;
    CRM idempotent theo Idempotency-Key nên lỡ đã tới nơi cũng không sao)."""
    global _crm_pool
    from concurrent.futures import ThreadPoolExecutor, TimeoutError as _FutTimeout
    if _crm_pool is None:
        _crm_pool = ThreadPoolExecutor(max_workers=4, thread_name_prefix="khach-crm")
    fut = _crm_pool.submit(_http_post, url, body, headers)
    try:
        return fut.result(timeout=crm_han_chot_giay())
    except _FutTimeout:
        fut.cancel()
        raise TimeoutError(f"CRM quá hạn chót {crm_han_chot_giay():.1f}s") from None


def _nhan_dong(conn, row_id: int) -> bool:
    """Nhận (claim) NGUYÊN TỬ một dòng trước khi gửi: chỉ một lượt (vòng nền, CLI, tiến trình
    khác) gửi được mỗi dòng trong thời hạn lease ⇒ không gửi trùng."""
    now = _bay_gio()
    cur = conn.execute(
        "UPDATE crm_sync_pending SET claimed_until=? WHERE id=? AND done_at IS NULL "
        "AND (claimed_until IS NULL OR claimed_until<?)",
        (_iso(now + timedelta(seconds=crm_lease_giay())), row_id, _iso(now)))
    conn.commit()
    return cur.rowcount == 1


def thu_gui(conn, row_id: int) -> bool:
    """Gửi một dòng hàng đợi nếu nhận được nó. Trả True chỉ khi CHÍNH lượt này gửi thành công."""
    return _nhan_dong(conn, row_id) and _gui_da_nhan(conn, row_id)


def _gui_da_nhan(conn, row_id: int) -> bool:
    """Gửi một dòng mà lượt hiện tại ĐÃ nhận (claim)."""
    row = db.one(conn, "SELECT * FROM crm_sync_pending WHERE id=?", (row_id,))
    if not row or row["done_at"]:
        return False
    body = row["body"].encode("utf-8")
    headers = {"Content-Type": "application/json", "Idempotency-Key": row["idem_key"],
               **ky_portal(HUONG_RA, "POST", row["path"], body)}
    try:
        status, mo_ta = _gui_co_han(config.CRM_PORTAL_INTERNAL_URL + row["path"], body, headers)
        ok = 200 <= status < 300 or status == 409  # 409 = CRM đã có (idempotent)
        loi = None if ok else f"HTTP {status}: {mo_ta}"
    except Exception as exc:  # noqa: BLE001 - CRM lỗi mạng ⇒ để lại hàng đợi
        ok, loi = False, f"{type(exc).__name__}: {str(exc)[:150]}"
    n = int(row["attempts"]) + 1
    if ok:
        conn.execute("UPDATE crm_sync_pending SET attempts=?, done_at=?, last_error=NULL, "
                     "claimed_until=NULL WHERE id=?", (n, db.now_iso(), row_id))
    else:
        tre = min(3600, 30 * 2 ** min(n, 7))
        conn.execute("UPDATE crm_sync_pending SET attempts=?, last_error=?, next_at=?, "
                     "claimed_until=NULL WHERE id=?",
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
    sql += " AND (claimed_until IS NULL OR claimed_until<?)"
    params = (*params, db.now_iso())
    ids = [r["id"] for r in db.q(conn, sql + " ORDER BY id LIMIT ?", (*params, gioi_han))]
    thu = ok = 0
    for i in ids:
        if not _nhan_dong(conn, i):
            continue  # lượt khác đã nhận
        thu += 1
        ok += 1 if _gui_da_nhan(conn, i) else 0
    con = int(db.scalar(conn, "SELECT COUNT(*) FROM crm_sync_pending WHERE done_at IS NULL"))
    return {"thu": thu, "thanh_cong": ok, "con_lai": con}


def _ms_hien_tai() -> int:
    return int(time.time() * 1000)


MOC_TRAN_MS = 5 * 60 * 1000  # mốc thời gian lưu không được vượt now + 5 phút


def _canh_bao_dong_ho(conn, subject: str, cot: str, gia_tri: int, now: int) -> None:
    _ghi_audit(conn, "system", "khach.canh_bao.dong_ho", target_id=subject,
               detail={"cot": cot, "gia_tri_ms": gia_tri, "now_ms": now}, lay_mau=f"{subject}:{cot}")
    log.warning("CANH_BAO khach: %s của %s bị kẹp ở now+5 phút (đồng hồ lệch/dữ liệu sai); "
                "xem runbook khach-dat-lai-moc", cot, subject)


def moc_thu_hoi(conn, account_id: str, session_id: str | None = None, tat_ca: bool = False,
                ly_do: str = "") -> int:
    """Ghi mốc thu hồi (mili-giây unix) VÀ thu hồi phiên VIP ID trong CÙNG một giao dịch ghi.

    revoked_at_ms = MIN(MAX(revoked_at_ms + 1, launch_at_ms + 1, now), now + 5 phút) — một
    UPDATE…RETURNING. Bất biến: mọi launch phát trước có iat_ms < mốc; mọi launch phát sau có
    iat_ms > mốc; không launch nào phát được cho phiên đã thu hồi (phat_launch_token kiểm phiên
    trong giao dịch của nó). `session_id` ⇒ thu hồi phiên đó; `tat_ca` ⇒ mọi phiên của khách."""
    now = _ms_hien_tai()
    tran = now + MOC_TRAN_MS
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute(
            "UPDATE customer_accounts SET revoked_at_ms = MIN(MAX(COALESCE(revoked_at_ms, 0) + 1, "
            "COALESCE(launch_at_ms, 0) + 1, ?), ?) WHERE id=? RETURNING revoked_at_ms, subject",
            (now, tran, account_id)).fetchone()
        if session_id is not None:
            conn.execute("UPDATE customer_sessions SET status='revoked', revoked_at=?, "
                         "revoke_reason=? WHERE id=? AND status='active'",
                         (db.now_iso(), ly_do[:200], session_id))
        if tat_ca:
            conn.execute("UPDATE customer_sessions SET status='revoked', revoked_at=?, "
                         "revoke_reason=? WHERE account_id=? AND status='active'",
                         (db.now_iso(), ly_do[:200], account_id))
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    ms = int(row[0]) if row else now
    if row and ms >= tran:
        _canh_bao_dong_ho(conn, row[1], "revoked_at_ms", ms, now)
    return ms


def dat_lai_moc(conn, account_id: str, actor: str = "ops") -> dict:
    """Ops: đưa revoked_at_ms/launch_at_ms về `now` (sau sự cố đồng hồ). Thu hồi mọi phiên VIP ID
    để không launch nào cũ hơn còn dùng được; trả mốc mới để báo CRM đặt lại phía CRM."""
    now = _ms_hien_tai()
    conn.execute("BEGIN IMMEDIATE")
    try:
        conn.execute("UPDATE customer_accounts SET revoked_at_ms=?, launch_at_ms=? WHERE id=?",
                     (now, now, account_id))
        n = conn.execute("UPDATE customer_sessions SET status='revoked', revoked_at=?, "
                         "revoke_reason='Ops đặt lại mốc thời gian' WHERE account_id=? "
                         "AND status='active'", (db.now_iso(), account_id)).rowcount
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    acc = tai_khoan(conn, account_id)
    _ghi_audit(conn, actor, "khach.ops.dat_lai_moc", target_id=acc["subject"],
               detail={"moc_ms": now, "phien_thu_hoi": n})
    return {"subject": acc["subject"], "moc_ms": now, "phien_thu_hoi": n}


def bao_crm_thu_hoi(conn, subject: str, reason: str, revoked_at_ms: int | None = None) -> None:
    """Xếp hàng thu hồi phiên portal ở CRM. `revoked_at_ms` (mili-giây unix) = lúc thu hồi xảy ra
    TẠI VIP ID, ghi khi xếp hàng (không phải lúc gửi; gửi bất đồng bộ). CRM từ chối launch token
    có `iat_ms < revoked_at_ms`. Kèm `revoked_at` (giây) để tương thích."""
    ms = _ms_hien_tai() if revoked_at_ms is None else int(revoked_at_ms)
    xep_hang_crm(conn, "thu_hoi", f"thu-hoi:{subject}:{reason}:{security.token_moi(6)}",
                 subject, PATH_THU_HOI, {"subject": subject, "reason": reason,
                                         "revoked_at": ms // 1000, "revoked_at_ms": ms})


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
        # Owner 07/11: không gọi xác minh SĐT; duyệt của nhân viên = xác minh (phương thức
        # 'duyet_crm'). Người duyệt tuỳ chọn (phone_verified_by hoặc approved_by).
        nguoi = str(data.get("phone_verified_by") or data.get("approved_by") or "").strip() or "crm"
        if (not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", crm_id) or not code
                or len(nguoi) > 120 or (cust_code and len(cust_code) > 40)):
            return 400, {"ma": "DU_LIEU_SAI",
                         "thongBao": "Thiếu/sai crm_customer_id hoặc portal_code."}
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
                "phone_verified_by=?, phone_verified_method='duyet_crm', crm_customer_id=?, "
                "customer_code=?, portal_code=?, updated_at=? WHERE id=? AND status='cho_duyet'",
                (now, nguoi, crm_id, cust_code, code, now, acc["id"]))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.rollback()
            return 409, {"ma": "XUNG_DOT", "thongBao": "crm_customer_id hoặc portal_code đã dùng."}
        _ghi_audit(conn, "crm", "khach.duyet", target_id=subject,
                   detail={"crm_customer_id": crm_id, "portal_code": code,
                           "phone_verified_by": nguoi, "method": "duyet_crm"}, request=request)
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
        # Bị từ chối ⇒ GIẢI PHÓNG SĐT/email (chủ thật đăng ký lại được). Giữ dấu vết bằng
        # sha256 trong audit, không giữ giá trị gốc ở cột unique.
        conn.execute("UPDATE customer_accounts SET status='tu_choi', phone_e164=?, updated_at=? "
                     "WHERE id=?", ("released:" + acc["id"], db.now_iso(), acc["id"]))
        conn.commit()
        thu_hoi_moi_phien(conn, acc["id"], "Bị từ chối")
        _ghi_audit(conn, "crm", "khach.tu_choi", target_id=subject,
                   detail={"reason": str(data.get("reason") or "")[:200],
                           "phoneSha256": security.sha256(acc["phone_e164"]),
                           "emailSha256": security.sha256(acc["email_norm"] or ""),
                           "phone": che_sdt(acc["phone_e164"])}, request=request)
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
    if acc["status"] == "tu_choi":
        return 409, {"ma": "XUNG_DOT", "thongBao": "Tài khoản đã bị từ chối."}
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
                   else "cho_duyet")
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
                   request=request, lay_mau=ip)
        return
    if not config.KHACH_EMAIL_ENABLED:
        return
    em = chuan_hoa_email(dinh_danh)
    if em:  # email không unique: chỉ dùng khi đúng MỘT tài khoản mang email này
        rows = db.q(conn, "SELECT * FROM customer_accounts WHERE email_norm=? LIMIT 2", (em,))
        acc = rows[0] if len(rows) == 1 else None
    else:
        acc, _ = _tim_theo_dinh_danh(conn, dinh_danh)
    if not acc or acc["status"] not in ("hoat_dong", "cho_duyet"):
        return
    if vuot_tan_suat(conn, "quen_acc_ip", f"{acc['id']}:{ip}",
                     config.KHACH_RESET_ACC_IP_PER_HOUR, 3600):
        return
    raw = tao_token(conn, acc["id"], "khoi_phuc")
    if not raw:
        return
    gui_email(conn, acc["id"], acc["email_norm"], "khoi_phuc",
              "VIP GROUP — Đặt lại mật khẩu cổng khách hàng",
              f"Chào {acc['display_name']},\n\nBấm liên kết sau để đặt mật khẩu mới (hiệu lực "
              f"{config.KHACH_TOKEN_TTL_MIN} phút, dùng một lần):\n"
              f"{_link('/tai-khoan/dat-lai?t=' + raw)}" + _CHAN_THU)
    _ghi_audit(conn, acc["subject"], "khach.quen_mat_khau", target_id=acc["subject"],
               request=request, lay_mau=f"{ip}:{acc['id']}")


def tao_link_dat_lai(conn, data: dict, request=None) -> tuple[int, dict]:
    """CRM → VIP ID (HMAC): nhân viên đã xác nhận danh tính khách qua điện thoại, cấp link đặt lại
    mật khẩu (một lần, chỉ lưu sha256, TTL 30 phút) để gửi khách qua Zalo. Link mới thay mọi link
    đặt lại còn treo (chỉ nhân viên phát được nên không có nguy cơ kẻ lạ làm hỏng link của chủ)."""
    subject = str(data.get("subject") or "")
    nguoi = str(data.get("requested_by") or "").strip()
    if not nguoi or len(nguoi) > 120:
        return 400, {"ma": "DU_LIEU_SAI", "thongBao": "Thiếu/sai requested_by."}
    acc = tai_khoan_theo_subject(conn, subject) if subject.startswith("cust:") else None
    if not acc:
        return 404, {"ma": "KHONG_TIM_THAY", "thongBao": "Không có tài khoản khách này."}
    if acc["status"] not in ("hoat_dong", "cho_duyet"):
        return 409, {"ma": "XUNG_DOT", "thongBao": f"Trạng thái {acc['status']} không cấp link được."}
    if not pilot_cho_phep(acc["phone_e164"]):
        return 403, {"ma": "PILOT", "thongBao": "Đang chạy thử: tài khoản không thuộc danh sách pilot."}
    now = _bay_gio()
    conn.execute("UPDATE customer_tokens SET used_at=? WHERE account_id=? AND purpose='khoi_phuc' "
                 "AND used_at IS NULL", (_iso(now), acc["id"]))
    conn.commit()
    raw = tao_token(conn, acc["id"], "khoi_phuc")
    het = db.scalar(conn, "SELECT expires_at FROM customer_tokens WHERE token_hash=?",
                    (security.sha256(raw),))
    _ghi_audit(conn, "crm", "khach.tao_link_dat_lai", target_id=subject,
               detail={"requested_by": nguoi, "tokenHash": security.sha256(raw)[:16],
                       "expires_at": het}, request=request)
    return 200, {"subject": subject, "url": _link("/tai-khoan/dat-lai?t=" + raw), "expires_at": het}


def dat_lai_mat_khau(conn, raw: str | None, mat_khau: str, mat_khau_2: str,
                     request=None) -> dict:
    tk = xem_token(conn, raw, "khoi_phuc")
    if not tk:
        raise KhachLoi("Liên kết đặt lại mật khẩu không hợp lệ, đã dùng hoặc đã hết hạn.", 400,
                       "TOKEN_SAI")
    acc = tai_khoan(conn, tk["account_id"])
    if acc:
        chan_pilot(acc["phone_e164"])
    if not acc or acc["status"] not in ("hoat_dong", "cho_duyet"):
        raise KhachLoi("Tài khoản hiện không thể đặt lại mật khẩu. Vui lòng liên hệ VIP GROUP.",
                       403, "KHONG_DUOC_PHEP")
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
    hash_b64, salt_b64, algo = bam_mk(mat_khau)
    now = db.now_iso()
    conn.execute("UPDATE customer_accounts SET password_hash=?, password_salt=?, password_algo=?, "
                 "token_version=token_version+1, failed_attempts=0, locked_until=NULL, "
                 "updated_at=? WHERE id=?", (hash_b64, salt_b64, algo, now, acc_id))
    conn.execute("UPDATE customer_tokens SET used_at=? WHERE account_id=? AND purpose='khoi_phuc' "
                 "AND used_at IS NULL", (now, acc_id))
    # Đặt lại thành công ⇒ xoá bộ đếm sai của tài khoản (mọi IP).
    conn.execute("DELETE FROM customer_login_attempts WHERE account_key=? AND success=0", (acc_id,))
    conn.commit()
    n = db.scalar(conn, "SELECT COUNT(*) FROM customer_sessions WHERE account_id=? "
                  "AND status='active'", (acc_id,))
    rv_ms = moc_thu_hoi(conn, acc_id, tat_ca=True, ly_do="Đặt lại mật khẩu")
    acc = tai_khoan(conn, acc_id)
    bao_crm_thu_hoi(conn, acc["subject"], "dat_lai_mat_khau", rv_ms)
    _ghi_audit(conn, acc["subject"], "khach.dat_lai_mat_khau", target_id=acc["subject"],
               detail={"phien_thu_hoi": n}, request=request)
    gui_email(conn, acc_id, acc["email_norm"], "doi_mat_khau",
              "VIP GROUP — Mật khẩu của bạn vừa được đổi",
              "Mật khẩu cổng khách hàng VIP GROUP vừa được đặt lại và mọi phiên đăng nhập đã bị "
              "đăng xuất. Nếu không phải bạn, hãy liên hệ VIP GROUP ngay." + _CHAN_THU)
    return acc


# ------------------------------------------------------------------ đổi mật khẩu (đã đăng nhập)
DOI_MK_SAI_TOI_DA = 5          # theo (tài khoản, IP)
DOI_MK_SAI_TK_TOI_DA = 10      # theo tài khoản, mọi IP


def doi_mat_khau(conn, ctx: dict, mat_khau_cu: str, mat_khau: str, mat_khau_2: str, ip: str,
                 ua: str | None = None, request=None) -> tuple[dict, str, dict]:
    """Khách đã đăng nhập đổi mật khẩu. Trả (phiên mới, token phiên mới, account).

    - Sai mật khẩu hiện tại: đếm theo (tài khoản, IP); đủ ngưỡng ⇒ 429 KHÔNG băm.
    - Thành công: tăng token_version (cookie thiết bị cũ, phiên cũ mất hiệu lực), thu hồi MỌI phiên
      khác, cấp phiên mới cho trình duyệt hiện tại, email thông báo, báo CRM thu hồi phiên portal.
    """
    acc = ctx["account"]
    khoa = f"{acc['id']}:{ip}"
    w = config.KHACH_LOGIN_WINDOW_MIN * 60
    da_sai = int(conn.execute(
        "SELECT COUNT(*) FROM customer_rate_events WHERE bucket='doi_mk_sai' AND key=? "
        "AND created_at>=?", (khoa, _truoc(seconds=w))).fetchone()[0])
    sai_tk = int(conn.execute(
        "SELECT COUNT(*) FROM customer_rate_events WHERE bucket='doi_mk_sai_tk' AND key=? "
        "AND created_at>=?", (acc["id"], _truoc(seconds=w))).fetchone()[0])
    if sai_tk >= DOI_MK_SAI_TK_TOI_DA:
        _ghi_audit(conn, acc["subject"], "khach.doi_mat_khau.tam_khoa_tai_khoan",
                   target_id=acc["subject"], detail={"ip": ip, "lan": sai_tk}, request=request,
                   lay_mau=acc["id"])
        raise KhachLoi(f"Mật khẩu hiện tại đã bị nhập sai nhiều lần. Vui lòng thử lại sau "
                       f"{config.KHACH_LOGIN_WINDOW_MIN} phút.", 429, "TAM_KHOA")
    if da_sai >= DOI_MK_SAI_TOI_DA:
        _ghi_audit(conn, acc["subject"], "khach.doi_mat_khau.tam_khoa", target_id=acc["subject"],
                   detail={"ip": ip}, request=request, lay_mau=khoa)
        raise KhachLoi(f"Bạn đã nhập sai mật khẩu hiện tại nhiều lần. Vui lòng thử lại sau "
                       f"{config.KHACH_LOGIN_WINDOW_MIN} phút.", 429, "TAM_KHOA")
    mat_khau_cu, mat_khau, mat_khau_2 = mat_khau_cu or "", mat_khau or "", mat_khau_2 or ""
    if not kiem_mk(mat_khau_cu, acc):
        conn.execute("INSERT INTO customer_rate_events(bucket, key, created_at) VALUES(?,?,?)",
                     ("doi_mk_sai", khoa, _iso(_bay_gio())))
        conn.execute("INSERT INTO customer_rate_events(bucket, key, created_at) VALUES(?,?,?)",
                     ("doi_mk_sai_tk", acc["id"], _iso(_bay_gio())))
        conn.commit()
        _ghi_audit(conn, acc["subject"], "khach.doi_mat_khau.sai", target_id=acc["subject"],
                   detail={"ip": ip}, request=request, lay_mau=khoa)
        raise KhachLoi("Mật khẩu hiện tại không đúng.", 400, "SAI_MAT_KHAU")
    loi = security.kiem_tra_do_manh(mat_khau, acc["phone_e164"][3:],
                                    min_len=config.KHACH_PASSWORD_MIN)
    if loi:
        raise KhachLoi(loi)
    if mat_khau != mat_khau_2:
        raise KhachLoi("Hai lần nhập mật khẩu mới không khớp.")
    if hmac.compare_digest(mat_khau, mat_khau_cu):
        raise KhachLoi("Mật khẩu mới phải khác mật khẩu hiện tại.")
    hash_b64, salt_b64, algo = bam_mk(mat_khau)
    now = db.now_iso()
    cur = conn.execute(
        "UPDATE customer_accounts SET password_hash=?, password_salt=?, password_algo=?, "
        "token_version=token_version+1, updated_at=? WHERE id=? AND token_version=? "
        "AND status='hoat_dong'",
        (hash_b64, salt_b64, algo, now, acc["id"], acc["token_version"]))
    conn.commit()
    if cur.rowcount != 1:  # đổi song song / tài khoản vừa bị khoá
        raise KhachLoi("Phiên đã thay đổi, vui lòng đăng nhập lại.", 409, "XUNG_DOT")
    conn.execute("DELETE FROM customer_rate_events WHERE bucket='doi_mk_sai' AND key=?", (khoa,))
    conn.commit()
    n = db.scalar(conn, "SELECT COUNT(*) FROM customer_sessions WHERE account_id=? "
                  "AND status='active'", (acc["id"],))
    # Mốc + thu hồi mọi phiên (gồm phiên hiện tại) trong một giao dịch, TRƯỚC phiên mới.
    rv_ms = moc_thu_hoi(conn, acc["id"], tat_ca=True, ly_do="Đổi mật khẩu")
    acc = tai_khoan(conn, acc["id"])
    bao_crm_thu_hoi(conn, acc["subject"], "doi_mat_khau", rv_ms)
    sess, token = tao_phien(conn, acc, ip, ua)  # phiên mới cho trình duyệt đang dùng
    _ghi_audit(conn, acc["subject"], "khach.doi_mat_khau", target_id=acc["subject"],
               detail={"ip": ip, "phien_khac_thu_hoi": max(0, n - 1)}, request=request)
    gui_email(conn, acc["id"], acc["email_norm"], "doi_mat_khau",
              "VIP GROUP — Mật khẩu vừa được thay đổi",
              f"Chào {acc['display_name']},\n\nMật khẩu cổng khách hàng VIP GROUP của bạn vừa được "
              "thay đổi. Các phiên đăng nhập trên thiết bị khác đã bị đăng xuất.\n\nNếu không phải "
              "bạn, hãy đặt lại mật khẩu ngay và liên hệ VIP GROUP:\n"
              f"{_link('/tai-khoan/quen-mat-khau')}" + _CHAN_THU)
    return sess, token, acc
