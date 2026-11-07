"""Đăng nhập ID, phiên máy chủ, CSRF và thu hồi phiên."""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from . import config, db, security
from .errors import AuthRequired, Forbidden, ValidationError

TEN_COOKIE = config.COOKIE_NAME


def la_https(request) -> bool:
    """X-Forwarded-Proto chỉ được tin khi chạy sau proxy đã ghi đè header (COWORK_TIN_PROXY=1)."""
    if request.url.scheme == "https":
        return True
    return config.TIN_PROXY and request.headers.get("x-forwarded-proto", "").lower() == "https"


def cookie_kwargs(request, max_age: int | None = None) -> dict:
    return {
        "httponly": True,
        "secure": config.COOKIE_SECURE or la_https(request),
        "samesite": "lax",
        "path": "/",
        "max_age": max_age,
    }


def nguoi_dung_day_du(conn: sqlite3.Connection, user_id: str) -> dict | None:
    row = conn.execute(
        "SELECT u.*, r.name AS role_name, r.level AS role_level, r.is_locked AS role_locked, "
        "d.name AS department_name, d.code AS department_code, t.name AS tenant_name "
        "FROM users u JOIN roles r ON r.code=u.role_code "
        "LEFT JOIN departments d ON d.id=u.department_id "
        "JOIN tenants t ON t.id=u.tenant_id WHERE u.id=?",
        (user_id,)).fetchone()
    if not row:
        return None
    user = dict(row)
    user["is_super"] = user["role_code"] == "super_admin"
    return user


def _dt(value: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(value) if value else None
    except (TypeError, ValueError):
        return None


def idle_phut(conn: sqlite3.Connection) -> int:
    try:
        return max(1, int(db.get_setting(conn, "security.idle_minutes", str(config.IDLE_MINUTES))))
    except (TypeError, ValueError):
        return config.IDLE_MINUTES


def gio_phien(conn: sqlite3.Connection) -> int:
    try:
        return max(1, int(db.get_setting(conn, "security.session_hours", str(config.SESSION_HOURS))))
    except (TypeError, ValueError):
        return config.SESSION_HOURS


def tao_phien(conn: sqlite3.Connection, user: dict, request,
              ip: str | None = None) -> tuple[dict, str]:
    token = security.token_moi(32)
    csrf = security.token_moi(24)
    now = datetime.now(db.TZ).replace(microsecond=0)
    het_han = now + timedelta(hours=gio_phien(conn))
    sid = security.token_moi(12)
    conn.execute(
        "INSERT INTO sessions(id, token_hash, csrf_token, user_id, tenant_id, created_at, "
        "last_seen_at, expires_at, ip, user_agent, status) VALUES(?,?,?,?,?,?,?,?,?,?, 'active')",
        (sid, security.sha256(token), csrf, user["id"], user["tenant_id"],
         now.isoformat(), now.isoformat(), het_han.isoformat(),
         (request.client.host if request.client else None) if ip is None else ip,
         (request.headers.get("user-agent") or "")[:400] or None),
    )
    # Giới hạn 8 phiên sống / người: thu hồi các phiên cũ nhất, KHÔNG BAO GIỜ thu hồi
    # phiên vừa tạo (created_at chỉ tới giây nên nhiều phiên có thể trùng thời điểm).
    rows = conn.execute(
        "SELECT id FROM sessions WHERE user_id=? AND status='active' "
        "ORDER BY created_at DESC, rowid DESC",
        (user["id"],)).fetchall()
    phien_cu = [r["id"] for r in rows if r["id"] != sid]
    for old_id in phien_cu[7:]:
        conn.execute("UPDATE sessions SET status='revoked', revoked_at=?, revoked_by=?, "
                     "revoke_reason='Vượt giới hạn 8 phiên' WHERE id=?",
                     (db.now_iso(), user["id"], old_id))
    conn.commit()
    return {"id": sid, "csrf_token": csrf, "expires_at": het_han.isoformat()}, token


def dat_cookie(response, request, token: str) -> None:
    max_age = config.SESSION_HOURS * 3600
    response.set_cookie(TEN_COOKIE, token, **cookie_kwargs(request, max_age))


def xoa_cookie(response, request) -> None:
    response.delete_cookie(TEN_COOKIE, path="/", httponly=True,
                           secure=config.COOKIE_SECURE or la_https(request), samesite="lax")


def token_tu_request(request) -> str | None:
    if hasattr(request, "state") and getattr(request.state, "session_token", None):
        return request.state.session_token
    raw = request.cookies.get(TEN_COOKIE) if hasattr(request, "cookies") else None
    if raw:
        return raw.strip() or None
    auth = request.headers.get("authorization", "") if hasattr(request, "headers") else ""
    if auth.startswith("Bearer "):
        return auth[7:].strip() or None
    return None


def xac_thuc(conn: sqlite3.Connection, token: str | None) -> dict | None:
    """Trả {session, user} nếu phiên còn sống; ngược lại None (fail-closed)."""
    if not token:
        return None
    r = conn.execute(
        "SELECT * FROM sessions WHERE token_hash=? AND status='active'",
        (security.sha256(token),)).fetchone()
    if not r:
        return None
    s = dict(r)
    now = datetime.now(db.TZ)
    het_han = _dt(s["expires_at"])
    hoat_dong = _dt(s["last_seen_at"])
    if not het_han or now >= het_han:
        conn.execute("UPDATE sessions SET status='expired' WHERE id=?", (s["id"],))
        conn.commit()
        return None
    if not hoat_dong or now >= hoat_dong + timedelta(minutes=idle_phut(conn)):
        conn.execute("UPDATE sessions SET status='expired' WHERE id=?", (s["id"],))
        conn.commit()
        return None
    user = nguoi_dung_day_du(conn, s["user_id"])
    if not user or user["status"] != "active":
        conn.execute("UPDATE sessions SET status='revoked', revoked_at=?, revoked_by=?, "
                     "revoke_reason='Tài khoản không còn hoạt động' WHERE id=?",
                     (db.now_iso(), "system", s["id"]))
        conn.commit()
        return None
    # Chỉ ghi last_seen mỗi 60 giây để giảm ghi DB.
    if not hoat_dong or (now - hoat_dong).total_seconds() >= 60:
        conn.execute("UPDATE sessions SET last_seen_at=? WHERE id=?",
                     (now.replace(microsecond=0).isoformat(), s["id"]))
        conn.commit()
        s["last_seen_at"] = now.replace(microsecond=0).isoformat()
    s.pop("token_hash", None)
    return {"session": s, "user": user}


def thu_hoi_phien(conn: sqlite3.Connection, session_id: str, actor_id: str,
                  reason: str = "Thu hồi bởi quản trị") -> bool:
    cur = conn.execute(
        "UPDATE sessions SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=? "
        "WHERE id=? AND status='active'",
        (db.now_iso(), actor_id, reason[:200], session_id))
    conn.commit()
    return cur.rowcount > 0


def thu_hoi_cua_user(conn: sqlite3.Connection, user_id: str, actor_id: str,
                     reason: str = "Thu hồi bởi quản trị", tru_session: str | None = None) -> int:
    sql = ("UPDATE sessions SET status='revoked', revoked_at=?, revoked_by=?, revoke_reason=? "
           "WHERE user_id=? AND status='active'")
    params: list = [db.now_iso(), actor_id, reason[:200], user_id]
    if tru_session:
        sql += " AND id<>?"
        params.append(tru_session)
    cur = conn.execute(sql, params)
    conn.commit()
    return int(cur.rowcount)


# ------------------------------- CSRF -------------------------------
def csrf_anon(request) -> str:
    token = request.cookies.get(config.CSRF_COOKIE)
    if token and len(token) >= 20:
        return token
    return security.token_moi(24)


def dat_cookie_csrf(response, request, token: str) -> None:
    response.set_cookie(config.CSRF_COOKIE, token, **cookie_kwargs(request, 7200))


def kiem_csrf(request, form_token: str | None) -> None:
    """So token form/header với token phiên (hoặc cookie double-submit khi chưa đăng nhập)."""
    session = getattr(request.state, "session", None)
    if session:
        mong = session.get("csrf_token")
    else:
        mong = request.cookies.get(config.CSRF_COOKIE)
    gui = (form_token or request.headers.get("x-csrf-token") or "").strip()
    if not mong or not gui or not security.hmac.compare_digest(str(mong), str(gui)):
        raise Forbidden("Phiên làm việc không hợp lệ hoặc thiếu mã CSRF — tải lại trang và thử lại.")
    # Nếu trình duyệt có gửi Origin/Referer thì phải cùng host (chặn CSRF cross-site).
    origin = request.headers.get("origin") or ""
    if origin:
        host = request.headers.get("host") or ""
        try:
            if urlsplit(origin).netloc.lower() != host.lower():
                raise Forbidden("Yêu cầu bị chặn: Origin không cùng host.")
        except ValueError:
            raise Forbidden("Yêu cầu bị chặn: Origin không hợp lệ.")


# ------------------------------- Đăng nhập -------------------------------
def _dem_sai(conn: sqlite3.Connection, user_id: str, ip: str, phut: int) -> int:
    nguong = (datetime.now(db.TZ) - timedelta(minutes=phut)).replace(microsecond=0).isoformat()
    return int(conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE user_id=? AND ip=? AND success=0 "
        "AND created_at>=?", (user_id, ip, nguong)).fetchone()[0])


def _dem_sai_user(conn: sqlite3.Connection, user_id: str, phut: int) -> int:
    nguong = (datetime.now(db.TZ) - timedelta(minutes=phut)).replace(microsecond=0).isoformat()
    return int(conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE user_id=? AND success=0 AND created_at>=?",
        (user_id, nguong)).fetchone()[0])


def _ghi_lan(conn: sqlite3.Connection, user_id: str, ip: str, success: bool) -> None:
    conn.execute("INSERT INTO login_attempts(user_id, ip, success, created_at) VALUES(?,?,?,?)",
                 (user_id, ip, 1 if success else 0, db.now_iso()))
    conn.execute("DELETE FROM login_attempts WHERE created_at<?",
                 ((datetime.now(db.TZ) - timedelta(days=2)).isoformat(),))
    conn.commit()


def dang_nhap(conn: sqlite3.Connection, user_id: str, mat_khau: str, ip: str) -> dict:
    """Trả user đầy đủ nếu đúng; ném AuthRequired với thông báo chung nếu sai."""
    user_id = security.chuan_hoa_id(user_id)
    if not user_id or not mat_khau:
        raise AuthRequired("Sai ID hoặc mật khẩu.")
    if _dem_sai(conn, user_id, ip, config.LOGIN_WINDOW_MIN) >= config.LOGIN_MAX_FAIL:
        raise AuthRequired(f"Tài khoản tạm khoá {config.LOGIN_WINDOW_MIN} phút vì đăng nhập sai "
                           f"quá {config.LOGIN_MAX_FAIL} lần. Thử lại sau.")
    if _dem_sai_user(conn, user_id, 30) >= config.LOGIN_MAX_FAIL * 3:
        raise AuthRequired("Tài khoản tạm khoá 30 phút vì quá nhiều lần đăng nhập sai. "
                           "Liên hệ quản trị để mở khoá.")
    row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    hop_le = bool(row) and security.kiem_mat_khau(mat_khau, row["password_hash"], row["password_salt"])
    if not hop_le:
        if not row or not row["password_hash"]:
            security.bam_gia(mat_khau)
        _ghi_lan(conn, user_id, ip, False)
        raise AuthRequired("Sai ID hoặc mật khẩu.")
    user = nguoi_dung_day_du(conn, user_id)
    if not user or user["status"] != "active":
        _ghi_lan(conn, user_id, ip, False)
        raise AuthRequired("Tài khoản chưa kích hoạt hoặc đang bị khoá.")
    # Đăng nhập đúng chứng minh chủ tài khoản: xoá bộ đếm sai của chính user+IP này
    # để các lần gõ nhầm trước đó không khoá oan về sau.
    conn.execute("DELETE FROM login_attempts WHERE user_id=? AND ip=? AND success=0",
                 (user_id, ip))
    _ghi_lan(conn, user_id, ip, True)
    conn.execute("UPDATE users SET last_login_at=?, failed_attempts=0, locked_until=NULL, "
                 "updated_at=? WHERE id=?", (db.now_iso(), db.now_iso(), user_id))
    conn.commit()
    return user


# ------------------------------- MFA (TOTP) -------------------------------
TEN_COOKIE_MFA = "cowork_mfa"
MFA_PHUT = 5
MFA_TOI_DA = 5
MFA_SO_MA_DU_PHONG = 10


def _kiem_mat_khau_user(conn: sqlite3.Connection, user_id: str, mat_khau: str) -> bool:
    row = conn.execute("SELECT password_hash, password_salt FROM users WHERE id=?",
                       (user_id,)).fetchone()
    return bool(row) and security.kiem_mat_khau(mat_khau, row["password_hash"], row["password_salt"])


def tao_thach_thuc_mfa(conn: sqlite3.Connection, user: dict, request) -> dict:
    """Tạo challenge 5 phút sau khi mật khẩu đúng; trả token thô (DB chỉ giữ hash)."""
    token = security.token_moi(32)
    now = datetime.now(db.TZ).replace(microsecond=0)
    het = now + timedelta(minutes=MFA_PHUT)
    conn.execute("DELETE FROM mfa_challenges WHERE expires_at<? OR used_at IS NOT NULL",
                 (now.isoformat(),))
    conn.execute(
        "INSERT INTO mfa_challenges(id, token_hash, user_id, tenant_id, expires_at, attempts, "
        "created_at) VALUES(?,?,?,?,?,0,?)",
        (security.token_moi(10), security.sha256(token), user["id"], user["tenant_id"],
         het.isoformat(), now.isoformat()))
    conn.commit()
    return {"token": token, "expires_at": het.isoformat()}


def xac_thuc_mfa(conn: sqlite3.Connection, token: str | None, ma: str) -> dict | None:
    if not token:
        return None
    r = conn.execute("SELECT * FROM mfa_challenges WHERE token_hash=?",
                     (security.sha256(token),)).fetchone()
    if not r:
        return None
    ch = dict(r)
    try:
        het = datetime.fromisoformat(ch["expires_at"])
    except (TypeError, ValueError):
        return None
    if ch["used_at"] or datetime.now(db.TZ) >= het or int(ch["attempts"] or 0) >= MFA_TOI_DA:
        return None
    user = nguoi_dung_day_du(conn, ch["user_id"])
    if not user or user["status"] != "active" or not user.get("mfa_enabled"):
        return None
    hop_le = False
    if user.get("mfa_secret"):
        hop_le = security.kiem_totp(user["mfa_secret"], ma)
    if not hop_le:
        h = security.bam_ma_du_phong(ma)
        code = conn.execute(
            "SELECT id FROM mfa_backup_codes WHERE user_id=? AND code_hash=? AND used_at IS NULL",
            (user["id"], h)).fetchone()
        if code:
            conn.execute("UPDATE mfa_backup_codes SET used_at=? WHERE id=?",
                         (db.now_iso(), code["id"]))
            hop_le = True
    if not hop_le:
        conn.execute("UPDATE mfa_challenges SET attempts=attempts+1 WHERE id=?", (ch["id"],))
        conn.commit()
        return None
    now = db.now_iso()
    conn.execute("UPDATE mfa_challenges SET used_at=? WHERE id=?", (now, ch["id"]))
    # Một lần xác thực thành công vô hiệu mọi challenge song song còn lại của user.
    conn.execute("UPDATE mfa_challenges SET used_at=? WHERE user_id=? AND used_at IS NULL",
                 (now, user["id"]))
    conn.commit()
    return user


def bat_mfa(conn: sqlite3.Connection, user: dict, secret: str, ma: str,
            mat_khau: str) -> list[str]:
    """Bật MFA sau khi xác minh mật khẩu + mã TOTP; trả mã dự phòng dùng một lần."""
    if not _kiem_mat_khau_user(conn, user["id"], mat_khau):
        raise ValidationError("Mật khẩu hiện tại không đúng.")
    if not security.kiem_totp(secret, ma):
        raise ValidationError("Mã xác thực không đúng hoặc đã hết hạn.")
    conn.execute("UPDATE users SET mfa_enabled=1, mfa_secret=?, updated_at=? WHERE id=?",
                 (secret, db.now_iso(), user["id"]))
    conn.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user["id"],))
    ma_ds = [security.tao_ma_du_phong() for _ in range(MFA_SO_MA_DU_PHONG)]
    for code in ma_ds:
        conn.execute("INSERT INTO mfa_backup_codes(user_id, code_hash, created_at) VALUES(?,?,?)",
                     (user["id"], security.bam_ma_du_phong(code), db.now_iso()))
    conn.commit()
    return ma_ds


def tat_mfa(conn: sqlite3.Connection, user: dict, mat_khau: str, ma: str) -> None:
    if not _kiem_mat_khau_user(conn, user["id"], mat_khau):
        raise ValidationError("Mật khẩu hiện tại không đúng.")
    row = conn.execute("SELECT mfa_secret FROM users WHERE id=?", (user["id"],)).fetchone()
    if not row or not row["mfa_secret"] or not security.kiem_totp(row["mfa_secret"], ma):
        raise ValidationError("Mã xác thực không đúng hoặc đã hết hạn.")
    conn.execute("UPDATE users SET mfa_enabled=0, mfa_secret=NULL, updated_at=? WHERE id=?",
                 (db.now_iso(), user["id"]))
    conn.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user["id"],))
    conn.execute("DELETE FROM mfa_challenges WHERE user_id=?", (user["id"],))
    conn.commit()


def tao_lai_ma_du_phong(conn: sqlite3.Connection, user: dict, mat_khau: str,
                        ma: str) -> list[str]:
    if not _kiem_mat_khau_user(conn, user["id"], mat_khau):
        raise ValidationError("Mật khẩu hiện tại không đúng.")
    row = conn.execute("SELECT mfa_secret FROM users WHERE id=?", (user["id"],)).fetchone()
    if not row or not row["mfa_secret"] or not security.kiem_totp(row["mfa_secret"], ma):
        raise ValidationError("Mã xác thực không đúng hoặc đã hết hạn.")
    conn.execute("DELETE FROM mfa_backup_codes WHERE user_id=?", (user["id"],))
    ma_ds = [security.tao_ma_du_phong() for _ in range(MFA_SO_MA_DU_PHONG)]
    for code in ma_ds:
        conn.execute("INSERT INTO mfa_backup_codes(user_id, code_hash, created_at) VALUES(?,?,?)",
                     (user["id"], security.bam_ma_du_phong(code), db.now_iso()))
    conn.commit()
    return ma_ds


def ma_du_phong_con_lai(conn: sqlite3.Connection, user_id: str) -> int:
    return int(conn.execute(
        "SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id=? AND used_at IS NULL",
        (user_id,)).fetchone()[0])
