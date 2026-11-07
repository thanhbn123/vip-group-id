"""AG-02 — Kiểm thử đối kháng Danh tính: phiên, CSRF, rate limit, lưu trữ bí mật.

Nguyên tắc: chỉ dùng ứng dụng thật + SQLite thật (không mock). Mọi thao tác "tấn công"
đều đi qua HTTP hoặc sửa trực tiếp trạng thái DB như một sự cố vận hành thật.
"""
from __future__ import annotations

import base64
import html
import json
import re
import statistics
import time
from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from conftest import csrf_cua, csrf_tu, dang_nhap, tao_user
from cowork import auth, config, db, security
from cowork.main import app

COOKIE = auth.TEN_COOKIE


# ------------------------------------------------------------------ tiện ích
def _client() -> TestClient:
    """Client sạch (không cookie) — dùng để phát lại token cũ/bịa."""
    return TestClient(app)


def _gui(token: str) -> dict[str, str]:
    return {"Cookie": f"{COOKIE}={token}"}


def _thong_bao(resp) -> dict:
    """Giải mã flash cookie của phản hồi 303 (không in nội dung ra log)."""
    raw = resp.cookies.get(config.FLASH_COOKIE)
    assert raw, "Phản hồi không có flash cookie"
    padded = raw + "=" * (-len(raw) % 4)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def _phien(token: str):
    conn = db.connect()
    try:
        return conn.execute("SELECT * FROM sessions WHERE token_hash=?",
                            (security.sha256(token),)).fetchone()
    finally:
        conn.close()


def _sua_phien(token: str, **fields) -> None:
    assert fields, "Cần ít nhất một trường để sửa"
    conn = db.connect()
    try:
        conn.execute(
            f"UPDATE sessions SET {', '.join(f'{k}=?' for k in fields)} WHERE token_hash=?",
            (*fields.values(), security.sha256(token)))
        conn.commit()
    finally:
        conn.close()


def _xoa_lich_su_dang_nhap() -> None:
    conn = db.connect()
    try:
        conn.execute("DELETE FROM login_attempts")
        conn.commit()
    finally:
        conn.close()


def _dem_sai(user_id: str) -> int:
    conn = db.connect()
    try:
        return int(conn.execute(
            "SELECT COUNT(*) FROM login_attempts WHERE user_id=? AND success=0",
            (user_id,)).fetchone()[0])
    finally:
        conn.close()


# ------------------------------------------------- 1. token giả / token cũ
def test_token_phien_gia_bi_tu_choi(client, owner):
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    token = client.cookies.get(COOKIE)
    assert token
    phien = _phien(token)
    assert phien and phien["status"] == "active"

    # Đối chứng: token thật phát lại qua header Cookie vẫn phải được nhận.
    assert _client().get("/", headers=_gui(token)).status_code == 200

    # Token bịa đúng định dạng, hash trong DB (kẻ tấn công đọc được DB cũng không
    # dùng làm token được) và ID phiên — cả ba đều phải bị từ chối.
    gia = [security.token_moi(32), phien["token_hash"], phien["id"], "x"]
    for value in gia:
        c = _client()
        r = c.get("/", headers=_gui(value), follow_redirects=False)
        assert r.status_code == 303, "Token không hợp lệ phải bị đẩy về đăng nhập"
        assert "/dang-nhap" in r.headers["location"]
        assert c.get("/api/me", headers=_gui(value)).status_code == 401

    # Token Bearer bịa cũng không được chấp nhận.
    assert _client().get("/api/me", headers={
        "Authorization": f"Bearer {security.token_moi(32)}"}).status_code == 401

    conn = db.connect()
    try:
        assert conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    finally:
        conn.close()


def test_token_cu_sau_dang_xuat_bi_tu_choi(client, owner):
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    token = client.cookies.get(COOKIE)
    assert token
    assert client.get("/api/me").status_code == 200

    assert client.post("/dang-xuat", data={"_csrf": csrf_cua(client)}, follow_redirects=False).status_code == 303
    phien = _phien(token)
    assert phien and phien["status"] == "revoked"

    # Phát lại cookie cũ bằng client sạch (mô phỏng kẻ đã đánh cắp cookie).
    c = _client()
    r = c.get("/", headers=_gui(token), follow_redirects=False)
    assert r.status_code == 303
    assert "/dang-nhap" in r.headers["location"]
    assert c.get("/api/me", headers=_gui(token)).status_code == 401


# --------------------------------------------- 2. hết hạn tuyệt đối / idle
def test_phien_het_han_tuyet_doi(client, owner):
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    token = client.cookies.get(COOKIE)
    assert token

    now = datetime.now(db.TZ).replace(microsecond=0)
    # last_seen_at = hiện tại để chắc chắn đây là hết hạn tuyệt đối, không phải idle.
    _sua_phien(token, expires_at=(now - timedelta(minutes=1)).isoformat(),
               last_seen_at=now.isoformat())

    c = _client()
    r = c.get("/", headers=_gui(token), follow_redirects=False)
    assert r.status_code == 303
    assert "/dang-nhap" in r.headers["location"]
    assert c.get("/api/me", headers=_gui(token)).status_code == 401
    assert _phien(token)["status"] == "expired"


def test_phien_idle_timeout(client, owner):
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    token = client.cookies.get(COOKIE)
    assert token

    conn = db.connect()
    try:
        idle = auth.idle_phut(conn)
    finally:
        conn.close()
    now = datetime.now(db.TZ).replace(microsecond=0)
    # expires_at còn xa, chỉ last_seen_at vượt ngưỡng idle.
    _sua_phien(token, last_seen_at=(now - timedelta(minutes=idle + 1)).isoformat(),
               expires_at=(now + timedelta(hours=2)).isoformat())

    c = _client()
    r = c.get("/", headers=_gui(token), follow_redirects=False)
    assert r.status_code == 303
    assert "/dang-nhap" in r.headers["location"]
    assert c.get("/api/me", headers=_gui(token)).status_code == 401
    assert _phien(token)["status"] == "expired"


# ------------------------------------------------ 3. tài khoản khoá giữa phiên
def test_tai_khoan_bi_khoa_giua_phien(client, owner):
    tao_user("employee", "emp-bi-khoa", dept="kinh-doanh")
    c = _client()
    assert dang_nhap(c, "emp-bi-khoa", "User!Passw0rd").status_code == 303
    token = c.cookies.get(COOKIE)
    assert token
    assert c.get("/api/me").status_code == 200

    conn = db.connect()
    try:
        conn.execute("UPDATE users SET status='suspended' WHERE id='emp-bi-khoa'")
        conn.commit()
    finally:
        conn.close()

    r = c.get("/", follow_redirects=False)
    assert r.status_code == 303
    assert "/dang-nhap" in r.headers["location"]
    assert c.get("/api/me").status_code == 401
    phien = _phien(token)
    assert phien and phien["status"] == "revoked"
    assert "Tài khoản" in (phien["revoke_reason"] or "")


# ---------------------------------------------------------- 4. thuộc tính cookie
def test_cookie_httponly_samesite_lax_secure_khi_https(client, owner, monkeypatch):
    r = dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    header = r.headers.get("set-cookie", "")
    assert COOKIE in header
    assert "HttpOnly" in header
    assert "SameSite=lax" in header
    assert "Path=/" in header
    # Môi trường test chạy HTTP, COOKIE_SECURE=0 → không được gắn Secure.
    assert "Secure" not in header

    # HTTPS thật (base_url https) → cookie phải có Secure và vẫn đăng nhập được.
    c_https = TestClient(app, base_url="https://testserver")
    r_https = dang_nhap(c_https, "anh-thanh", "Owner!Passw0rd")
    header_https = r_https.headers.get("set-cookie", "")
    assert "Secure" in header_https and "HttpOnly" in header_https
    assert "SameSite=lax" in header_https
    assert c_https.get("/api/me").status_code == 200

    # X-Forwarded-Proto chỉ được tin khi COWORK_TIN_PROXY=1 (sau Caddy đã ghi đè header).
    def _qua_proxy():
        c_proxy = _client()
        token_csrf = csrf_tu(c_proxy.get("/dang-nhap").text)
        return c_proxy.post("/dang-nhap", data={
            "userId": "anh-thanh", "matKhau": "Owner!Passw0rd", "_csrf": token_csrf,
            "next": "/"}, headers={"X-Forwarded-Proto": "https"}, follow_redirects=False)
    assert "Secure" not in _qua_proxy().headers.get("set-cookie", "")
    assert "strict-transport-security" not in _qua_proxy().headers
    monkeypatch.setattr(config, "TIN_PROXY", True)
    r_proxy = _qua_proxy()
    assert "Secure" in r_proxy.headers.get("set-cookie", "")
    assert "strict-transport-security" in r_proxy.headers


# ------------------------------------------------------------------ 5. CSRF
def test_csrf_thieu_sai_va_token_cua_phien_khac(client, owner):
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    csrf_a = csrf_cua(client)
    payload = {"display_name": "Tên Bị Đổi", "email": "bi-doi@test.local"}

    assert client.post("/ho-so", data=payload).status_code == 403
    assert client.post("/ho-so", data={**payload, "_csrf": security.token_moi(24)}
                       ).status_code == 403

    # Phiên thứ hai của CÙNG người dùng: token CSRF của phiên đó không dùng được.
    c2 = _client()
    assert dang_nhap(c2, "anh-thanh", "Owner!Passw0rd").status_code == 303
    csrf_b = csrf_cua(c2)
    assert csrf_b != csrf_a
    assert client.post("/ho-so", data={**payload, "_csrf": csrf_b}).status_code == 403

    # Cả ba lần đều không có tác dụng phụ.
    conn = db.connect()
    try:
        assert conn.execute("SELECT display_name FROM users WHERE id='anh-thanh'"
                            ).fetchone()[0] == "anh-thanh"
    finally:
        conn.close()

    # Đối chứng: token đúng của chính phiên thì cập nhật thành công.
    assert client.post("/ho-so", data={**payload, "_csrf": csrf_a},
                       follow_redirects=False).status_code == 303
    conn = db.connect()
    try:
        assert conn.execute("SELECT display_name FROM users WHERE id='anh-thanh'"
                            ).fetchone()[0] == "Tên Bị Đổi"
    finally:
        conn.close()


# -------------------------------------------------------------- 6. rate limit
def test_rate_limit_5_lan_sai_tren_10_phut_theo_user_ip(client, owner):
    tao_user("employee", "emp-gioi-han", dept="kinh-doanh")
    for _ in range(5):
        assert dang_nhap(client, "emp-gioi-han", "SaiMatKhau!").status_code == 303

    # Lần thứ 6: mật khẩu đúng vẫn bị chặn trong cửa sổ 10 phút.
    r = dang_nhap(client, "emp-gioi-han", "User!Passw0rd")
    assert r.status_code == 303
    assert "tạm khoá" in _thong_bao(r)["m"].lower()
    assert _dem_sai("emp-gioi-han") == 5

    # Người dùng khác không bị ảnh hưởng.
    tao_user("employee", "emp-ngoai-vung", dept="kinh-doanh")
    c2 = _client()
    assert "Bảng điều khiển" in dang_nhap(c2, "emp-ngoai-vung", "User!Passw0rd",
                                          follow=True).text

    # Cùng người dùng nhưng IP khác không bị chặn (rate limit theo user+IP).
    c3 = TestClient(app, client=("203.0.113.9", 4444))
    assert "Bảng điều khiển" in dang_nhap(c3, "emp-gioi-han", "User!Passw0rd",
                                          follow=True).text

    # Bản ghi sai ra ngoài cửa sổ 10 phút thì không còn tính.
    cu = (datetime.now(db.TZ) - timedelta(minutes=config.LOGIN_WINDOW_MIN + 1)
          ).replace(microsecond=0).isoformat()
    conn = db.connect()
    try:
        conn.execute("UPDATE login_attempts SET created_at=? WHERE user_id='emp-gioi-han'",
                     (cu,))
        conn.commit()
    finally:
        conn.close()
    c4 = _client()
    assert "Bảng điều khiển" in dang_nhap(c4, "emp-gioi-han", "User!Passw0rd",
                                          follow=True).text


# ------------------------------------------- 7. không lộ user tồn tại (thông báo)
def test_thong_bao_khong_lo_user_ton_tai(client, owner):
    c_co = _client()
    c_khong = _client()
    m_co = _thong_bao(dang_nhap(c_co, "anh-thanh", "SaiMatKhau!"))
    m_khong = _thong_bao(dang_nhap(c_khong, "khong-ton-tai-ag02", "SaiMatKhau!"))
    assert m_co["m"] == m_khong["m"] == "Sai ID hoặc mật khẩu."
    assert m_co["k"] == m_khong["k"] == "err"

    # Sau 5 lần sai, thông báo tạm khoá cũng phải giống hệt nhau.
    for _ in range(4):
        dang_nhap(c_co, "anh-thanh", "SaiMatKhau!")
        dang_nhap(c_khong, "khong-ton-tai-ag02", "SaiMatKhau!")
    r_co = _thong_bao(dang_nhap(c_co, "anh-thanh", "Owner!Passw0rd"))
    r_khong = _thong_bao(dang_nhap(c_khong, "khong-ton-tai-ag02", "SaiMatKhau!"))
    assert r_co["m"] == r_khong["m"]
    assert "tạm khoá" in r_co["m"].lower()


# --------------------------------------- 8. thời gian trả lời không lộ user tồn tại
def test_thoi_gian_tra_loi_khong_lo_user_ton_tai(client, owner):
    c = _client()
    token_csrf = csrf_tu(c.get("/dang-nhap").text)

    def thu(user_id: str) -> float:
        bat_dau = time.perf_counter()
        r = c.post("/dang-nhap", data={
            "userId": user_id, "matKhau": "SaiMatKhau!", "_csrf": token_csrf},
                   follow_redirects=False)
        assert r.status_code == 303
        return time.perf_counter() - bat_dau

    # Làm nóng cache + tránh ảnh hưởng lần đo đầu.
    thu("khong-ton-tai-warmup")
    _xoa_lich_su_dang_nhap()
    thu("anh-thanh")
    _xoa_lich_su_dang_nhap()

    khong_ton_tai: list[float] = []
    co_ton_tai: list[float] = []
    for i in range(5):
        khong_ton_tai.append(thu(f"khong-ton-tai-do-dai-{i}"))
        _xoa_lich_su_dang_nhap()
        co_ton_tai.append(thu("anh-thanh"))
        _xoa_lich_su_dang_nhap()  # tránh chạm ngưỡng khoá 5 lần

    trung_binh_khong = statistics.median(khong_ton_tai)
    trung_binh_co = statistics.median(co_ton_tai)
    # Cả hai phải thật sự chạy scrypt (không trả lời tức thì vì "user không tồn tại").
    assert trung_binh_khong > 0.005
    assert trung_binh_co > 0.005
    # Chênh lệch tương đối rộng để không flaky, nhưng chặn lộ kiểu 2x trở lên.
    assert 0.4 <= trung_binh_khong / trung_binh_co <= 2.5


# -------------------------------- 9. đổi mật khẩu thu hồi mọi phiên khác
def test_doi_mat_khau_thu_hoi_moi_phien_khac(client, owner):
    c2 = _client()
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    assert dang_nhap(c2, "anh-thanh", "Owner!Passw0rd").status_code == 303
    token_cu_a = client.cookies.get(COOKIE)
    token_cu_b = c2.cookies.get(COOKIE)
    assert token_cu_a and token_cu_b and token_cu_a != token_cu_b

    r = client.post("/doi-mat-khau", data={
        "_csrf": csrf_cua(client),
        "matKhauCu": "Owner!Passw0rd",
        "matKhauMoi": "Owner!MoiPass1",
        "nhapLai": "Owner!MoiPass1",
    }, follow_redirects=False)
    assert r.status_code == 303
    token_moi = client.cookies.get(COOKIE)
    assert token_moi and token_moi not in (token_cu_a, token_cu_b)
    assert client.get("/api/me").status_code == 200

    for token in (token_cu_a, token_cu_b):
        phien = _phien(token)
        assert phien and phien["status"] == "revoked"
        assert "Đổi mật khẩu" in (phien["revoke_reason"] or "")
        assert _client().get("/api/me", headers=_gui(token)).status_code == 401

    # Phiên B (cùng người dùng) bị đẩy ra ngay ở request kế tiếp.
    r_b = c2.get("/", follow_redirects=False)
    assert r_b.status_code == 303
    assert "/dang-nhap" in r_b.headers["location"]

    # Mật khẩu mới dùng được, mật khẩu cũ không còn.
    assert "Bảng điều khiển" in dang_nhap(_client(), "anh-thanh", "Owner!MoiPass1",
                                          follow=True).text
    assert "Bảng điều khiển" not in dang_nhap(_client(), "anh-thanh", "Owner!Passw0rd",
                                              follow=True).text


# -------------------------------- 10. đặt lại mật khẩu thu hồi mọi phiên
def test_dat_lai_mat_khau_thu_hoi_moi_phien(client, owner):
    tao_user("employee", "emp-dat-lai", dept="kinh-doanh")
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303
    c2 = _client()
    assert dang_nhap(c2, "emp-dat-lai", "User!Passw0rd").status_code == 303
    token = c2.cookies.get(COOKIE)
    assert token
    assert c2.get("/api/me").status_code == 200

    r = client.post("/tai-khoan/emp-dat-lai/dat-lai-mat-khau",
                    data={"_csrf": csrf_cua(client)})
    assert r.status_code == 200
    m = re.search(r'id="mat-khau-tam">([^<]+)</code>', r.text)
    assert m, "Trang kết quả phải hiện mật khẩu tạm một lần"
    temp = html.unescape(m.group(1))  # Jinja escape ký tự & trong mật khẩu tạm

    phien = _phien(token)
    assert phien and phien["status"] == "revoked"
    assert "Đặt lại mật khẩu" in (phien["revoke_reason"] or "")
    assert c2.get("/api/me").status_code == 401

    # Mật khẩu cũ chết, mật khẩu tạm đăng nhập được và buộc đổi ngay.
    assert "Bảng điều khiển" not in dang_nhap(_client(), "emp-dat-lai",
                                              "User!Passw0rd", follow=True).text
    c3 = _client()
    r3 = dang_nhap(c3, "emp-dat-lai", temp)
    assert r3.status_code == 303
    assert r3.headers.get("location") == "/doi-mat-khau"


# --------------------------- 11. DB chỉ lưu hash scrypt + salt, không token thô
def test_db_chi_luu_hash_scrypt_va_khong_luu_token_tho(client, owner):
    mat_khau = "Owner!Passw0rd"
    assert dang_nhap(client, "anh-thanh", mat_khau).status_code == 303
    token = client.cookies.get(COOKIE)
    assert token

    conn = db.connect()
    try:
        user = conn.execute("SELECT * FROM users WHERE id='anh-thanh'").fetchone()
        phien = conn.execute("SELECT * FROM sessions WHERE token_hash=?",
                             (security.sha256(token),)).fetchone()
        assert user and phien
        assert user["password_algo"] == "scrypt"
        assert user["password_hash"] != mat_khau
        hash_bytes = base64.b64decode(user["password_hash"])
        salt_bytes = base64.b64decode(user["password_salt"])
        assert len(hash_bytes) == 32 and len(salt_bytes) == 16
        assert hash_bytes != salt_bytes
        assert security.kiem_mat_khau(mat_khau, user["password_hash"], user["password_salt"])
        assert not security.kiem_mat_khau("SaiMatKhau!", user["password_hash"],
                                         user["password_salt"])
        assert phien["token_hash"] == security.sha256(token)
        assert phien["token_hash"] != token

        # Quét toàn bộ bảng: không bảng/cột nào chứa mật khẩu hay token thô.
        bang = [r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        for ten_bang in bang:
            for row in conn.execute(f"SELECT * FROM {ten_bang}").fetchall():
                for gia_tri in row:
                    if isinstance(gia_tri, str):
                        assert token not in gia_tri
                        assert mat_khau not in gia_tri
    finally:
        conn.close()


# ----------------------- 12. đăng nhập đúng phải xoá bộ đếm sai (chống khoá oan)
def test_dang_nhap_thanh_cong_xoa_bo_dem_sai(client, owner):
    for _ in range(4):
        assert dang_nhap(client, "anh-thanh", "SaiMatKhau!").status_code == 303
    assert dang_nhap(client, "anh-thanh", "Owner!Passw0rd").status_code == 303

    # Đăng xuất rồi gõ sai 1 lần; nếu bộ đếm cũ còn thì lần đúng này bị khoá oan.
    assert client.post("/dang-xuat", data={"_csrf": csrf_cua(client)}, follow_redirects=False).status_code == 303
    assert dang_nhap(client, "anh-thanh", "SaiMatKhau!").status_code == 303
    r = dang_nhap(client, "anh-thanh", "Owner!Passw0rd", follow=True)
    assert "Bảng điều khiển" in r.text
    assert _dem_sai("anh-thanh") == 0


# ------------------ 13. giới hạn 8 phiên không thu hồi chính phiên vừa tạo
def test_gioi_han_8_phien_khong_thu_hoi_phien_vua_tao(client, owner):
    for _ in range(8):
        c = _client()
        assert dang_nhap(c, "anh-thanh", "Owner!Passw0rd").status_code == 303

    # Mô phỏng đồng hồ bị lùi/trùng giây: 8 phiên cũ mang created_at "mới hơn"
    # phiên sắp tạo. Cách sắp xếp cũ sẽ thu hồi nhầm chính phiên vừa tạo.
    conn = db.connect()
    try:
        conn.execute("UPDATE sessions SET created_at='2030-01-01T00:00:00+07:00' "
                     "WHERE user_id='anh-thanh' AND status='active'")
        conn.commit()
    finally:
        conn.close()

    c9 = _client()
    assert dang_nhap(c9, "anh-thanh", "Owner!Passw0rd").status_code == 303
    token = c9.cookies.get(COOKIE)
    assert token
    phien = _phien(token)
    assert phien is not None and phien["status"] == "active"
    assert c9.get("/api/me").status_code == 200

    conn = db.connect()
    try:
        so_active = conn.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id='anh-thanh' AND status='active'"
        ).fetchone()[0]
    finally:
        conn.close()
    assert so_active == 8
