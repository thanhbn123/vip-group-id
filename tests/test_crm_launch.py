"""COWORK → CRM (§15.6): launch token `cowork-launch/1`, phân quyền backend, audit, CSP.

Có một kiểm thử liên thông chạy CHÍNH bộ xác minh của CRM (Node, chỉ đọc từ repo CRM);
tự bỏ qua nếu máy không có node hoặc bản checkout CRM.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import csrf_cua, dang_nhap, tao_user

from cowork import config, crm_launch, db

BI_MAT = "crm-launch-test-secret-0123456789abcdefXYZ"
CRM_TOKENS_JS = Path(os.environ.get(
    "CRM_TOKENS_JS",
    str(Path.home() / "Projects/vip-group-khoqctq/server/modules/adapters/tokens.js")))


@pytest.fixture(autouse=True)
def _bi_mat(monkeypatch):
    monkeypatch.setenv("COWORK_CRM_LAUNCH_SECRET", BI_MAT)
    monkeypatch.setattr(config, "CRM_TENANT_MAP", {"vip-group": "VIP"})


def _giai(token: str) -> tuple[dict, dict]:
    h, p, s = token.split(".")
    pad = lambda x: x + "=" * (-len(x) % 4)  # noqa: E731
    mong = base64.urlsafe_b64encode(
        hmac.new(BI_MAT.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
    assert hmac.compare_digest(mong, s), "chữ ký sai"
    return (json.loads(base64.urlsafe_b64decode(pad(h))), json.loads(base64.urlsafe_b64decode(pad(p))))


def _token_tu_redirect(r) -> str:
    assert r.status_code == 303, r.text[:300]
    u = urlsplit(r.headers["location"])
    assert f"{u.scheme}://{u.netloc}{u.path}" == "https://crm.vipgroup.com.vn/api/auth/cowork/launch"
    return parse_qs(u.query)["token"][0]


# ───────── token ─────────

def test_token_dung_dinh_dang_va_claim():
    tok, p = crm_launch.tao_token({"id": "nv-01", "tenant_id": "vip-group"}, now=1_800_000_000)
    header, payload = _giai(tok)
    assert header == {"alg": "HS256", "typ": "JWT"}
    assert payload == p
    assert list(payload) == ["ver", "aud", "sub", "tenant_code", "iat", "exp", "nonce"]
    assert payload["ver"] == 1 and payload["aud"] == "vip-crm"
    assert payload["sub"] == "cowork:nv-01" and payload["tenant_code"] == "VIP"
    assert payload["exp"] - payload["iat"] == 60
    assert 8 <= len(payload["nonce"]) <= 200
    assert "role" not in payload


def test_nonce_moi_lan_khac_nhau():
    u = {"id": "nv-01", "tenant_id": "vip-group"}
    assert crm_launch.tao_token(u)[1]["nonce"] != crm_launch.tao_token(u)[1]["nonce"]


@pytest.mark.parametrize("ttl", [0, -5, 61, 3600])
def test_ttl_ngoai_1_60_bi_tu_choi(monkeypatch, ttl):
    monkeypatch.setattr(config, "CRM_LAUNCH_TTL", ttl)
    assert any("COWORK_CRM_LAUNCH_TTL" in x for x in crm_launch.loi_cau_hinh())
    with pytest.raises(RuntimeError):
        crm_launch.tao_token({"id": "x", "tenant_id": "vip-group"})


def test_ttl_hop_le_duoc_dung(monkeypatch):
    monkeypatch.setattr(config, "CRM_LAUNCH_TTL", 30)
    _, p = crm_launch.tao_token({"id": "x", "tenant_id": "vip-group"})
    assert p["exp"] - p["iat"] == 30


@pytest.mark.parametrize("env", ["prod", "production", "PROD"])
def test_http_bi_chan_o_moi_ten_production(monkeypatch, env):
    monkeypatch.setattr(config, "ENV", env)
    monkeypatch.setattr(config, "CRM_PUBLIC_URL", "http://crm.vipgroup.com.vn")
    assert any("https://" in x for x in crm_launch.loi_cau_hinh())


def test_http_cho_phep_o_local(monkeypatch):
    monkeypatch.setattr(config, "ENV", "local")
    monkeypatch.setattr(config, "CRM_PUBLIC_URL", "http://127.0.0.1:8080")
    assert not crm_launch.loi_cau_hinh()


def test_trung_bi_mat_portal_nap_tu_tep(monkeypatch, tmp_path):
    f = tmp_path / "portal.key"
    f.write_text(BI_MAT + "\n")
    monkeypatch.delenv("VIPID_PORTAL_SECRET", raising=False)
    monkeypatch.setattr(config, "PORTAL_SECRET_FILE", f)
    assert any("KHÁC" in x for x in crm_launch.loi_cau_hinh())


def test_kiem_portal_khong_sinh_tep(monkeypatch, tmp_path):
    f = tmp_path / "portal-chua-co.key"
    monkeypatch.delenv("VIPID_PORTAL_SECRET", raising=False)
    monkeypatch.setattr(config, "PORTAL_SECRET_FILE", f)
    assert not crm_launch.loi_cau_hinh() and not f.exists()


def test_chieu_nguoc_trung_voi_launch_crm():
    assert crm_launch.trung_voi_launch_crm(BI_MAT)
    assert not crm_launch.trung_voi_launch_crm("khac-" + BI_MAT)
    assert not crm_launch.trung_voi_launch_crm("")


@pytest.mark.parametrize("gia_tri, mau", [
    ("", "Chưa cấu hình"),
    ("ngan-qua", "ít nhất 32"),
    ("change-me-change-me-change-me-change-me", "giá trị mẫu"),
])
def test_bi_mat_khong_hop_le_thi_tu_choi(monkeypatch, tmp_path, gia_tri, mau):
    monkeypatch.setenv("COWORK_CRM_LAUNCH_SECRET", gia_tri)
    monkeypatch.setattr(config, "CRM_LAUNCH_SECRET_FILE", tmp_path / "khong-co.key")
    assert any(mau in x for x in crm_launch.loi_cau_hinh())
    with pytest.raises(RuntimeError):
        crm_launch.tao_token({"id": "x", "tenant_id": "vip-group"})


def test_bi_mat_trung_bi_mat_khac_bi_tu_choi(monkeypatch):
    monkeypatch.setenv("COWORK_CRM_LAUNCH_SECRET", config.SECRET_KEY)
    assert any("KHÁC" in x for x in crm_launch.loi_cau_hinh())


def test_khong_tu_sinh_bi_mat(monkeypatch, tmp_path):
    monkeypatch.delenv("COWORK_CRM_LAUNCH_SECRET")
    f = tmp_path / "crm.key"
    monkeypatch.setattr(config, "CRM_LAUNCH_SECRET_FILE", f)
    assert crm_launch.bi_mat() == "" and not f.exists()


def test_tenant_chua_anh_xa_khong_ky():
    with pytest.raises(RuntimeError):
        crm_launch.tao_token({"id": "x", "tenant_id": "tenant-b"})


# ───────── route + quyền ─────────

def test_owner_mo_crm_va_audit_khong_luu_token(client, owner):
    dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    trang = client.get("/crm")
    assert trang.status_code == 200 and "cowork:anh-thanh" in trang.text
    r = client.post("/crm/mo", data={"_csrf": csrf_cua(client)}, follow_redirects=False)
    tok = _token_tu_redirect(r)
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["referrer-policy"] == "no-referrer"
    _, p = _giai(tok)
    assert p["sub"] == "cowork:anh-thanh"
    conn = db.connect()
    try:
        row = conn.execute("SELECT * FROM audit_log WHERE action='crm.launch' ORDER BY id DESC").fetchone()
    finally:
        conn.close()
    assert row and json.loads(row["detail"])["nonce"] == p["nonce"]
    assert tok not in (row["detail"] or "") and tok.split(".")[2] not in (row["detail"] or "")


def test_mo_crm_bat_buoc_csrf_va_post(client, owner):
    dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    assert client.post("/crm/mo", data={}, follow_redirects=False).status_code in (400, 403)
    assert client.get("/crm/mo", follow_redirects=False).status_code in (404, 405)


def test_chua_dang_nhap_khong_mo_duoc(client, owner):
    r = client.get("/crm", follow_redirects=False)
    assert r.status_code in (302, 303, 401)
    assert "crm.vipgroup" not in r.headers.get("location", "")


def test_nhan_vien_mac_dinh_khong_thay_crm(client, owner):
    tao_user("employee", "emp-crm", dept="kinh-doanh")
    dang_nhap(client, "emp-crm", "User!Passw0rd")
    assert "crm" not in client.get("/api/me").json()["data"]["modules"]
    assert client.get("/crm").status_code == 403
    r = client.post("/crm/mo", data={"_csrf": csrf_cua(client)}, follow_redirects=False)
    assert r.status_code == 403


def _cap(user_id: str, *perms: str, effect: str = "allow") -> None:
    conn = db.connect()
    try:
        for p in perms:
            conn.execute("INSERT INTO user_permissions(tenant_id, user_id, permission_code, effect, "
                         "granted_by, granted_at) VALUES('vip-group',?,?,?,?, datetime('now'))",
                         (user_id, p, effect, "anh-thanh"))
    finally:
        conn.close()


def test_nhan_vien_duoc_cap_rieng_thi_mo_duoc(client, owner):
    tao_user("employee", "emp-crm2", dept="kinh-doanh")
    _cap("emp-crm2", "crm.view", "crm.use")
    dang_nhap(client, "emp-crm2", "User!Passw0rd")
    assert client.get("/crm").status_code == 200
    tok = _token_tu_redirect(client.post("/crm/mo", data={"_csrf": csrf_cua(client)},
                                         follow_redirects=False))
    assert _giai(tok)[1]["sub"] == "cowork:emp-crm2"


def test_chi_co_view_khong_phat_token(client, owner):
    tao_user("employee", "emp-crm3", dept="kinh-doanh")
    _cap("emp-crm3", "crm.view")
    dang_nhap(client, "emp-crm3", "User!Passw0rd")
    assert client.get("/crm").status_code == 200
    assert client.post("/crm/mo", data={"_csrf": csrf_cua(client)},
                       follow_redirects=False).status_code == 403


def test_doi_tac_bi_chan_du_duoc_cap_quyen(client, owner):
    tao_user("partner", "dt-crm")
    _cap("dt-crm", "crm.view", "crm.use")
    dang_nhap(client, "dt-crm", "User!Passw0rd")
    assert client.get("/crm").status_code == 403
    assert client.post("/crm/mo", data={"_csrf": csrf_cua(client)},
                       follow_redirects=False).status_code == 403


def test_thu_hoi_quyen_co_hieu_luc_ngay(client, owner):
    tao_user("employee", "emp-crm4", dept="kinh-doanh")
    _cap("emp-crm4", "crm.view", "crm.use")
    dang_nhap(client, "emp-crm4", "User!Passw0rd")
    csrf = csrf_cua(client)
    conn = db.connect()
    try:
        conn.execute("DELETE FROM user_permissions WHERE user_id='emp-crm4' AND permission_code='crm.use'")
    finally:
        conn.close()
    assert client.post("/crm/mo", data={"_csrf": csrf}, follow_redirects=False).status_code == 403


def test_chua_cau_hinh_thi_khong_phat_token(client, owner, monkeypatch, tmp_path):
    monkeypatch.delenv("COWORK_CRM_LAUNCH_SECRET")
    monkeypatch.setattr(config, "CRM_LAUNCH_SECRET_FILE", tmp_path / "khong-co.key")
    dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    assert "Chưa cấu hình COWORK_CRM_LAUNCH_SECRET" in client.get("/crm").text
    r = client.post("/crm/mo", data={"_csrf": csrf_cua(client)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/crm"


def test_tenant_chua_anh_xa_thi_khong_phat_token(client, owner, monkeypatch):
    monkeypatch.setattr(config, "CRM_TENANT_MAP", {})
    dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    r = client.post("/crm/mo", data={"_csrf": csrf_cua(client)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/crm"


def test_csp_form_action_cho_phep_dung_origin_crm(client, owner):
    dang_nhap(client, "anh-thanh", "Owner!Passw0rd")
    csp = client.get("/crm").headers["content-security-policy"]
    fa = next(x for x in csp.split(";") if x.strip().startswith("form-action")).split()
    assert "https://crm.vipgroup.com.vn" in fa and "'self'" in fa
    assert not any(x in ("*", "https:", "https://*.vipgroup.com.vn") for x in fa)


def test_seed_moi_cap_crm_cho_admin_khong_cho_nhan_vien():
    from cowork.schema import ROLE_PERMISSIONS_MAC_DINH as M
    assert {"crm.view", "crm.use"} <= set(M["admin"])
    assert not {"crm.view", "crm.use"} & set(M["employee"] + M["partner"] + M["department_manager"])


# ───────── liên thông với bộ xác minh thật của CRM ─────────

@pytest.mark.skipif(not (shutil.which("node") and CRM_TOKENS_JS.is_file()),
                    reason="cần node + checkout vip-group-khoqctq")
def test_lien_thong_voi_verify_cowork_token_cua_crm():
    tok, p = crm_launch.tao_token({"id": "anh-thanh", "tenant_id": "vip-group"})
    sai = tok[:-2] + ("AA" if not tok.endswith("AA") else "BB")
    js = (f"import {{ verifyCoworkToken }} from {json.dumps(CRM_TOKENS_JS.as_uri())};"
          "const [s,a,b]=process.argv.slice(1);"
          "console.log(JSON.stringify([verifyCoworkToken(s,a), verifyCoworkToken(s,b),"
          " verifyCoworkToken('khac-'+s,a)]));")
    out = subprocess.run(["node", "--input-type=module", "-e", js, BI_MAT, tok, sai],
                         capture_output=True, text=True, timeout=30, check=True)
    ok, hong, sai_khoa = json.loads(out.stdout)
    assert ok == {"payload": p}
    assert hong == {"error": "TOKEN_SIGNATURE"}
    assert sai_khoa == {"error": "TOKEN_SIGNATURE"}


# ───────── chiều ngược trong khach.kiem_cau_hinh (vòng 9 B-2) ─────────

@pytest.fixture()
def realm_khach_bat(monkeypatch):
    monkeypatch.setattr(config, "KHACH_ENABLED", True)
    monkeypatch.setattr(config, "KHACH_HOSTS", ["khach.localhost:8898", "khach.localhost"])
    monkeypatch.setattr(config, "STAFF_HOSTS", ["testserver"])
    monkeypatch.setattr(config, "CRM_PORTAL_PUBLIC_URL", "http://crm.localhost:8897")
    monkeypatch.setattr(config, "CRM_PORTAL_INTERNAL_URL", "http://127.0.0.1:8897")


def test_khach_tu_choi_portal_secret_trung_launch_crm(monkeypatch, realm_khach_bat):
    from cowork import khach
    monkeypatch.setattr(khach, "_bi_mat_cache", BI_MAT)
    with pytest.raises(RuntimeError, match="KHÁC COWORK_CRM_LAUNCH_SECRET"):
        khach.kiem_cau_hinh()


def test_khach_portal_secret_khac_launch_crm_thi_khong_bao(monkeypatch, realm_khach_bat):
    from cowork import khach
    monkeypatch.setattr(khach, "_bi_mat_cache", "portal-" + BI_MAT)
    try:
        khach.kiem_cau_hinh()
    except RuntimeError as e:
        assert "COWORK_CRM_LAUNCH_SECRET" not in str(e)
