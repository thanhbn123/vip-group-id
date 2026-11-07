"""E2E thật COWORK (feature/cowork-crm, uvicorn local) → CRM local test (127.0.0.1:5197).

Không ghi token/bí mật ra kết quả. Bằng chứng: JSON gồm mã HTTP, mã lỗi, danh tính CRM.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

REPO = Path.home() / "code/vip-group-id-cowork-crm"
HERE = Path(__file__).resolve().parent
DATA = HERE / "data"
SECRET_FILE = sys.argv[1]
CRM = "http://127.0.0.1:5197"
PORT = 8911
COWORK = f"http://127.0.0.1:{PORT}"

env = dict(os.environ,
           COWORK_DATA_DIR=str(DATA), COWORK_DB_PATH=str(DATA / "cowork.db"),
           COWORK_ENV="local", COWORK_COOKIE_SECURE="0", COWORK_BRAIN_ENABLED="0",
           COWORK_STAFF_HOSTS=f"127.0.0.1:{PORT}", COWORK_KHACH_ENABLED="0",
           COWORK_CRM_ENABLED="1", COWORK_CRM_PUBLIC_URL=CRM, COWORK_CRM_TENANT_MAP="vip-group=VIP",
           COWORK_CRM_LAUNCH_SECRET_FILE=SECRET_FILE, PYTHONPATH=str(REPO))
env.pop("COWORK_CRM_LAUNCH_SECRET", None)
PY = str(REPO / ".venv/bin/python")
PW = "E2e!Passw0rd-local"

SETUP = r'''
import sys
from cowork import auth, db, rbac, services
db.init_db()
conn = db.connect()
pw = sys.argv[1]
services.tao_super_admin(conn, "anh-thanh", pw, "anh-thanh")
actor = auth.nguoi_dung_day_du(conn, "anh-thanh"); perms = rbac.quyen_hieu_luc(conn, actor)
for uid, role in [("nv-kho-sz","employee"),("nv-chua-lk","employee"),("khach-thu","employee"),
                  ("nv-khong-quyen","employee"),("dt-01","partner")]:
    services.tao_nguoi_dung(conn, actor, perms, {"id": uid, "display_name": uid, "email": uid+"@e2e.local",
        "role_code": role, "department_id": "kinh-doanh" if role=="employee" else "", "password": pw,
        "must_change": "0", "scope_mode": "tenant", "scope_departments": [],
        "partner_org": "DT" if role=="partner" else ""})
for uid in ["nv-kho-sz","nv-chua-lk","khach-thu","dt-01"]:
    for p in ["crm.view","crm.use"]:
        conn.execute("INSERT INTO user_permissions(tenant_id,user_id,permission_code,effect,granted_by,granted_at) "
                     "VALUES('vip-group',?,?,'allow','anh-thanh',datetime('now'))", (uid, p))
conn.close()
print("setup ok")
'''


def csrf(html: str) -> str:
    return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)


def login(uid: str) -> httpx.Client:
    c = httpx.Client(base_url=COWORK, follow_redirects=False, timeout=10)
    r = c.get("/dang-nhap")
    r = c.post("/dang-nhap", data={"userId": uid, "matKhau": PW, "_csrf": csrf(r.text), "next": "/"})
    assert r.status_code == 303, (uid, r.status_code, r.text[:200])
    return c


def launch_url(c: httpx.Client) -> tuple[int, str]:
    page = c.get("/crm")
    if page.status_code != 200:
        return page.status_code, ""
    r = c.post("/crm/mo", data={"_csrf": csrf(page.text)})
    return r.status_code, r.headers.get("location", "")


def crm_open(url: str) -> dict:
    with httpx.Client(follow_redirects=False, timeout=10) as b:
        r = b.get(url)
        out = {"status": r.status_code, "location": r.headers.get("location")}
        try:
            out["error"] = r.json().get("error") or r.json().get("code")
        except Exception:  # noqa: BLE001
            pass
        ck = r.cookies.get("vip_session")
        out["cookie_vip_session"] = bool(ck)
        sc = r.headers.get("set-cookie", "")
        out["cookie_flags"] = [f for f in ("HttpOnly", "SameSite=Strict", "Secure") if f.lower() in sc.lower()]
        if ck:
            me = b.get(CRM + "/api/me", cookies={"vip_session": ck})
            j = me.json()
            u = j.get("user") or j
            out["crm_me"] = {"status": me.status_code, "username": u.get("username"),
                             "tenant": (j.get("tenant") or {}).get("code") if isinstance(j.get("tenant"), dict) else j.get("tenant_code"),
                             "role": j.get("role") or (j.get("membership") or {}).get("role")}
        return out


def main() -> None:
    DATA.mkdir(mode=0o700, exist_ok=True)
    print(subprocess.run([PY, "-c", SETUP, PW], env=env, cwd=str(HERE), capture_output=True, text=True, check=True).stdout.strip())
    srv = subprocess.Popen([PY, "-m", "uvicorn", "cowork.main:app", "--host", "127.0.0.1", "--port", str(PORT)],
                           env=env, cwd=str(HERE), stdout=open(HERE / "uvicorn.log", "w"), stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                if httpx.get(COWORK + "/api/health", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.2)
        kq: dict = {"cowork_commit": subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
                                                    capture_output=True, text=True).stdout.strip(),
                    "crm": CRM, "cases": {}}
        C = kq["cases"]

        c = login("anh-thanh")
        csp = c.get("/crm").headers.get("content-security-policy", "")
        C["csp_form_action"] = next(x.strip() for x in csp.split(";") if "form-action" in x)
        st, url = launch_url(c)
        C["A_owner_launch"] = {"cowork": st, "dest": urlsplit(url).path, **crm_open(url)}
        C["B_replay_same_url"] = crm_open(url)

        st, url = launch_url(login("nv-kho-sz"))
        C["C_staff_kho"] = {"cowork": st, **crm_open(url)}

        st, url = launch_url(login("nv-chua-lk"))
        C["D_unlinked"] = {"cowork": st, **crm_open(url)}

        st, url = launch_url(login("khach-thu"))
        C["E_customer_kind"] = {"cowork": st, **crm_open(url)}

        c = login("nv-khong-quyen")
        C["F_no_permission"] = {"get_crm": c.get("/crm").status_code,
                                "post_mo": c.post("/crm/mo", data={"_csrf": csrf(c.get("/ho-so").text)}).status_code}

        c = login("dt-01")
        C["G_partner_granted"] = {"get_crm": c.get("/crm").status_code,
                                  "post_mo": c.post("/crm/mo", data={"_csrf": csrf(c.get("/ho-so").text)}).status_code}

        st, url = launch_url(login("nv-kho-sz"))
        time.sleep(62)
        C["H_expired_62s"] = {"cowork": st, **crm_open(url)}

        conn_out = subprocess.run([PY, "-c",
            "from cowork import db;c=db.connect();import json;"
            "print(json.dumps([dict(r) for r in c.execute(\"SELECT actor_id, detail FROM audit_log WHERE action='crm.launch'\")]))"],
            env=env, cwd=str(HERE), capture_output=True, text=True, check=True).stdout
        rows = json.loads(conn_out)
        C["I_audit"] = {"rows": len(rows), "actors": sorted({r["actor_id"] for r in rows}),
                        "token_in_audit": any("eyJ" in (r["detail"] or "") for r in rows)}
        (HERE / "result.json").write_text(json.dumps(kq, ensure_ascii=False, indent=2))
        print(json.dumps(kq, ensure_ascii=False, indent=2))
    finally:
        srv.terminate()
        srv.wait(10)


if __name__ == "__main__":
    main()
