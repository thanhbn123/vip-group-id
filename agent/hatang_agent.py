#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Agent Hạ tầng: đo chính máy này rồi ĐẨY ảnh chụp về COWORK (HMAC).

Chạy 10 phút/lượt (anh Thành chốt 31/10/2026, V-14901, đường dữ liệu A).
Chỉ ĐỌC trên máy: systemd, /proc, df, docker, VIP Vault. Không sửa gì.
Chỉ stdlib — không cài thêm gói nào.

Cấu hình qua tệp env (systemd `EnvironmentFile=` hoặc `. /duong/dan` trước khi gọi):
    HATANG_MAY_CHU=vps-160-22-171-228      # phải CÓ trong sổ hatang_may_chu của COWORK
    HATANG_COWORK_URL=https://cowork.vipgroup.com.vn
    HATANG_SECRET_FILE=/etc/cowork-agent/secret   # 1 dòng, chmod 600, người đặt một lần (§20.4)

Mã thoát: 0 = COWORK đã nhận; 2 = cấu hình thiếu; 3 = COWORK từ chối/không nối được.
Hỏng thì PHẢI thoát khác 0 — systemd/cron còn thấy; nuốt lỗi là hỏng im lặng.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

GIOI_HAN_DICH_VU = 80      # chống phình body quá giới hạn 200KB của COWORK
GIOI_HAN_DOCKER = 60


def chay(lenh: list[str], timeout: int = 15) -> str:
    """Chạy một lệnh đọc; hỏng thì trả chuỗi rỗng (thiếu một phép đo ≠ chết cả lượt),
    nhưng KHÔNG nuốt dấu vết: ghi stderr để systemd/cron còn thấy."""
    try:
        return subprocess.run(lenh, capture_output=True, text=True,
                              timeout=timeout).stdout.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"đo hỏng ({' '.join(lenh[:2])}): {exc}", file=sys.stderr)
        return ""


def doc(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return ""


def cau_hinh() -> dict:
    os_name = ""
    for line in doc("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip('"')
    cpu = ""
    m = re.search(r"Model name:\s*(.+)", chay(["lscpu"]))
    if m:
        cpu = m.group(1).strip()
    ram_mb = swap_mb = 0
    for line in chay(["free", "-m"]).splitlines():
        if line.startswith("Mem:"):
            ram_mb = int(line.split()[1])
        if line.startswith("Swap:"):
            swap_mb = int(line.split()[1])
    df = chay(["df", "-h", "/"]).splitlines()
    dia_tong = df[1].split()[1] if len(df) > 1 else ""
    ch = {
        "hostname": chay(["hostname"]),
        "os": os_name,
        "kernel": chay(["uname", "-r"]),
        "cpu": cpu,
        "nhanCpu": int(chay(["nproc"]) or 0),
        "ramMb": ram_mb,
        "swapMb": swap_mb,
        "diaTong": dia_tong,
        "tailscale": (chay(["tailscale", "ip", "-4"]).splitlines() or [""])[0],
    }
    pg = chay(["psql", "--version"])
    if pg:
        ch["postgres"] = pg
    caddy = doc("/etc/caddy/Caddyfile")          # chỉ root đọc được — thiếu thì bỏ
    if caddy:
        ch["caddySite"] = len(re.findall(r"^\S.*\{", caddy, re.M))
    units = chay(["bash", "-c",
                  "ls -1 /etc/systemd/system/*.service /etc/systemd/system/*.timer "
                  "2>/dev/null | wc -l"])
    ch["unitTuViet"] = int(units or 0)
    return ch


def trang_thai() -> dict:
    up = doc("/proc/uptime").split()
    load = doc("/proc/loadavg").split()
    ram_dung = 0
    for line in chay(["free", "-m"]).splitlines():
        if line.startswith("Mem:"):
            ram_dung = int(line.split()[2])
    df = chay(["df", "-h", "/"]).splitlines()
    dia_dung, dia_pt = ("", "")
    if len(df) > 1:
        p = df[1].split()
        dia_dung, dia_pt = p[2], p[4].rstrip("%")
    return {
        "uptimeGiay": int(float(up[0])) if up else 0,
        "load1": load[0] if load else "",
        "ramDungMb": ram_dung,
        "diaDung": dia_dung,
        "diaDungPhanTram": dia_pt,
    }


# Unit của hệ điều hành — không phải việc của màn này
_BO_QUA = re.compile(r"^(systemd-|dbus-|iscsi$|syslog$|sshd$|chronyd$|getty|"
                     r"regenerate-|auto-extend-|user@)")


def dich_vu() -> list[dict]:
    ra = []
    out = chay(["bash", "-c", "ls -1 /etc/systemd/system/*.service 2>/dev/null"])
    for f in out.splitlines():
        ten = os.path.basename(f)[:-len(".service")]
        if _BO_QUA.match(ten):
            continue
        act = chay(["systemctl", "is-active", ten]) or "unknown"
        d = {"ten": ten, "act": act}
        if act == "active":
            nr = chay(["systemctl", "show", "-p", "NRestarts", "--value", ten])
            mem = chay(["systemctl", "show", "-p", "MemoryCurrent", "--value", ten])
            d["nr"] = int(nr or 0)
            if mem.isdigit():
                d["memBytes"] = int(mem)
        ra.append(d)
        if len(ra) >= GIOI_HAN_DICH_VU:
            break
    return ra


def docker_ps() -> list[dict]:
    out = chay(["docker", "ps", "--format", "{{.Names}}|{{.Status}}"], timeout=20)
    ra = [{"ten": p[0], "trangThai": p[1]}
          for p in (line.split("|", 1) for line in out.splitlines()) if len(p) == 2]
    ra.sort(key=lambda c: c["ten"])
    return ra[:GIOI_HAN_DOCKER]


def vip_vault() -> dict | None:
    raw = doc("/opt/vip-vault/monitoring/trang-thai.json")
    if not raw:
        return None
    try:
        v = json.loads(raw)
    except ValueError:
        return {"status": "trang-thai.json hỏng JSON"}
    return {"status": v.get("status"), "last_backup_iso": v.get("last_backup_iso"),
            "so_buoc_hong": v.get("so_buoc_hong")}


def gui(url: str, secret: str, body: bytes) -> int:
    ts = str(int(time.time()))
    sig = hmac.new(secret.encode("utf-8"),
                   f"hatang->cowork.{ts}.".encode("utf-8") + body,
                   hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        url.rstrip("/") + "/api/internal/hatang/bao-cao", data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "X-Cowork-Ts": ts, "X-Cowork-Sig": sig})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def main() -> int:
    may_chu = os.environ.get("HATANG_MAY_CHU", "").strip()
    url = os.environ.get("HATANG_COWORK_URL", "").strip()
    secret_file = os.environ.get("HATANG_SECRET_FILE", "").strip()
    if not (may_chu and url and secret_file):
        print("Thiếu HATANG_MAY_CHU / HATANG_COWORK_URL / HATANG_SECRET_FILE",
              file=sys.stderr)
        return 2
    secret = doc(secret_file).strip()
    if not secret:
        print(f"Không đọc được bí mật từ {secret_file}", file=sys.stderr)
        return 2

    bao_cao = {
        "mayChu": may_chu,
        "doLuc": datetime.now(timezone.utc).astimezone().replace(microsecond=0).isoformat(),
        "cauHinh": cau_hinh(),
        "trangThai": trang_thai(),
        "dichVu": dich_vu(),
        "docker": docker_ps(),
    }
    vault = vip_vault()
    if vault:
        bao_cao["vault"] = vault
    body = json.dumps(bao_cao, ensure_ascii=False).encode("utf-8")

    try:
        status = gui(url, secret, body)
    except urllib.error.HTTPError as exc:
        print(f"COWORK từ chối: HTTP {exc.code} — {exc.read()[:300]!r}", file=sys.stderr)
        return 3
    except (urllib.error.URLError, OSError) as exc:
        print(f"Không nối được COWORK: {exc}", file=sys.stderr)
        return 3
    print(f"đã gửi {len(body)} byte, COWORK trả {status}")
    return 0 if status == 200 else 3


if __name__ == "__main__":
    sys.exit(main())
