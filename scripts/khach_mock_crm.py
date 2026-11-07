"""CRM GIẢ cho thử tay realm khách (chỉ dev, stdlib, nghe 127.0.0.1).

- POST /api/internal/portal/signups, /api/internal/portal/thu-hoi: kiểm HMAC "vipid->crm";
  thu-hoi bắt buộc `revoked_at_ms` (+ `revoked_at` giây) và chặn launch có iat_ms < revoked_at_ms.
- GET  /portal/auth/launch?token=: kiểm launch token HS256 (ver/aud/exp/nonce một lần) và
  hiển thị claims.
Bí mật đọc từ env VIPID_PORTAL_SECRET hoặc tệp VIPID_PORTAL_SECRET_FILE (không in ra).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def _secret() -> str:
    v = os.environ.get("VIPID_PORTAL_SECRET", "").strip()
    if v:
        return v
    return Path(os.environ["VIPID_PORTAL_SECRET_FILE"]).read_text().strip()


NONCES: set[str] = set()
#: subject -> revoked_at_ms (mili-giây unix) nhận qua /thu-hoi; launch có iat_ms < revoked_at_ms
#: bị từ chối (so theo mili-giây — đăng xuất cùng giây với launch vẫn thu hồi đúng).
THU_HOI: dict[str, int] = {}


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def kiem_launch(token: str) -> dict:
    h, p, s = token.split(".")
    if json.loads(_b64d(h)).get("alg") != "HS256":
        raise ValueError("alg")
    mong = hmac.new(_secret().encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(mong, _b64d(s)):
        raise ValueError("chữ ký sai")
    c = json.loads(_b64d(p))
    now = time.time()
    if c.get("ver") != 1 or c.get("aud") != "vip-crm-portal":
        raise ValueError("ver/aud")
    if not (c["iat"] - 30 <= now < c["exp"]) or c["exp"] - c["iat"] > 60:
        raise ValueError("hết hạn")
    iat_ms = c.get("iat_ms") if isinstance(c.get("iat_ms"), int) else c["iat"] * 1000
    if iat_ms < THU_HOI.get(c["sub"], 0):
        raise ValueError("token phát trước thời điểm thu hồi")
    if c["nonce"] in NONCES:
        raise ValueError("nonce đã dùng")
    NONCES.add(c["nonce"])
    return c


class H(BaseHTTPRequestHandler):
    def _tra(self, code: int, body: str, ctype: str = "application/json") -> None:
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):  # noqa: N802
        raw = self.rfile.read(int(self.headers.get("content-length") or 0))
        ts, sig = self.headers.get("x-portal-ts", ""), self.headers.get("x-portal-sig", "")
        # Chuỗi ký: "<direction>.<METHOD>.<path>.<ts>." + body
        mong = hmac.new(_secret().encode(), f"vipid->crm.POST.{urlsplit(self.path).path}.{ts}.".encode()
                        + raw, hashlib.sha256).hexdigest()
        if not ts.isdigit() or abs(time.time() - int(ts)) > 300 or not hmac.compare_digest(mong, sig):
            return self._tra(401, '{"ok":false}')
        print(f"[mock-crm] {self.path} {raw.decode()}", file=sys.stderr)
        if urlsplit(self.path).path == "/api/internal/portal/thu-hoi":
            b = json.loads(raw)
            if not isinstance(b.get("revoked_at_ms"), int) or not isinstance(b.get("revoked_at"), int):
                return self._tra(400, '{"ok":false,"loi":"thiếu revoked_at_ms/revoked_at"}')
            THU_HOI[b["subject"]] = max(THU_HOI.get(b["subject"], 0), b["revoked_at_ms"])
        return self._tra(200, '{"ok":true}')

    def do_GET(self):  # noqa: N802
        u = urlsplit(self.path)
        if u.path != "/portal/auth/launch":
            return self._tra(404, '{"ok":false}')
        try:
            c = kiem_launch(parse_qs(u.query).get("token", [""])[0])
        except Exception as e:  # noqa: BLE001
            return self._tra(401, f"<h1>Launch bị từ chối</h1><p>{html.escape(str(e))}</p>",
                             "text/html")
        return self._tra(200, "<h1>CRM giả: launch hợp lệ</h1><pre>"
                         + html.escape(json.dumps(c, ensure_ascii=False, indent=2)) + "</pre>",
                         "text/html")

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    port = int(os.environ.get("MOCK_CRM_PORT", "8897"))
    print(f"[mock-crm] nghe http://127.0.0.1:{port}", file=sys.stderr)
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
