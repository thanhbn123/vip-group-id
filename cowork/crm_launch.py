"""COWORK → CRM nội bộ: ký launch token `cowork-launch/1` (KIEN_TRUC_P1 §15.6).

Định dạng khớp byte với bộ xác minh có sẵn của CRM
(`vip-group-khoqctq/server/modules/adapters/tokens.js` · `verifyCoworkToken`):
compact HS256 JWT — base64url(header).base64url(payload).base64url(HMAC-SHA256('h.p')).

Payload: {ver:1, aud:'vip-crm', sub:'cowork:<users.id>', tenant_code:<mã CRM>, iat, exp, nonce}.
CRM kiểm chữ ký (so sánh hằng thời gian), aud, ver, exp ≤ 60 s, iat lệch, nonce dùng một lần,
ánh xạ `sub` → `users.vip_subject` (kind='staff'), từ chối tài khoản khách (C0).

Bí mật: env `COWORK_CRM_LAUNCH_SECRET` → tệp 0600 `COWORK_CRM_LAUNCH_SECRET_FILE`.
KHÔNG tự sinh (phải trùng giá trị `COWORK_SHARED_SECRET` phía CRM). Thiếu/yếu/trùng bí mật
khác ⇒ module báo "chưa cấu hình" và không phát token.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
import uuid

from . import config

CONTRACT = "cowork-launch/1"
AUDIENCE = "vip-crm"
SUB_PREFIX = "cowork:"
_HEADER = {"alg": "HS256", "typ": "JWT"}
#: CRM chặn exp - now > 60 (COWORK_MAX_TTL_SEC); giữ đúng trần đó.
TTL_TOI_DA = 60
#: Vai trò thấp hơn mức này (partner = 20) không bao giờ được mở CRM nội bộ.
CAP_TOI_THIEU = 40


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _json(obj: dict) -> bytes:
    # Giống JSON.stringify: không khoảng trắng, giữ thứ tự khoá, UTF-8.
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def bi_mat() -> str:
    v = os.environ.get("COWORK_CRM_LAUNCH_SECRET", "").strip()
    if v:
        return v
    p = config.CRM_LAUNCH_SECRET_FILE
    try:
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
    except OSError:
        pass
    return ""


def loi_cau_hinh() -> list[str]:
    """Danh sách lỗi cấu hình (rỗng = sẵn sàng). Không bao giờ trả giá trị bí mật."""
    loi: list[str] = []
    if not config.CRM_ENABLED:
        loi.append("Module CRM đang tắt (COWORK_CRM_ENABLED=0).")
    s = bi_mat()
    if not s:
        loi.append("Chưa cấu hình COWORK_CRM_LAUNCH_SECRET.")
    else:
        if len(s) < 32:
            loi.append("COWORK_CRM_LAUNCH_SECRET phải dài ít nhất 32 ký tự.")
        if "change-me" in s:
            loi.append("COWORK_CRM_LAUNCH_SECRET đang là giá trị mẫu.")
        khac = [config.SECRET_KEY, config.BRAIN_SHARED_SECRET, config.HATANG_SHARED_SECRET,
                os.environ.get("VIPID_PORTAL_SECRET", ""), os.environ.get("VIPID_SHARED_SECRET", "")]
        if any(k and hmac.compare_digest(k, s) for k in khac):
            loi.append("COWORK_CRM_LAUNCH_SECRET phải KHÁC mọi bí mật khác (phiên, Brain, hạ tầng, portal).")
    if not config.CRM_PUBLIC_URL.startswith("https://") and config.ENV == "production":
        loi.append("COWORK_CRM_PUBLIC_URL phải là https:// ở production.")
    return loi


def tenant_crm(cowork_tenant_id: str) -> str | None:
    """Mã tenant phía CRM; None = tenant chưa được ánh xạ ⇒ không cho mở CRM."""
    return config.CRM_TENANT_MAP.get(cowork_tenant_id)


def subject(user: dict) -> str:
    return SUB_PREFIX + str(user["id"])


def ky(secret: str, payload: dict) -> str:
    h = _b64u(_json(_HEADER))
    p = _b64u(_json(payload))
    sig = hmac.new(secret.encode("utf-8"), f"{h}.{p}".encode("ascii"), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def tao_token(user: dict, *, now: float | None = None) -> tuple[str, dict]:
    """Ký token cho `user` (đã kiểm quyền ở router). Trả (token, payload) — payload để audit."""
    loi = loi_cau_hinh()
    if loi:
        raise RuntimeError("; ".join(loi))
    tenant = tenant_crm(user["tenant_id"])
    if not tenant:
        raise RuntimeError("Tenant chưa được ánh xạ sang CRM.")
    iat = int(now if now is not None else time.time())
    payload = {
        "ver": 1, "aud": AUDIENCE, "sub": subject(user), "tenant_code": tenant,
        "iat": iat, "exp": iat + min(config.CRM_LAUNCH_TTL, TTL_TOI_DA), "nonce": str(uuid.uuid4()),
    }
    return ky(bi_mat(), payload), payload


def url_launch(token: str) -> str:
    from urllib.parse import urlencode
    return config.CRM_PUBLIC_URL.rstrip("/") + config.CRM_LAUNCH_PATH + "?" + urlencode({"token": token})
