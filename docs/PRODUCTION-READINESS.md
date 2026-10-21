# PRODUCTION READINESS — COWORK

**Ngày:** 19/10/2026 · **Trạng thái:** ✅ **PRODUCTION ĐÃ GO-LIVE** (COWORK + Caddy/TLS + Brain bridge)
**Tên miền:** `https://cowork.vipgroup.com.vn` (DNS đúng, chưa có site block Caddy)

---

## 1. BẢNG SẴN SÀNG

| Hạng mục | Trạng thái | Ghi chú |
|---|---|---|
| Ứng dụng chạy local | ✅ | `127.0.0.1:8899`, `/api/health` ok |
| DB schema + seed | ✅ | `cowork.db`, version 1 |
| Đăng nhập ID + scrypt | ✅ | 14 test + test bổ sung |
| Phiên máy chủ + thu hồi | ✅ | cookie HttpOnly/SameSite, idle/absolute |
| CSRF form | ✅ | thiếu/sai token → 403 |
| Rate limit đăng nhập | ✅ | 5 sai/10 phút theo user+IP |
| 5 vai trò + quyền module | ✅ | chống leo thang, scope ban |
| Tenant isolation | ✅ | tenant B không thấy tenant A |
| Audit append-only | ✅ | trigger chặn UPDATE/DELETE |
| Màn hình quản trị | ✅ | dashboard, tài khoản, ban, vai trò, quyền, module, nhật ký, cài đặt |
| Brain ticket one-time + HMAC | ✅ | TTL 60s, chống replay |
| Brain staging + AI Local | ✅/đang nghiệm thu | DB bản sao, `qwen2.5:7b-instruct` |
| Caddy block cowork | ✅ đã áp dụng | cert Let’s Encrypt hạn 17/01/2027 |
| Tunnel 18835 | ✅ đang chạy | khóa riêng, permitlisten 18835 |
| Bridge Brain production | ✅ đã áp dụng | backup + smoke production PASS |
| Sao lưu COWORK định kỳ | ✅ LaunchAgent 03:20 | bản test 19/10/2026 |
| MFA cho COWORK | ⏸ tạm tắt sau reset owner | bật lại `/ho-so/mfa`; TOTP + mã dự phòng |
| IP thật sau proxy | ✅ đã vá | `COWORK_TIN_PROXY=1` + `web.ip_cua` đọc `X-Real-IP`; `run.sh --no-proxy-headers` |
| Trusted host / HSTS | ✅ sau Caddy | HSTS bật khi `X-Forwarded-Proto=https` |

---

## 2. KHOẢNG TRỐNG PHẢI XỬ LÝ TRƯỚC KHI MỞ PUBLIC

### 2.1. IP thật sau Caddy — ĐÃ VÁ
- `COWORK_TIN_PROXY=1` (production) + `web.ip_cua()` đọc `X-Real-IP` do Caddy ghi đè; `run.sh` chạy `--no-proxy-headers` để không tin `X-Forwarded-For` tự khai.
- Rate limit đăng nhập + `audit_log.ip` dùng IP thật; khi `TIN_PROXY=0` header bị bỏ qua.
- Test: `tests/test_controller_ops.py` (4 ca IP) — header giả bị bỏ, header hợp lệ được nhận.
- Còn lại: cột `sessions.ip` vẫn lấy peer socket (127.0.0.1 sau Caddy); không ảnh hưởng rate limit/audit. Nếu cần hiển thị IP thật trong phiên, truyền `ip_cua` vào `auth.tao_phien` ở bước sau.

### 2.2. Đăng xuất COWORK — ĐÃ THU HỒI BRAIN
- `auth_routes.dang_xuat` gọi `brain.thu_hoi_phien()` khi user có `brain.view`; phiên Brain native bị thu hồi ngay, audit ghi `brainRevoke`.
- Test: `tests/test_controller_ops.py::test_dang_xuat_thu_hoi_phien_brain`.

### 2.3. MFA cho COWORK — ĐÃ TRIỂN KHAI (tuỳ chọn)
- TOTP 6 số, challenge 5 phút, 10 mã dự phòng dùng một lần, CLI `mfa-reset` break-glass.
- Owner production **đã bật** 19/10/2026; secret + 10 mã dự phòng tại file 0600 trên Studio.
- Test: `tests/test_mfa_controller.py` (9 test); smoke production `evidence/PRODUCTION-mfa-smoke-20261019.json`.

### 2.4. Caddy/Header — ĐÃ KIỂM TRA SAU PUBLIC
- Caddy block đã áp dụng 19/10/2026; TLS + header đã kiểm tra: CSP, HSTS, X-Frame-Options DENY, nosniff, Referrer-Policy.
- Caddyfile root-owned + mount read-only; luôn sao lưu và dùng `docker run -v` để sửa.

### 2.5. Brain production
- Bridge `COWORK_BRIDGE_ALLOW_MFA_USERS=1` sau khi owner bật MFA COWORK; owner đã test mở Brain không hỏi MFA lần hai.
- Brain `/api/settings` authz gap và header chưa persist là nợ cũ của Brain, không do COWORK; ghi nhận để chủ dự án xử lý riêng.
- Không xoá dữ liệu test Brain nếu chưa có phê duyệt.

### 2.6. Vận hành — ĐÃ CÀI
- LaunchAgent COWORK + backup 03:20 + tunnel đã cài; health public 200.
- Giám sát `/api/health` và dung lượng DB.
- Log COWORK/uvicorn không chứa mật khẩu/token; audit không chứa bí mật.

---

## 3. KIỂM THỬ BẮT BUỘC TRƯỚC KHI PUBLIC

- [ ] `pytest` toàn bộ xanh.
- [ ] Đăng nhập đúng/sai, rate limit, CSRF, session revocation.
- [ ] Nhân viên chỉ thấy module được cấp; route admin 403.
- [ ] Quản trị cấp dưới không tạo/sửa Super Admin, không vượt phạm vi.
- [ ] Cross-tenant 404.
- [ ] Brain ticket one-time; chat `providerId=local`, `nhan=real`.
- [ ] Thu hồi quyền Brain → phiên Brain cũ 401.
- [ ] Header bảo mật + TLS + cookie Secure.
- [x] IP thật sau proxy đúng (đã có test).
- [ ] Backup/restore thử trên bản sao.

---

## 4. QUYẾT ĐỊNH CỦA CHỦ DỰ ÁN

1. Duyệt cổng 1 (COWORK lên Mac Studio)?
2. Duyệt cổng 2 (tunnel + Caddy + TLS)?
3. Duyệt cổng 3 (bridge Brain production)?
4. Có yêu cầu MFA cho COWORK trước khi public không?
5. Có giới hạn IP cho `/cai-dat`, `/tai-khoan` không?

### 2.7. Access log chứa ticket (từ AG-05)
- Brain staging/uvicorn và Caddy access log ghi `/cowork/vao?ticket=...`. Ticket one-time/TTL 60s nên rủi ro thấp, nhưng trước khi public nên:
  - tắt/che access log cho path `/cowork/vao`, hoặc
  - chuyển ticket sang POST/fragment.
- Chưa sửa production; ghi nhận để xử lý khi duyệt cổng 3.

**Chủ dự án đã duyệt cả 3 cổng ngày 19/10/2026.**

---

## 5. DIỄN TẬP ROLLBACK (19/10/2026)

- `./scripts/rollback-drill.sh` — **PASS**:
  - Backup SQLite: 17 user · 275 audit · integrity `ok`.
  - Restore ra DB tạm: counts khớp 6 bảng (users/audit/sessions/role_permissions/modules/tenants).
  - Chạy server trên DB khôi phục cổng 8902: đăng nhập `anh-thanh` PASS, 15 module.
  - Xoá DB tạm; giữ backup.
- Bằng chứng: `evidence/FINAL-rollback-drill.txt`.
- Caddy block đã **validate cú pháp** trên VPS bằng tệp tạm, live hash không đổi: `evidence/FINAL-caddy-validate.txt`.

**Vẫn chưa có thay đổi production nào.**


---

## 6. SAU GO-LIVE (19/10/2026)

- Public: `https://cowork.vipgroup.com.vn` · `https://ai.vipgroup.com.vn`
- COWORK LaunchAgent pid 18460; tunnel 18533; Brain pid 18620.
- Smoke production: owner login, tạo nhân viên, SSO Brain, chat local thật `qwen2.5:7b-instruct`, owner mở Brain 200 sau MFA, thu hồi 403/401, archive.
- Biên bản: `evidence/PRODUCTION-DEPLOY-20261019.md`; smoke: `evidence/PRODUCTION-smoke-20261019.json`.
- **Đã xong:** MFA owner, owner mở Brain qua COWORK, offsite backup, nghiệm thu production 8/8. Còn lại: chủ dự án ký nghiệm thu thủ công.


### 2.8. CSP form-action (bản vá 19/10/2026)
- CSP cũ `form-action 'self'` chặn redirect form `/brain/mo` sang `ai.vipgroup.com.vn` trên Chrome/Safari.
- Đã mở đúng origin Brain: `form-action 'self' https://ai.vipgroup.com.vn`; test Chrome thật PASS.


---

## 7. VPS STAGING (19/10/2026 20:18)

- GitHub public: `https://github.com/thanhbn123/vip-group-id`.
- VPS `CIITNRVPlinux`: `/srv/vip-staging/cowork`, container `cowork-staging` healthy, `127.0.0.1:8899`.
- DB copy production: 7 user, 110 audit, schema 2, integrity ok; login owner 200.
- **Chưa cutover**: Caddy vẫn 18835 → Studio; Brain internal vẫn Studio.
- Cutover/rollback: `deploy/vps/README.md`; bằng chứng `evidence/VPS-staging-20261019.txt`.


---

## 8. CUTOVER VPS (19/10/2026 20:26)

- COWORK production chạy VPS `127.0.0.1:8899`; Caddy upstream 8899.
- Brain `COWORK_INTERNAL_URL=https://cowork.vipgroup.com.vn`.
- Nghiệm thu 8/8; owner SSO/chat local; logout Brain 401.
- Backup VPS local 03:20 + offsite Synology 03:50; backup/offsite Studio cũ đã tắt.
- Chi tiết + rollback: `evidence/PRODUCTION-CUTOVER-20261019.md`.
