# VIP GROUP COWORK

Cổng đăng nhập và làm việc tập trung của VIP GROUP: ID, vai trò, ban/bộ phận, phân quyền module,
nhật ký quản trị và cầu nối tới **VIP AI Brain** (AI Local trên Mac Studio).

- **Tên miền chính thức:** `https://cowork.vipgroup.com.vn`
- **VIP AI Brain:** `https://ai.vipgroup.com.vn`
- **Nguyên tắc:** local-first · không đụng Brain production · không deploy/push tự động.

---

## 1. TRẠNG THÁI HIỆN TẠI

| Thành phần | Trạng thái |
|---|---|
| COWORK app (FastAPI + SQLite) | ✅ chạy local `http://127.0.0.1:8899` |
| Đăng nhập ID, phiên, CSRF, rate limit | ✅ |
| MFA TOTP + 10 mã dự phòng + CLI reset | ⏸ tạm tắt sau reset owner 19/10; bật lại tại `/ho-so/mfa` |
| 5 vai trò + phân quyền module + tenant + audit | ✅ |
| 15 màn hình quản trị + dashboard + Brain | ✅ |
| Brain staging (bản sao DB + bridge) | ✅ `http://127.0.0.1:8892` (khi bật) |
| Brain production | ✅ `Mac Studio:8891`; bridge COWORK bật; owner mở Brain qua COWORK không hỏi MFA lần hai |
| Production COWORK | ✅ `https://cowork.vipgroup.com.vn` — chạy trên **VPS** từ 19/10/2026 |
| GitHub | ✅ `https://github.com/thanhbn123/vip-group-id` (repo chính; bản cũ `vip-group-cowork` giữ mirror) |
| VPS production | ✅ container `cowork-staging` tại `/srv/vip-staging/cowork`, Caddy → 8899 |
| Caddy `cowork.vipgroup.com.vn` | ✅ HTTPS + TLS, upstream VPS 8899 |
| Nghiệm thu 8 bước | ✅ 8/8 PASS local/staging + smoke production 19/10/2026 |

---

## 2. CHẠY LOCAL

```bash
cd "/Users/viporder/Library/CloudStorage/SynologyDrive-Macbook/VIP GROUP ID/cowork"

# Lần đầu: tạo venv, DB, Super Admin; mật khẩu ghi vào secrets/ (0600)
./scripts/bootstrap.sh

# Chạy COWORK
./run.sh
# → http://127.0.0.1:8899
```

Đăng nhập `anh-thanh`; mật khẩu đọc tại `secrets/owner-anh-thanh.txt` (không commit, không in ra log).

### 2.1. Brain staging + AI Local
```bash
# 1. Tunnel Ollama từ Mac Studio
ssh -f -N -L 127.0.0.1:11434:127.0.0.1:11434 vip-ai-studio

# 2. Cấp phát bản sao Brain + bridge (không đụng production)
./scripts/provision_brain_staging.sh

# 3. Chạy Brain staging
./scripts/start-brain-staging.sh
# → http://127.0.0.1:8892 · bridge bật
```

- Staging dùng **bản sao DB** `brain-staging/data/vip-brain-staging.db`.
- Brain production trên Mac Studio **không bị chạm**.
- `COWORK_BRAIN_BASE_URL=http://127.0.0.1:8892` trong `.env` local.

Dừng staging:
```bash
./scripts/stop-brain-staging.sh
```

---

## 3. TÀI KHOẢN TEST (LOCAL, KHÔNG PHẢI PRODUCTION)

| ID | Vai trò | Mật khẩu | Ghi chú |
|---|---|---|---|
| `anh-thanh` | Super Admin | `secrets/owner-anh-thanh.txt` | cao nhất, không ai sửa được |
| `quan-tri-01` | Quản trị cấp dưới | `Qt01!Passw0rd` | toàn tenant |
| `quan-tri-scope` | Quản trị cấp dưới | `Scope01!Pass` | chỉ Ban Kinh doanh |
| `nhan-vien-01` | Nhân viên | `Nv01!Passw0rd` | Ban Kinh doanh |
| `b-admin` / `b-user` | Tenant B | `Badmin!Passw0rd` / `Buser!Passw0rd` | kiểm thử cách ly tenant |

Đổi mật khẩu test trước khi dùng thật. Không dùng các mật khẩu này ở production.

---

## 4. VAI TRÒ & MODULE

**Vai trò:** `super_admin` (100) · `admin` (80) · `department_manager` (60) · `employee` (40) · `partner` (20).

**Nguyên tắc quyền:**
- Super Admin có toàn quyền, không ai sửa/khoá/lưu trữ được.
- Quản trị cấp dưới chỉ thao tác trong tenant/ban được uỷ quyền; không tạo vai trò ngang/cao hơn; không cấp quyền mình không có.
- Nhân viên chỉ thấy module được cấp; kiểm tra lại mỗi request.
- Partner chỉ thấy cổng đối tác và module được cấp.
- Mọi thao tác quản trị ghi `audit_log` (trigger chặn UPDATE/DELETE).

**Module mặc định:** dashboard, brain, tasks, knowledge, tools, usage, approvals, partner,
accounts, departments, roles, permissions, modules, audit, settings.

---

## 5. CẤU TRÚC

```
cowork/
├── cowork/
│   ├── main.py            # FastAPI app, middleware, exception handlers
│   ├── config.py          # env, bí mật 0600
│   ├── db.py              # SQLite + seed
│   ├── schema.py          # schema + module/permission registry
│   ├── auth.py            # đăng nhập, phiên, CSRF, rate limit
│   ├── security.py        # scrypt, token, HMAC
│   ├── rbac.py            # quyền hiệu lực, phạm vi, chống leo thang
│   ├── services.py        # nghiệp vụ tài khoản/ban/quyền/cài đặt
│   ├── brain.py           # ticket + client Brain
│   ├── web.py             # dependency, template, flash
│   ├── routers/           # auth, dashboard, accounts, departments, roles,
│   │                      # modules, audit, settings, brain, internal
│   ├── templates/         # giao diện Jinja2
│   └── static/            # CSS/JS/favicon, không CDN
├── brain-bridge/          # bản vá THÊM cho Brain (feature-flag)
├── scripts/               # bootstrap, backup, provisioning, acceptance
├── tests/                 # pytest bảo mật
├── docs/                  # khảo sát, tên miền, triển khai, rollback, hợp đồng agent
├── data/                  # cowork.db + secret (gitignore)
└── secrets/               # mật khẩu một lần (gitignore)
```

---

## 6. KIỂM THỬ

```bash
.venv/bin/python -m pytest -q
```

- Test dùng DB tạm, không đụng `data/cowork.db`.
- Bộ hiện có: **97 test PASS** (lõi + 5 làn agent + controller): đăng nhập, rate limit, CSRF, RBAC, chống leo thang, tenant, thu hồi quyền/phiên, audit append-only, Brain ticket/HMAC, UI 3 vai trò, E2E 8 bước.
- Bằng chứng nghiệm thu cuối: `evidence/FINAL-acceptance-20261019.json`, `evidence/FINAL-acceptance-report-20261019.md`, `evidence/controller-final-e2e.json`.
- Không dùng MOCK để kết luận PASS: chat Brain phải `providerId=local`, `nhan=real`.

---

## 7. TÀI LIỆU

| Tệp | Nội dung |
|---|---|
| `docs/BAO-CAO-KHAO-SAT.md` | khảo sát COWORK/Brain hiện có, đối chiếu kiến trúc |
| `docs/CAU-HINH-TEN-MIEN.md` | DNS/TLS/Caddy, khối Caddy, trạng thái áp dụng |
| `docs/TRIEN-KHAI-PRODUCTION.md` | kế hoạch đưa COWORK + Brain bridge lên production |
| `docs/ROLLBACK.md` | quy trình quay lui từng lớp |
| `docs/AGENT-CONTRACTS.md` | phân vùng 5 agent, API contract, quy tắc phối hợp |
| `docs/NGHIEM-THU.md` | 8 bước chủ dự án nghiệm thu (cập nhật sau tích hợp) |

---

## 8. AN TOÀN

- Không commit `data/`, `secrets/`, `.env`, `brain-staging/`.
- Không sửa/khởi động lại Brain production nếu chưa có phê duyệt.
- Không đổi DNS/Caddy trước khi kiểm thử bảo mật đạt.
- Không push GitHub, không deploy VPS, không kết nối dự án khác.
