# KIỂM TRA CẤU HÌNH TÊN MIỀN — COWORK & AI BRAIN

**Ngày:** 19/10/2026 · **Trạng thái:** ĐÃ KIỂM TRA VÀ **ĐÃ ÁP DỤNG** 19/10/2026
**Quyết định chính thức:** COWORK = `https://cowork.vipgroup.com.vn` · Brain = `https://ai.vipgroup.com.vn`

---

## 1. KẾT QUẢ KIỂM TRA

| Hạng mục | Kết quả | Ghi chú |
|---|---|---|
| DNS `cowork.vipgroup.com.vn` | ✅ A → `160.22.170.20` | Đã lan truyền; Google DNS `8.8.8.8` trả cùng IP. Không có AAAA/CNAME. |
| DNS `ai.vipgroup.com.vn` | ✅ A → `160.22.170.20` | Giữ nguyên. |
| HTTP `cowork` | ⚠️ `308` → `https://cowork...` | Caddy trả redirect mặc định; **chưa có site block**. |
| HTTPS `cowork` | ❌ `TLS alert internal error`, không có cert | Caddy chưa cấu hình tên này nên không xin được chứng chỉ. |
| HTTPS `ai` | ✅ `200`, cert Let's Encrypt | `CN=ai.vipgroup.com.vn`, hạn 16/01/2027. |
| Caddy | ✅ `v2.11.4`, container `vip-staging-caddy`, network host | Cấu hình `/srv/vip-staging-proxy/Caddyfile` (root), mount `/etc/caddy/Caddyfile`. |
| Danh sách domain Caddy quản lý | `viporder.com.vn`, `hq`, `ai`, `vtp.staging`, `www.viporder`, `cpn`, `qua`, `hub.staging`, `member...` | **Không có `cowork`**. |
| Cổng 80/443 | ✅ đang mở công khai | Đủ điều kiện HTTP-01 challenge. |
| Tunnel Brain | ✅ `127.0.0.1:18834` → Mac Studio `127.0.0.1:8891` | `/api/health` trả `200`, DB `ok`. |
| Cổng dự kiến cho COWORK | `127.0.0.1:18835` — **đang trống** | Dùng tunnel riêng, không đụng 18834 của Brain. |
| Quyền quản trị Caddy | `deploy` không có sudo; nhưng thuộc group `docker` | Có thể đọc/ghi Caddyfile qua `docker exec` (root trong container). **Chưa thao tác.** |
| Firewall | Không đọc được `ufw` bằng `deploy` | 80/443 đã truy cập được từ Internet nên firewall đang cho qua. |

**Kết luận:** DNS đã đúng, không cần đổi DNS. Thiếu **một site block Caddy** cho `cowork.vipgroup.com.vn` và **một tunnel** trỏ về dịch vụ COWORK. Chưa có thay đổi nào được áp dụng.

---

## 2. HIỆN TRẠNG KHỐI AI TRONG CADDY (NGUYÊN VĂN RÚT GỌN)

```caddy
ai.vipgroup.com.vn {
    encode zstd gzip
    header {
        X-Robots-Tag "noindex, nofollow"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    @quan_tri path /api/settings* /api/budgets* /api/providers* /api/ops* /api/code-agent*
    handle @quan_tri {
        @khong_duoc not remote_ip 127.0.0.1/32 14.190.214.49/32 100.64.0.0/10
        respond @khong_duoc "Không có quyền truy cập quản trị." 403
        reverse_proxy 127.0.0.1:18834 {
            header_up X-Real-IP {remote_host}
            header_down Set-Cookie "^(.*)$" "$1; Secure"
        }
    }
    handle {
        reverse_proxy 127.0.0.1:18834 {
            header_up X-Real-IP {remote_host}
            header_down Set-Cookie "^(.*)$" "$1; Secure"
        }
    }
    log {
        output file /data/access-vip-ai-brain.log { roll_size 10mb roll_keep 5 }
    }
}
```

- Brain vẫn chạy độc lập trên Mac Studio, chỉ nghe `127.0.0.1:8891`; VPS không mở trực tiếp cổng Brain.
- COWORK sẽ dùng **tunnel riêng** `18835`, không dùng chung 18834.

---

## 3. KHỐI CADDY CHO COWORK — ĐÃ ÁP DỤNG 19/10/2026

```caddy
# VIP GROUP COWORK — cổng đăng nhập và làm việc tập trung.
# Đích: /srv/vip-staging-proxy/Caddyfile (root giữ). Áp dụng SAU khi kiểm thử bảo mật đạt.
cowork.vipgroup.com.vn {
    encode zstd gzip
    header {
        X-Robots-Tag "noindex, nofollow"
        X-Content-Type-Options "nosniff"
        Referrer-Policy "strict-origin-when-cross-origin"
        -Server
    }
    reverse_proxy 127.0.0.1:18835 {
        header_up X-Real-IP {remote_host}
        header_down Set-Cookie "^(.*)$" "$1; Secure"
    }
    log {
        output file /data/access-cowork.log {
            roll_size 10mb
            roll_keep 5
        }
    }
}
```

**Ghi chú kỹ thuật:**
- COWORK tự đặt CSP, HSTS, X-Frame-Options; Caddy chỉ thêm `noindex`, `nosniff`, `Referrer-Policy`, ẩn `Server` và ép `Secure` cho cookie.
- `X-Forwarded-Proto` do Caddy gửi; COWORK dùng nó để bật HSTS và cờ `Secure`.
- Không cần đổi DNS: bản ghi A đã đúng.
- Chứng chỉ sẽ được Caddy tự xin bằng HTTP-01 sau khi reload; cổng 80 đang mở.

---

## 4. QUY TRÌNH ÁP DỤNG (KHI ĐƯỢC DUYỆT)

```bash
# 1. Sao lưu
cp /srv/vip-staging-proxy/Caddyfile \
   /srv/vip-staging-proxy/Caddyfile.bak-before-cowork-$(date +%Y%m%d-%H%M)

# 2. Dán khối §3 vào cuối Caddyfile
# 3. Kiểm tra cú pháp
docker exec vip-staging-caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
# 4. Nạp lại không downtime
docker exec vip-staging-caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
# 5. Kiểm tra
curl -I https://cowork.vipgroup.com.vn/
echo | openssl s_client -connect cowork.vipgroup.com.vn:443 -servername cowork.vipgroup.com.vn 2>/dev/null | openssl x509 -noout -subject -dates
```

**Rollback:**
```bash
cp /srv/vip-staging-proxy/Caddyfile.bak-before-cowork-<thời-điểm> \
   /srv/vip-staging-proxy/Caddyfile
docker exec vip-staging-caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile
```
DNS không đổi nên rollback chỉ gồm Caddyfile + reload.

---

## 5. ĐIỀU KIỆN TRƯỚC KHI ÁP DỤNG

- [ ] COWORK chạy ổn định trên Mac Studio, cổng `127.0.0.1:8899`.
- [ ] Tunnel `com.vipai.cowork.tunnel-vps` → `127.0.0.1:18835` hoạt động.
- [ ] Bộ kiểm thử bảo mật COWORK đạt: auth, CSRF, rate limit, RBAC, tenant, session revocation.
- [ ] Kiểm thử SSO COWORK → Brain trên staging đạt; MFA Brain vẫn bật cho đăng nhập trực tiếp.
- [ ] Có bản sao lưu Caddyfile và kịch bản rollback đã chạy thử.
- [ ] Chủ dự án phê duyệt.

**Chưa có mục nào trong danh sách trên được tự động áp dụng.**

---

## 6. KẾT QUẢ VALIDATE KHỐI CADDY (19/10/2026)

Đã kiểm tra cú pháp bằng **tệp tạm trong container**, không reload, không sửa Caddyfile sống:

```bash
# Ghép Caddyfile hiện tại + khối COWORK vào /tmp, rồi:
docker exec -i vip-staging-caddy sh -c 'cat > /tmp/Caddyfile.cowork-test'
docker exec vip-staging-caddy caddy validate \
  --config /tmp/Caddyfile.cowork-test --adapter caddyfile
```

Kết quả:
- **`Valid configuration`**
- `live_before = c2674057…dad3c`
- `live_after  = c2674057…dad3c` — **không đổi**
- Cảnh báo không chặn: Caddyfile hiện tại chưa được `caddy fmt` (dòng 53); không ảnh hưởng nạp cấu hình.
- Bằng chứng: `evidence/FINAL-caddy-validate.txt`

**Chưa reload, chưa thêm block vào Caddyfile sống.**


---

## 7. TRẠNG THÁI ÁP DỤNG THỰC TẾ (19/10/2026)

- Đã thêm block vào Caddyfile sống, `caddy validate` **Valid configuration**, `caddy reload` exit 0.
- Hash trước: `c2674057…dad3c` · sau: `be7a8ef8…5434`.
- Backup: `/home/deploy/Caddyfile.bak-before-cowork-20261019-180126.txt` và `/data/Caddyfile.bak-before-cowork-20261019-180126`.
- TLS Let's Encrypt cấp thành công: `CN=cowork.vipgroup.com.vn`, hạn 17/01/2027.
- Public: `https://cowork.vipgroup.com.vn` → trang đăng nhập 200; `/api/health` 200.
- DNS **không đổi**.
- Biên bản đầy đủ: `evidence/PRODUCTION-DEPLOY-20261019.md`.

### 7.1. Lưu ý vận hành Caddyfile (đã gặp thực tế)

`/etc/caddy/Caddyfile` trong container là **bind mount read-only**, nên `docker exec ... cat > /etc/caddy/Caddyfile` báo
`Read-only file system`. Cách đã dùng để sửa an toàn:

```bash
# Sao lưu trước
docker exec vip-staging-caddy cat /etc/caddy/Caddyfile > ~/Caddyfile.bak-$(date +%Y%m%d-%H%M%S).txt
docker exec vip-staging-caddy cp /etc/caddy/Caddyfile /data/Caddyfile.bak-$(date +%Y%m%d-%H%M%S)

# Ghi qua volume host (container tạm, không reload)
docker run --rm -i -v /srv/vip-staging-proxy:/work caddy:2-alpine sh -c 'cat >> /work/Caddyfile'

# Validate + reload
docker exec vip-staging-caddy caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker exec vip-staging-caddy caddy reload   --config /etc/caddy/Caddyfile --adapter caddyfile
```

Không dùng `docker cp` vào `/etc/caddy` vì mount read-only.


### 7.2. Caddy fmt (19/10/2026 18:25)

- Đã chạy `caddy fmt --overwrite` trên Caddyfile sống; validate/reload OK, hết cảnh báo định dạng.
- Backup trước fmt: `~/Caddyfile.bak-before-fmt-20261019-182534.txt` và `/data/Caddyfile.bak-before-fmt-20261019-182534`.
- Hash sau fmt: `eea7ed56d9d373f14ec902cb17a8db71b5902fba06efa83cb7eb6aa1da95d86f`.
- Public health/TLS không đổi.


---

## 8. CUTOVER UPSTREAM SANG VPS (19/10/2026 20:26)

- `reverse_proxy 127.0.0.1:18835` → `127.0.0.1:8899`.
- Caddyfile host sửa bằng `docker run ... sed`; do file bind-mount đổi inode, phải **restart container** để nhận nội dung mới (reload đơn thuần vẫn đọc file cũ).
- Validate OK; public health 200; TLS giữ nguyên.
- Hash trước `eea7ed56…d86f`; sau `c0ae5314…74ad`.
- Backup trước cutover: `~/Caddyfile.bak-before-cutover-20261019-202511.txt` và `/data/Caddyfile.bak-before-cutover-20261019-202511`.

## Realm khách (cổng khách hàng) — danh sách host

Khi bật `COWORK_KHACH_ENABLED=1`, VIP ID chọn realm theo header `Host`:

| Biến | Ý nghĩa |
|---|---|
| `COWORK_KHACH_HOSTS` | Host realm khách, ví dụ `khachhang.vipgroup.com.vn` |
| `COWORK_STAFF_HOSTS` | **Danh sách trắng** host nhân viên, ví dụ `cowork.vipgroup.com.vn,127.0.0.1:8899` |

- Host không thuộc danh sách nào (kể cả thiếu Host) ⇒ **421**, không bao giờ rơi về realm nhân viên.
- Tên host khách và nhân viên phải **khác nhau** (khác cổng là chưa đủ — cookie không tách theo cổng).
- `COWORK_STAFF_HOSTS` **chưa đặt**: dev/staging ghi cảnh báo lớn khi khởi động và suy ra từ
  `COWORK_PUBLIC_URL`/`COWORK_INTERNAL_URL`; **production từ chối khởi động**.
- CRM gọi `/api/internal/khach/*` phải gửi `Host` là host khách.
- Staging: xem `deploy/vps/README.md` — đặt `COWORK_STAFF_HOSTS` **tường minh**.
- Trang thử thách Turnstile cần Caddy KHÔNG ghi đè CSP của VIP ID (CSP mở
  `challenges.cloudflare.com` chỉ trên trang đó).

### Giới hạn đã biết (realm khách)
- **Vượt ngưỡng trong một loạt đồng thời (P2-c, chấp nhận):** các bộ đếm tần suất/khoá được kiểm
  rồi mới ghi (không khoá nguyên tử). Một loạt request **đồng thời** có thể vượt ngưỡng một ít
  (ví dụ khoá cặp 5 lần có thể ghi nhận 6–8 lần sai) trước khi bị chặn. Mức vượt bị chặn trên bởi
  hàng đợi băm (2 luồng, trần 16) và trần siteverify Turnstile (4), nên không mở đường dò mật khẩu
  không giới hạn.
- Production bật realm khách bắt buộc `COWORK_TIN_PROXY=1` và `COWORK_COOKIE_SECURE=1`
  (thiếu ⇒ từ chối khởi động).

### Đăng ký & khôi phục (quyết định owner 07/11/2026)
- **Không xác minh email, không gọi xác minh SĐT.** Đăng ký tạo ngay tài khoản `cho_duyet` và gửi
  signup HMAC sang CRM (lỗi mạng ⇒ hàng đợi `crm_sync_pending`, chạy `cowork.cli khach-dong-bo`).
  Nhân viên duyệt là cổng duy nhất; đăng nhập chỉ khi `hoat_dong`.
- Email là thông tin liên hệ **tuỳ chọn** (kiểm định dạng nếu nhập, không unique). SĐT vẫn unique.
- Đăng ký trùng SĐT: phản hồi y hệt, không tạo tài khoản, đánh dấu `phone_conflict` gửi CRM.
- **Quên mật khẩu do nhân viên hỗ trợ:** trang `/tai-khoan/quen-mat-khau` chỉ hướng dẫn gọi
  hotline/Zalo (`COWORK_KHACH_HOTLINE`, mặc định `0961 102 655`). CRM cấp link qua
  `POST /api/internal/khach/tao-link-dat-lai` `{subject, requested_by}` ⇒ `{url, expires_at}`.
- `COWORK_KHACH_EMAIL_ENABLED=0` (mặc định): không ghi outbox email, không có tự khôi phục qua
  email; production **không** đòi kênh email thật. Bật `=1` thì phải có kênh gửi thật (A8).
- Lỗi BUG-VIPID-01 (đã sửa): không dùng `<meta name="referrer" content="no-referrer">` trong trang
  khách — Chrome gửi `Origin: null` khi POST ⇒ mọi form 403. Header `Referrer-Policy: same-origin`
  đã đủ.
