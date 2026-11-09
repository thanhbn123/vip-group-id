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
- **Vượt ngưỡng trong một loạt đồng thời (P2-c):** bộ giới hạn chung (`vuot_tan_suat`: đăng ký,
  siteverify theo IP, quên mật khẩu, trần đăng ký…) đếm + ghi trong một giao dịch `BEGIN IMMEDIATE`
  nên **không** vượt ngưỡng. Riêng bộ đếm đăng nhập sai (khoá cặp/IP) vẫn kiểm rồi mới ghi: một loạt
  đồng thời có thể vượt ngưỡng một ít, bị chặn trên bởi hàng đợi băm (2 luồng, trần 16).
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

### Gửi CRM, chống đăng ký ồ ạt, nâng cấp DB
- **Request không bao giờ gọi CRM.** Mọi signup/thu hồi chỉ xếp hàng `crm_sync_pending`; vòng nền
  trong tiến trình gửi mỗi `COWORK_KHACH_SYNC_GIAY` giây (mặc định 5). `cowork.cli khach-dong-bo`
  (cron) vẫn dùng được song song. Thời gian phản hồi đăng ký không phụ thuộc SĐT đã có hay chưa.
- **Turnstile bắt buộc cho đăng ký** khi đã cấu hình (action `khach_dang_ky`); production đã bắt
  buộc có khoá thật.
- **Trần đăng ký toàn hệ thống** `COWORK_KHACH_SIGNUP_GLOBAL_PER_HOUR` (mặc định 200/giờ): vượt ⇒
  trang "Hệ thống đang nhận quá nhiều đăng ký" (503) + audit `khach.canh_bao.dang_ky_tang_dot_bien`
  (tối đa 1 dòng/giờ) để cảnh báo.
- Cập nhật cờ `phone_conflict` sang CRM gộp tối đa 1 lần/subject/giờ (số đếm vẫn tăng tại chỗ).
- **Nâng cấp DB realm khách lỗi** (ví dụ còn `portal_code` kiểu cũ VG + 6 số): giao dịch dựng lại
  bảng được hoàn tác, ghi log ERROR + audit `khach.migration.loi`, **realm khách tự tắt**, realm
  nhân viên vẫn khởi động bình thường. Sửa dữ liệu rồi khởi động lại để thử nâng cấp lại.
- **Giới hạn rollback:** sau schema v6 (email tuỳ chọn, mã VG1001…), bản code cũ (v4/v5) **không**
  dùng được DB này nữa (ràng buộc khác). Rollback code ⇒ phải khôi phục bản backup DB chụp TRƯỚC
  khi nâng cấp (`scripts/backup.sh`). Tắt cờ `COWORK_KHACH_ENABLED=0` là cách rollback an toàn mà
  không đổi code.


### Hợp đồng thu hồi VIP ID → CRM
`POST {CRM_PORTAL_INTERNAL_URL}/api/internal/portal/thu-hoi` (HMAC `vipid->crm`), body:
`{subject, reason, revoked_at, revoked_at_ms}` — `reason` ∈ `dang_xuat` | `dat_lai_mat_khau` |
`doi_mat_khau` | `rut_pilot` (tài khoản bị rút khỏi danh sách pilot); `revoked_at_ms` = **mili-giây unix (số nguyên) lúc thu hồi xảy ra tại VIP ID**,
ghi khi xếp hàng (gửi là bất đồng bộ); `revoked_at` = `revoked_at_ms // 1000` (giây, tương thích).

Launch token có thêm claim `iat_ms` (mili-giây unix lúc phát; `iat = iat_ms // 1000`).
**CRM so theo mili-giây:** từ chối khi `iat_ms < revoked_at_ms` (INTEROP-05: đăng xuất cùng giây với
launch). VIP ID bảo đảm bất biến theo từng tài khoản (lưu `revoked_at_ms`, `launch_at_ms`):
- mọi launch đã phát TRƯỚC một lần thu hồi có `iat_ms < revoked_at_ms` (kể cả cùng mili-giây);
- mọi launch phát SAU (đổi mật khẩu, đặt lại, đăng nhập lại) có `iat_ms > revoked_at_ms` —
  mốc thu hồi được lấy TRƯỚC khi tạo phiên mới.

#### Nguyên tử và kẹp đồng hồ (R8)
- Phát launch: **một giao dịch ghi** — kiểm phiên VIP ID còn sống + một
  `UPDATE … SET launch_at_ms = MIN(MAX(launch_at_ms, revoked_at_ms + 1, now), now + 5 phút) RETURNING`.
- Thu hồi (đăng xuất, đặt lại, đổi mật khẩu): **một giao dịch ghi** — một
  `UPDATE … SET revoked_at_ms = MIN(MAX(revoked_at_ms + 1, launch_at_ms + 1, now), now + 5 phút) RETURNING`
  + thu hồi phiên VIP ID tương ứng. Không có khe đọc-rồi-ghi giữa launch và thu hồi.
- Mốc lưu không vượt `now + 5 phút`; khi phải kẹp ⇒ audit `khach.canh_bao.dong_ho` + log WARNING.

#### Runbook: đặt lại mốc thời gian của một khách (sau sự cố đồng hồ)
Dấu hiệu: audit `khach.canh_bao.dong_ho`, hoặc khách đăng nhập được VIP ID nhưng CRM liên tục từ
chối launch (mốc `revoked_at_ms` ở tương lai).
1. Sửa đồng hồ máy chủ (NTP) trước.
2. `COWORK_DATA_DIR=… COWORK_DB_PATH=… .venv/bin/python -m cowork.cli khach-dat-lai-moc <SĐT|VG…|cust:…>`
   — đưa `revoked_at_ms`/`launch_at_ms` về hiện tại, thu hồi mọi phiên VIP ID của khách, ghi audit
   `khach.ops.dat_lai_moc`, in mốc mới.
3. Yêu cầu phiên CRM đặt lại `revoked_at_ms` của subject đó (phía CRM) về **cùng mốc** đã in.
4. Khách đăng nhập lại.

### Pilot (chạy thử có kiểm soát) và công tắc bảo trì
- `COWORK_KHACH_PILOT=1`: chỉ SĐT trong danh sách trắng (`COWORK_KHACH_PILOT_PHONES` ∪ tệp
  `COWORK_KHACH_PILOT_FILE`, đọc lại khi tệp đổi) được **đăng ký, đăng nhập, vào cổng, khôi phục**.
  Ngoài danh sách ⇒ trang "Cổng khách hàng VIP GROUP đang chạy thử nội bộ, sẽ mở sớm. Liên hệ
  hotline/Zalo …" (403): không tạo tài khoản, không gửi CRM, không kiểm mật khẩu, không đếm lượt.
  Quyết định chỉ dựa trên danh sách (SĐT của định danh, hoặc của tài khoản mang mã VG…) nên không lộ
  SĐT đã có tài khoản hay chưa. Phiên đang có của tài khoản bị rút khỏi danh sách hết dùng được;
  CRM xin link đặt lại cho tài khoản ngoài danh sách ⇒ 403 `PILOT`.
- CLI `cowork.cli khach-pilot add|remove|list` (sửa tệp nguyên tử, 0600, audit). SĐT trong env chỉ
  sửa được bằng env.
- Production bật realm khách **bắt buộc** đặt `COWORK_KHACH_PILOT=0` hoặc `1` (thiếu ⇒ từ chối khởi
  động) — buộc quyết định tường minh.
- **Công tắc khẩn** `COWORK_KHACH_MAINTENANCE_FILE` (mặc định `data/khach_bao_tri.flag`):
  `touch <tệp>` ⇒ mọi request host khách 503 bảo trì ngay; `rm <tệp>` ⇒ mở lại. Không ảnh hưởng
  realm nhân viên. Kiểm bằng `os.stat`: mọi lỗi khác "không có tệp" ⇒ coi như đang bảo trì.
  **Không đóng phiên portal CRM đang mở** — CRM có `portal.off` riêng; vận hành phải touch cả hai.
- Rút SĐT khỏi pilot (CLI hoặc sửa tay tệp — phát hiện khi tệp đổi) ⇒ thu hồi mọi phiên VIP ID + xếp
  hàng thu hồi portal CRM (`rut_pilot`, có `revoked_at_ms`). Đăng xuất vẫn dùng được với tài khoản
  ngoài pilot. Tệp pilot không đọc được ⇒ fail-closed (chỉ SĐT env), audit `khach.pilot.loi_tep`.
  Giới hạn: thay đổi xảy ra khi tiến trình đang tắt (hoặc sửa env) không được phát hiện như "rút" —
  phiên VIP ID của tài khoản ngoài danh sách vẫn bị chặn ở mỗi request, nhưng phiên portal CRM tồn
  tại tới khi hết hạn; khi đó chạy `khach-pilot remove` (hoặc `khach-dat-lai-moc`) để báo CRM.

### §15 — hai tên miền realm khách (dangky / dangnhap)
| Biến | Ví dụ production |
|---|---|
| `COWORK_KHACH_HOST_DANGKY` | `dangky.vipgroup.com.vn` — chỉ `/tai-khoan/dang-ky`, `/tai-khoan/cho-duyet`, static; `/` → đăng ký |
| `COWORK_KHACH_HOST_DANGNHAP` | `dangnhap.vipgroup.com.vn` — đăng nhập, đăng xuất, hồ sơ, đổi/quên/đặt lại mật khẩu, `vao-cong`, chờ duyệt, static, **API nội bộ**; `/` → đăng nhập |
| `COWORK_KHACH_DANGKY_URL` / `COWORK_KHACH_DANGNHAP_URL` | URL tuyệt đối cho liên kết chéo (mặc định `https://<host>` ở production) |
| `COWORK_KHACH_TIEP_CHO_PHEP` | `https://khachhang.vipgroup.com.vn/portal` (mặc định `CRM_PORTAL_PUBLIC_URL/portal`) |

- Mỗi host chỉ phục vụ route của nó (còn lại 404). Để trống cả hai ⇒ chế độ một host cũ
  (`COWORK_KHACH_HOSTS`, dùng cho dev/test). Chế độ hai host **bỏ** giá trị mặc định của
  `COWORK_KHACH_HOSTS`; production đặt cả hai kiểu ⇒ từ chối khởi động trừ khi
  `COWORK_KHACH_HOSTS_CA_HAI=1`.
- Cookie luôn host-only (không đặt `Domain`): `vg_khach` chỉ có ở dangnhap.
- `/api/internal/khach/*` chỉ trên host dangnhap **và** chỉ khi gọi trực tiếp qua mạng nội bộ:
  request mang `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `Via` (đi qua proxy công khai) ⇒ 404.
  Caddy nên chặn thêm `/api/internal/*` trên mọi site công khai.
- Turnstile: hostname trong phản hồi siteverify phải khớp đúng host đang phục vụ (dangky ≠ dangnhap).
- Link đặt lại mật khẩu (CRM xin) luôn trỏ host dangnhap.
- **`tiep` sau đăng nhập:** `GET /tai-khoan/dang-nhap?tiep=<URL tuyệt đối>` (và `vao-cong?tiep=`).
  Chỉ nhận khi URL khớp một tiền tố trong `COWORK_KHACH_TIEP_CHO_PHEP`: https (http chỉ ngoài
  production), đúng host (không userinfo, không cổng khác, không dấu chấm cuối), path bắt đầu bằng
  path cho phép theo ranh giới `/`, không `\`, `//`, `.`/`..`, ký tự điều khiển hay mã hoá đánh lừa
  (`%2F %5C %2E %00`…). Hợp lệ ⇒ launch `…/portal/auth/launch?token=…&tiep=<chỉ path>` (CRM tự quyết);
  không hợp lệ ⇒ bỏ qua, như `vao-cong` mặc định.

### §16 — Đăng ký tự kích hoạt (`COWORK_KHACH_TU_DONG`, owner chốt 09/11/2026)
Căn cứ: `DE_XUAT_TU_DONG_DUYET.md` §5–6 (repo website). Mặc định **tắt** (`0`): luồng chờ nhân viên
duyệt giữ nguyên từng chi tiết. Tắt cờ là rollback, không đổi dữ liệu (tài khoản đã tự kích hoạt vẫn
đăng nhập bình thường).

| Biến | Ý nghĩa |
|---|---|
| `COWORK_KHACH_TU_DONG` | `1` ⇒ đăng ký gọi CRM đồng bộ, CRM trả `kich_hoat` thì tạo tài khoản `hoat_dong` ngay |
| `CRM_PORTAL_INTERNAL_URL` | Đích nội bộ CRM (vd `http://crm:3000` trong mạng docker). Production + cờ bật ⇒ **bắt buộc đặt tường minh** |
| `COWORK_KHACH_TU_DONG_TIMEOUT` | Hạn chót tổng mỗi lời gọi CRM, giây (mặc định và tối đa 5) |
| `COWORK_KHACH_HANDOFF_TTL` | Hạn token chuyển phiên dangky → dangnhap, giây (10–60, mặc định 60) |

**Chặn khởi động khi cờ bật:** `CRM_PORTAL_INTERNAL_URL` phải là https, hoặc http CHỈ tới đích nội bộ
(cùng quy tắc với CRM `lib/internal-url.js`: tên dịch vụ docker một nhãn, `localhost`/`*.localhost`,
IPv4 127/8, 10/8, 172.16/12, 192.168/16, IPv6 `::1`, `fc00::/7`; không userinfo). Ở production còn bắt
buộc biến này được đặt tường minh và `VIPID_PORTAL_SECRET` có sẵn (env hoặc tệp
`VIPID_PORTAL_SECRET_FILE`, không tự sinh).

**Luồng `POST /tai-khoan/dang-ky` (host dangky)** — sau CSRF/cùng nguồn, Turnstile, định dạng, pilot,
giới hạn theo IP và trần toàn hệ thống (không đổi):
1. Chuẩn hoá SĐT; VIP ID đã có tài khoản với SĐT đó (mọi trạng thái chưa giải phóng, kể cả
   `cho_duyet`) ⇒ trang **"Số điện thoại này đã được đăng ký"** (409) với [Dùng số khác] [Đăng nhập]
   [Quên mật khẩu]. **Không gọi CRM** (tài khoản kia đang chờ duyệt thì vẫn tăng
   `phone_conflict_count` và xếp hàng cập nhật signup như luồng cũ).
2. Băm mật khẩu (luồng KDF), rồi gọi CRM **đồng bộ** trong executor riêng (`khach-crm-dk`, tối đa 16
   lời gọi đang chờ, vượt ⇒ bận): `POST {CRM_PORTAL_INTERNAL_URL}/api/internal/portal/dang-ky-tu-dong`,
   ký HMAC `vipid->crm` canonical như mọi lời gọi ra (`X-Portal-Ts`, `X-Portal-Sig` trên
   `vipid->crm.POST.<path>.<ts>.<body>`), `Idempotency-Key` = subject, body
   `{subject, display_name, phone_e164, email|null}`. Host = host của `CRM_PORTAL_INTERNAL_URL`
   (httpx tự đặt, như hàng đợi signup/thu-hoi), không proxy từ env, không theo chuyển hướng, không
   chuyển tiếp header nào của trình duyệt.
3. Kết quả (kiểm chặt hình dạng):
   - `kich_hoat {crm_customer_id, portal_code}` ⇒ tạo tài khoản `hoat_dong`, `phone_verified_at=now`,
     `phone_verified_method='tu_dong'`, audit `khach.dang_ky.tu_dong` ⇒ trang **"Tạo tài khoản thành
     công · Mã khách hàng VGxxxx"** (201) với nút **Vào cổng khách hàng**.
   - `trung/tai_khoan_cong` ⇒ như bước 1. `trung/ho_so_cu` ⇒ "Số này đã có hồ sơ khách hàng tại VIP
     GROUP. Vui lòng gọi hoặc nhắn Zalo 0961 102 655…" + [Dùng số khác]. Không tạo tài khoản.
   - HTTP ≠ 200 (503 `AUTO_APPROVE_OFF`, 401 chữ ký, 409 phát lại…), quá hạn, lỗi mạng, JSON sai, hình
     dạng sai, `portal_code`/`crm_customer_id` sai ⇒ form đăng ký kèm "Hệ thống đang bận, vui lòng thử
     lại sau ít phút." (503). Không tạo gì, không xếp hàng; audit `khach.dang_ky.tu_dong.crm_loi`
     (lấy mẫu 1 dòng/phút).

**Đăng ký chờ phía server (chống khoá khách ra ngoài — review vòng 10 P1).** Trước khi gọi CRM,
VIP ID ghi `customer_tu_dong_cho` khoá theo **SĐT đã chuẩn hoá** (một giao dịch ghi): subject, họ tên,
email, băm mật khẩu của lần thử mới nhất, `attempts`, `last_attempt`, `expires_at` (TTL trượt
`COWORK_KHACH_TU_DONG_CHO_GIO`, mặc định 24 giờ).
- Còn hạn ⇒ **mọi** lần thử lại cho SĐT đó (mọi trình duyệt) dùng **lại subject** ⇒ CRM idempotent theo
  subject trả lại đúng `kich_hoat` cũ dù lần trước CRM đã commit nhưng trả lời sau hạn chót 5 s. Không
  thêm rủi ro: owner đã chấp nhận việc đăng ký bằng SĐT của người khác (Q3).
- Hết hạn ⇒ subject mới; subject cũ giữ ở `acc_id_cu`. CRM trả `trung/tai_khoan_cong` cho subject mới
  ⇒ VIP ID thử lại **một lần** bằng subject cũ; CRM trả `kich_hoat` ⇒ kích hoạt bằng subject cũ.
- Xoá dòng khi thành công hoặc trùng dứt khoát (`tai_khoan_cong`/`ho_so_cu`). Dòng không ai đụng tới
  quá 30 × TTL bị dọn (subject vẫn còn trong audit).
- Thử lại với họ tên/email/mật khẩu khác: VIP ID lưu giá trị của **lần gọi thành công** (ý định hiện
  tại). CRM (idempotent) có thể vẫn giữ họ tên/email của lần đầu — lệch này được chấp nhận; hồ sơ CRM
  là nguồn đúng về họ tên, nhân viên sửa ở CRM.

**Phân loại lỗi CRM (audit).**
- `khach.dang_ky.tu_dong.co_the_mo_coi` (KHÔNG lấy mẫu, kèm subject + `phoneSha256`): CRM **có thể**
  đã tạo khách — quá hạn chót, quá hạn đọc, đứt kết nối sau khi gửi, 5xx khác 503, 200 sai hình dạng.
- `khach.dang_ky.tu_dong.crm_loi` (lấy mẫu 1 dòng/phút): CRM chắc chắn chưa tạo — không kết nối được,
  4xx (401 chữ ký, 409 phát lại…), 503 `AUTO_APPROVE_OFF`.
- `khach.dang_ky.tu_dong.mo_coi`: CRM trả `kich_hoat` mà VIP ID không lưu được (mã VG/crm id đã thuộc
  tài khoản khác, DB lỗi sau một lần thử lại, hoặc SĐT vừa được subject KHÁC giành). Lượt song song
  cùng subject (nhờ đăng ký chờ) không bị ghi mồ côi.

**Đối soát (ops):** `python -m cowork.cli khach-doi-soat <SĐT|cust:kh_…> [--sdt … --ten … --email …]`
- Hỏi lại CRM bằng **cùng endpoint, subject đã lưu** (CRM idempotent). CRM báo `kich_hoat` ⇒ tạo tài
  khoản `hoat_dong` (`phone_verified_by=cli:<user>`, audit `khach.ops.doi_soat_tu_dong`) với mật khẩu
  khách đã đặt ở lần thử cuối. In kết quả.
- Theo subject (lấy từ audit `co_the_mo_coi`) khi không còn đăng ký chờ: cần `--sdt` và `--ten`; tài
  khoản tạo với mật khẩu ngẫu nhiên ⇒ nhân viên cấp link đặt lại (đường hotline/Zalo hiện có). Lưu ý:
  nếu CRM chưa từng thấy subject đó, lời gọi sẽ **tạo** khách ở CRM (hoàn tất đăng ký thay khách).
- Mã thoát: 0 đã tạo / đã liên kết (chạy lại an toàn) · 1 trùng hoặc không có dữ liệu · 2 tham số sai ·
  3 CRM bận. SĐT đã thuộc tài khoản VIP ID có subject khác ⇒ không đổi gì.

**Giới hạn luồng gọi CRM.** Mỗi pha httpx (connect/write/read/pool) ≤ `COWORK_KHACH_TU_DONG_TIMEOUT`
(≤ 5 s) **và** hạn chót tổng: thân phản hồi đọc dạng luồng, quá hạn tổng hoặc quá 16 KB ⇒ dừng (CRM
nhỏ giọt không giữ được luồng). Bộ đếm trần 16 đếm **luồng thật** (giảm khi luồng xong, không phải khi
request hết chờ) ⇒ luồng treo không tích tụ vượt trần; vượt trần ⇒ báo bận ngay.

**Đồng thời cùng SĐT.** `customer_accounts.phone_e164 UNIQUE` ⇒ chỉ một tài khoản; lượt thua thấy
"đã được đăng ký". Các lượt cùng lúc dùng chung subject đã lưu nên CRM chỉ có một khách.

**Chuyển phiên dangky → dangnhap (`POST /tai-khoan/nhan-phien`, chỉ host dangnhap).** Cookie host-only
nên trang thành công trên dangky không đặt được phiên dangnhap. Trang này chứa một form POST (body, không
nằm trên URL) sang `https://dangnhap…/tai-khoan/nhan-phien` với token
`v1.<account_id>.<exp>.<nonce>.<HMAC SECRET_KEY>`:
- **gắn tài khoản**: `account_id` nằm trong phần ký VÀ trong dòng DB `customer_handoff` (chỉ lưu
  sha256 nonce); đổi tài khoản ⇒ sai chữ ký hoặc không khớp dòng;
- **≤ 60 giây**: kiểm cả `exp` trong token (không được xa hơn TTL) lẫn `expires_at` trong DB;
- **một lần**: `UPDATE … SET used_at WHERE used_at IS NULL` nguyên tử; phát lại ⇒ 400;
- **chống login CSRF**: chỉ nhận `Origin` đúng bằng origin dangky (chế độ một host: cùng nguồn);
  trang lạ không gửi được. CSP `form-action` chỉ mở thêm origin dangnhap cho riêng trang thành công;
- tài khoản phải còn `hoat_dong` + đủ điều kiện (bị CRM khoá trong 60 giây đó ⇒ từ chối) và thuộc
  pilot (khi pilot bật);
- thành công ⇒ tạo phiên `vg_khach` + cookie thiết bị như đăng nhập thường, audit `khach.handoff`, rồi
  303 thẳng sang launch token của CRM (vào cổng). Hết hạn/đã dùng ⇒ trang "Liên kết vào cổng đã hết
  hạn…" + link đăng nhập; trang thành công cũng có link `dang-nhap?u=VGxxxx` (chỉ điền sẵn mã VG,
  không bao giờ đưa SĐT hay mật khẩu lên URL).

**Tài khoản tự kích hoạt** đăng nhập y như tài khoản được duyệt (`hoat_dong` + SĐT đã xác minh +
`crm_customer_id`). Tài khoản `cho_duyet` có sẵn vẫn đi đường `ket-qua-duyet` cũ (lệnh backlog Q4 phía
CRM gọi đúng đường đó).

**CRM giả** (`scripts/khach_mock_crm.py`, `COWORK_KHACH_TU_DONG=1 ./scripts/khach-dev.sh --mock-crm`):
SĐT đuôi 7 ⇒ `ho_so_cu`; đuôi 6 ⇒ 503 `AUTO_APPROVE_OFF`; SĐT đã cấp ⇒ `tai_khoan_cong`; còn lại ⇒
`kich_hoat` VG1001, VG1002…; idempotent theo subject; `MOCK_AUTO_APPROVE=0` ⇒ mọi lời gọi 503.

**Rủi ro owner đã chấp nhận** (§3 đề xuất): lộ "số này đã đăng ký" (giảm bằng Turnstile, 5 lượt/giờ/IP,
trần 200/giờ; thông báo không nói tên hay mã khách); không xác minh chủ SĐT (Q3).
