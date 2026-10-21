# COWORK — deploy staging trên VPS

Mục tiêu: dựng **bản staging** trên VPS cổng `127.0.0.1:8899`, dùng bản copy DB production,
**không đổi Caddy/Brain production**. Sau khi kiểm tra đạt mới bàn giao cutover.

## Yêu cầu
- Docker + Docker Compose (VPS đã có).
- Cổng 8899 trống.
- `data/` chứa `cowork.db`, `secret.key`, `brain_secret.key` (copy từ Studio, 0600).
- `.env.staging` từ `.env.staging.example`; staging để `COWORK_BRAIN_ENABLED=0` vì Brain
  production đang trỏ `COWORK_INTERNAL_URL` về Studio.

## Chạy
```bash
cd /srv/vip-staging/cowork
cp deploy/vps/.env.staging.example deploy/vps/.env.staging
# sửa .env.staging nếu cần
mkdir -p deploy/vps/data && chmod 700 deploy/vps/data
# copy dữ liệu vào deploy/vps/data/
docker run --rm -v "$PWD/deploy/vps/data:/data" alpine:3.20 \
  chown -R 10001:10001 /data
docker compose -f deploy/vps/docker-compose.yml up -d --build
curl -s http://127.0.0.1:8899/api/health
```

## Kiểm tra
- `/api/health` 200, `db=ok`.
- Đăng nhập owner (MFA staging tùy DB copy), `/api/me` 200.
- `docker ps` healthy; log không lỗi.

## Cutover (chưa làm)
Chỉ sau khi chủ dự án duyệt:
1. Caddy đổi upstream `cowork` từ `127.0.0.1:18835` sang `127.0.0.1:8899`.
2. Brain `.env` đổi `COWORK_INTERNAL_URL=https://cowork.vipgroup.com.vn`.
3. Chuyển backup/offsite sang VPS hoặc giữ Studio làm bản dự phòng.

## Trạng thái đã chạy (19/10/2026 20:18)

- Repo GitHub: `https://github.com/thanhbn123/vip-group-id` (public, branch `main`).
- VPS: `/srv/vip-staging/cowork`, container `cowork-staging` healthy, `127.0.0.1:8899`.
- DB copy production: integrity ok, 7 user, 110 audit, schema 2.
- Login owner staging: 200 `/`, `/api/me` 200 Super Admin.
- **Chưa cutover**: Caddy vẫn `reverse_proxy 127.0.0.1:18835` (Studio); Brain vẫn gọi
  `COWORK_INTERNAL_URL=http://127.0.0.1:8899` (Studio).
- Bằng chứng: `evidence/VPS-staging-20261019.txt`.

### Cutover cần duyệt
1. Đổi Caddy `cowork` sang `127.0.0.1:8899`; reload; kiểm TLS/health.
2. Đổi Brain `.env` `COWORK_INTERNAL_URL=https://cowork.vipgroup.com.vn`; restart backend.
3. Đổi `.env.staging` thành production (`COOKIE_SECURE=1`, `TIN_PROXY=1`, public URL thật,
   `BRAIN_ENABLED=1`, Brain base/public URL thật), restart container.
4. Chuyển backup/offsite sang VPS; giữ bản Studio làm dự phòng đến khi ổn định.
5. Rollback: Caddy về 18835; Brain internal về `http://127.0.0.1:8899`; restart.

## Truy cập staging (nội bộ)

Từ MacBook:
```bash
ssh -L 18899:127.0.0.1:8899 viporder-staging
# mở http://127.0.0.1:18899
```
Mật khẩu owner lấy trên Studio như production; DB copy đang để MFA tắt.

## Cập nhật staging
```bash
ssh viporder-staging
cd /srv/vip-staging/cowork
./deploy/vps/deploy.sh
```

## CUTOVER PRODUCTION — ĐÃ HOÀN TẤT (19/10/2026 20:26)

- Caddy `cowork` → `127.0.0.1:8899` (VPS); đã restart container để nhận file mới.
- Brain `COWORK_INTERNAL_URL=https://cowork.vipgroup.com.vn`.
- Nghiệm thu 8/8 PASS; owner SSO/chat local thật; logout thu hồi Brain 401.
- Backup VPS local cron **03:20**; offsite Synology **03:50**.
- Backup/offsite Studio cũ đã tắt.
- Rollback: Caddy về `18835` + restart; Brain internal về `http://127.0.0.1:8899`; bật lại backup Studio.
- Chi tiết: `evidence/PRODUCTION-CUTOVER-20261019.md`.

### Vận hành
```bash
ssh viporder-staging
cd /srv/vip-staging/cowork
./deploy/vps/deploy.sh          # cập nhật app
./deploy/vps/backup.sh          # backup ngay
crontab -l | grep cowork        # lịch 03:20
```
