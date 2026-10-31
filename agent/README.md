# Agent Hạ tầng → COWORK

Một tệp `hatang_agent.py` (Python stdlib, chỉ ĐỌC máy), chạy 10 phút/lượt,
đo máy rồi POST ảnh chụp về `/api/internal/hatang/bao-cao` bằng HMAC.

Máy chủ phải có sẵn trong sổ `hatang_may_chu` của COWORK (danh sách trắng) —
agent lạ bị 403. Thêm máy mới: anh bảo → thêm dòng vào sổ → cài agent.

## Cấu hình (tệp env, người đặt MỘT lần — §20.4, không vào Git)

```
HATANG_MAY_CHU=vps-160-22-171-228
HATANG_COWORK_URL=https://cowork.vipgroup.com.vn
HATANG_SECRET_FILE=/etc/cowork-agent/secret
```

Bí mật: cùng giá trị với `COWORK_HATANG_SHARED_SECRET` (hoặc `data/hatang_secret.key`)
bên COWORK. Sinh trên máy chủ, chmod 600, KHÔNG dán vào hội thoại/log.

## Cài

- **Máy chạy root + systemd** (VPS 160.22.171.228): dùng `hatang-agent.service`
  + `hatang-agent.timer` (xem chú thích đầu tệp service).
  ⚠ Với VPS 160.22.171.228, đường đưa tệp lên là repo `vps-160.22.171.228`
  (CLAUDE.md §20.9) — ở đó đã có bản sao kèm ghi nguồn gốc, đừng scp thẳng.
- **Máy không có quyền root** (vd user `deploy` trên 160.22.170.20): cron.
  `crontab -e` thêm:
  ```
  */10 * * * * set -a; . $HOME/.config/cowork-agent/env; set +a; /usr/bin/python3 $HOME/.local/opt/cowork-agent/hatang_agent.py >> $HOME/.local/state/cowork-agent.log 2>&1

  ⚠ PHẢI có `set -a` quanh lượt nạp env: `.` trong sh chỉ đặt BIẾN SHELL, không
  export, nên python sẽ không thấy — đã dính thật trên 160.22.170.20 lúc 22:40
  31/10/2026 (hai lượt cron đầu báo "Thiếu HATANG_MAY_CHU…" trong khi chạy tay
  với `set -a` thì chạy ngon — đúng dạng §12.1 ca 8: đo thiếu một ca).
  ```
  Phần không đo được vì thiếu quyền (Caddyfile, một số unit) agent tự bỏ qua
  và màn hình hiện "—" — thiếu một phép đo không làm chết cả lượt.

## Phạm vi — nói rõ

Agent đo: systemd unit tự viết, /proc, df /, docker ps, VIP Vault (nếu có).
KHÔNG đo: container từng dự án bên trong, CSDL, mạng, chứng chỉ TLS.
Mã thoát khác 0 khi gửi hỏng — systemd/cron thấy được, không hỏng im lặng.
