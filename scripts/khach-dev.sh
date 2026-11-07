#!/bin/sh
# Chạy realm KHÁCH local trên cổng 8898 với DB + bí mật RIÊNG (data/khach-dev*), không đụng
# data/cowork.db. Mở: http://khach.localhost:8898/tai-khoan/dang-ky
#
#   ./scripts/khach-dev.sh              # chỉ VIP ID realm khách
#   ./scripts/khach-dev.sh --mock-crm   # kèm CRM giả trên 127.0.0.1:8897
#
# Xem email (outbox):   COWORK_DATA_DIR=data/khach-dev COWORK_DB_PATH=data/khach-dev.db \
#                         .venv/bin/python -m cowork.cli khach-outbox
# Duyệt giả (thay CRM): ... cowork.cli khach-duyet-dev 0900000001 --portal-code VG1001
set -eu
cd "$(dirname "$0")/.."
umask 077
PY="${PY:-.venv/bin/python}"
[ -x "$PY" ] || PY=../vip-group-id/.venv/bin/python
[ -x "$PY" ] || { echo "Không thấy python venv (đặt PY=...)."; exit 78; }

mkdir -p data/khach-dev
chmod 700 data data/khach-dev
export COWORK_ENV=local
export COWORK_DATA_DIR="$PWD/data/khach-dev"
export COWORK_DB_PATH="$PWD/data/khach-dev.db"
export COWORK_PORT=8898
export COWORK_PUBLIC_URL=http://127.0.0.1:8899
export COWORK_INTERNAL_URL=http://127.0.0.1:8899
export COWORK_BRAIN_ENABLED=0
export COWORK_COOKIE_SECURE=0
export COWORK_KHACH_ENABLED=1
# Tên host khách phải KHÁC tên host nhân viên (127.0.0.1) — cookie không tách theo cổng.
export COWORK_KHACH_HOSTS="${COWORK_KHACH_HOSTS:-khach.localhost:8898}"
export COWORK_STAFF_HOSTS="${COWORK_STAFF_HOSTS:-127.0.0.1:8899}"
export COWORK_KHACH_PUBLIC_URL="${COWORK_KHACH_PUBLIC_URL:-http://khach.localhost:8898}"
export CRM_PORTAL_INTERNAL_URL="${CRM_PORTAL_INTERNAL_URL:-http://127.0.0.1:8897}"
export CRM_PORTAL_PUBLIC_URL="${CRM_PORTAL_PUBLIC_URL:-http://127.0.0.1:8897}"
export VIPID_PORTAL_SECRET_FILE="${VIPID_PORTAL_SECRET_FILE:-$PWD/data/khach-dev/portal_secret.key}"
# Bí mật dev sinh tự động (0600) ở lần chạy đầu; CRM dev đọc cùng tệp này.

if [ "${1:-}" = "--mock-crm" ]; then
  "$PY" -c "from cowork import khach; khach.portal_secret()"   # tạo tệp bí mật nếu chưa có
  "$PY" scripts/khach_mock_crm.py &
  MOCK_PID=$!
  trap 'kill $MOCK_PID 2>/dev/null || true' EXIT INT TERM
fi

"$PY" -m uvicorn cowork.main:app --host 127.0.0.1 --port 8898 --no-access-log --no-proxy-headers
