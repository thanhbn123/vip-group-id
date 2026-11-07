# COWORK → CRM nội bộ: phụ lục Production Pilot

Ngày 07/11/2026 · VIP ID Controller · nhánh `feature/cowork-crm` (gộp SAU `feature/khach-p1`).
Bổ sung cho `vip-group-com-vn/docs/cong-khach-hang/PHUONG_AN_PILOT_P1.md` (§4 P-01…P-11). Hợp đồng: `KIEN_TRUC_P1.md` §15.6.

Mọi thao tác hạ tầng và production dưới đây chỉ chạy khi owner gửi đúng **câu duyệt**.

## 1. Hiện trạng (đã kiểm chỉ đọc lúc 19:40 ngày 07/11)

| Mục | Kết quả |
|---|---|
| DNS `dangky`, `dangnhap`, `khachhang`, `cowork`, `crm` | ✅ Cả 5 tên miền trỏ A về 160.22.170.20 |
| `https://cowork.vipgroup.com.vn/api/health` | ✅ 200, db ok |
| `https://crm.vipgroup.com.vn` | ❌ Lỗi TLS (`tlsv1 alert internal error`): Caddy chưa có khối site. Kế hoạch CRM: NO-GO PUBLIC, chờ owner và người giữ root |
| `https://dangnhap…`, `https://khachhang…` | ❌ Lỗi TLS, cùng nguyên nhân (chờ P-09) |
| Code | ✅ `cowork-crm` 329 test PASS. Liên thông với `verifyCoworkToken` thật của CRM (đã siết, c02474b) PASS. Verifier vòng 9: GO |

**Điều kiện chặn:** CRM nội bộ phải có HTTPS công khai tại `crm.vipgroup.com.vn` (kế hoạch `VIP_CRM_V6_HTTPS_GO_PUBLIC_PLAN.md` của CRM). Chưa có thì nút "Mở CRM" sẽ dẫn tới trang lỗi TLS.

## 2. Thao tác cần duyệt (nối tiếp P-11)

| Mã | Thao tác | Ai làm | Câu duyệt |
|---|---|---|---|
| P-01 / P-03 | Push, PR và deploy VIP ID **gồm cả** `feature/cowork-crm` (sau `khach-p1`). Không phát sinh thêm downtime | Website Controller | (dùng chung câu duyệt P-01 / P-03) |
| P-09b | Khối Caddy `crm.vipgroup.com.vn` → CRM prod (theo kế hoạch HTTPS của CRM) | Owner hoặc người giữ root | Người root thực hiện, báo "xong P-09b" |
| P-12 | Sinh **một** bí mật launch mới trên VPS: `openssl rand -hex 32`. Ghi vào VIP ID `/data/crm_launch_secret.key` (0600) và `COWORK_SHARED_SECRET` trong `secrets/app.env` của CRM prod (0600). Không đi qua chat hay log. Khởi động lại app CRM (< 1 phút) | VIP ID + CRM Controller qua SSH | `DUYỆT P-12 SECRET CRM` |
| P-13 | Cấp quyền `crm.view` và `crm.use` trong COWORK: màn **Vai trò** (theo vai trò) hoặc **Phân quyền module** (từng người). Có audit | **Owner** (giao diện COWORK) | Owner tự làm |
| P-14 | Liên kết nhân sự trong CRM: vip_admin đặt `vip_subject = cowork:<ID đăng nhập COWORK>` (màn Nhân sự). Mỗi nhân viên xem mã của mình ở `cowork…/crm` | vip_admin CRM | Owner chỉ định danh sách |

## 3. Cấu hình VIP ID production (thêm vào §5 của phương án Pilot)

```
COWORK_CRM_ENABLED=1
COWORK_CRM_PUBLIC_URL=https://crm.vipgroup.com.vn
COWORK_CRM_TENANT_MAP=vip-group=VIP
COWORK_CRM_LAUNCH_SECRET_FILE=/data/crm_launch_secret.key   # 0600, P-12
# COWORK_CRM_LAUNCH_TTL mặc định 60 (cho phép 1..60)
```

- Thiếu bí mật, bí mật yếu hoặc trùng bí mật khác: module báo "chưa cấu hình" và không phát token. COWORK vẫn chạy bình thường.
- Bí mật launch trùng `VIPID_PORTAL_SECRET`: realm khách **từ chối khởi động**.

## 4. Smoke sau P-12 / P-13 / P-14 (owner, khoảng 5 phút)

1. Đăng nhập `cowork.vipgroup.com.vn` → menu **CRM VIP GROUP** → **Mở CRM**. Kết quả mong đợi: vào CRM đúng tài khoản, không hỏi đăng nhập lại.
2. Bấm Back và mở lại đúng URL launch cũ. Mong đợi: CRM từ chối (`TOKEN_REPLAYED`).
3. Đăng nhập một nhân viên **chưa** được cấp `crm.use`. Mong đợi: không thấy menu; vào thẳng `/crm` thì 403.
4. Nhân viên đã được cấp quyền nhưng **chưa** liên kết `vip_subject`. Mong đợi: CRM báo `SUBJECT_UNKNOWN`.
5. `cowork…/nhat-ky` có dòng `crm.launch` (kèm nonce, không có token). CRM audit có `auth.cowork.launch`.

## 5. Tắt nhanh và rollback

| Mức | Cách làm | Hiệu lực |
|---|---|---|
| Một người | Bỏ `crm.use` của người đó (Phân quyền module) | Ngay, không restart |
| Tất cả | Bỏ `crm.use` khỏi các vai trò (màn Vai trò) | Ngay, không restart |
| Kết nối | `COWORK_CRM_ENABLED=0` rồi restart COWORK; hoặc xoá `COWORK_SHARED_SECRET` phía CRM rồi restart CRM (CRM trả 503) | < 1 phút |
| Code | Quay về image VIP ID trước P-03 (`docs/ROLLBACK.md`). Thay đổi chỉ là bổ sung: không đổi bảng; module và quyền thêm vào registry | Theo quy trình P-03 |

**Lưu ý:** thu hồi quyền hoặc khoá tài khoản COWORK **không** huỷ phiên CRM đang mở. Phiên CRM tự hết hạn theo `sessionTtlHours`. Muốn chặn ngay thì vip_admin khoá user trong CRM. Đồng bộ thu hồi COWORK → CRM để P2.
