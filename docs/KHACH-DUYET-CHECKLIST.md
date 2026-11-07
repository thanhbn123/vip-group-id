# Checklist nhân viên — duyệt đăng ký cổng khách hàng

Áp dụng cho màn "Duyệt đăng ký khách" (CRM). VIP ID chỉ kích hoạt tài khoản khi CRM gửi
`ket-qua-duyet` với `phone_verified_by` là người đã gọi điện.

## Trước khi gọi
- Xem cờ **`phone_conflict`** / **`phone_conflict_count`** của đăng ký. Nếu > 0: đã có người
  khác (email khác) thử đăng ký **cùng số điện thoại** — nghi giữ chỗ. Gọi đặc biệt cẩn thận.
- Không gọi số khác ngoài số trong đăng ký; không gửi mã/link qua kênh khác.

## Khi gọi số điện thoại trong đăng ký
Hỏi người nghe máy, **không đọc trước thông tin cho họ**:
1. **Họ và tên** — phải khớp tên trong đăng ký.
2. **Địa chỉ email** đã dùng để đăng ký — phải khớp **đúng** email trong đăng ký.
3. Xác nhận họ **chủ động** đăng ký cổng khách hàng VIP GROUP.

Chỉ tích "đã gọi xác minh SĐT" và **duyệt** khi cả tên **và** email đều khớp với chủ số.

## Khi không khớp
- Tên hoặc email không khớp, hoặc chủ số nói không đăng ký ⇒ **từ chối** (ghi lý do).
  VIP ID sẽ giải phóng SĐT và email của đăng ký bị từ chối để chủ thật đăng ký lại.
- Khuyên chủ số tự đăng ký lại bằng email của chính họ.
- Không gọi được sau nhiều lần: để chờ, không duyệt.

## Ghi nhận
Mọi lần duyệt/từ chối đều ghi audit ở cả CRM và VIP ID (`tenant_id='khach'`).
