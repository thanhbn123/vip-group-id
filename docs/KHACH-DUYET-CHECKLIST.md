# Checklist nhân viên — duyệt đăng ký cổng khách hàng

Áp dụng cho màn "Duyệt đăng ký khách" (CRM). **Quyết định owner 07/11/2026:** bỏ cả bước xác
minh email lẫn bước gọi điện xác minh SĐT. Khách đăng ký là có ngay một yêu cầu `cho_duyet`;
**nhân viên duyệt là cổng kiểm soát duy nhất**. Khi duyệt, VIP ID ghi `phone_verified_at` = thời
điểm duyệt, `phone_verified_by` = nhân viên duyệt (nếu CRM gửi), phương thức `duyet_crm`.

## Trước khi duyệt
- **Kiểm cờ `phone_conflict` / `phone_conflict_count`.** Nếu > 0: đã có người khác thử đăng ký
  **cùng số điện thoại** với yêu cầu này — nghi giữ chỗ số của người khác. Khuyến nghị gọi điện
  hoặc nhắn Zalo cho chủ số để xác nhận họ tên trước khi duyệt; không chắc ⇒ **từ chối**.
- Đối chiếu họ tên, SĐT (và email nếu có) với hồ sơ khách sẵn có trong CRM; trùng khách cũ ⇒
  chọn "liên kết hồ sơ có sẵn" (có audit), không tạo hồ sơ mới.
- Không cần gọi điện cho mọi yêu cầu (owner đã bỏ bước này); vẫn có thể gọi khi nghi ngờ.

## Khi không khớp
- Nghi sai chủ số ⇒ **từ chối** (ghi lý do). VIP ID giải phóng SĐT của đăng ký bị từ chối để chủ
  thật đăng ký lại.

## Khôi phục mật khẩu (do nhân viên hỗ trợ)
Khách quên mật khẩu liên hệ hotline/Zalo (mặc định 0961 102 655):
1. **Gọi lại đúng SĐT của tài khoản** và xác nhận danh tính (họ tên, mã khách VG…).
2. Bấm "Cấp link đặt lại mật khẩu" trong CRM (CRM gọi `POST /api/internal/khach/tao-link-dat-lai`).
3. Gửi link cho khách **qua Zalo của đúng SĐT đó**. Link dùng một lần, hết hạn sau 30 phút;
   cấp link mới làm link cũ mất hiệu lực. Đặt lại xong, mọi phiên đăng nhập cũ bị đăng xuất.
4. Không đọc link qua điện thoại cho người khác, không gửi tới số khác.

## Ghi nhận
Mọi lần duyệt/từ chối/cấp link đều ghi audit ở cả CRM và VIP ID (`tenant_id='khach'`).
