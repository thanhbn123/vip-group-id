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

## Trùng hồ sơ cũ (`ho_so_cu`) — đăng ký tự kích hoạt §16
Khi bật `COWORK_KHACH_TU_DONG=1`, khách đăng ký bằng SĐT trùng **hồ sơ khách cũ** (chưa có tài khoản
cổng) sẽ thấy "Số này đã có hồ sơ tại VIP GROUP… nhân viên xác minh và gửi link đặt mật khẩu tới số
điện thoại trên hồ sơ". CRM hiện yêu cầu ở tab **"Trùng hồ sơ cũ"**; VIP ID giữ một tài khoản
`cho_duyet` gắn subject đó. **Người đăng ký chưa chắc là chủ hồ sơ** — làm đúng thứ tự:
1. **Gọi đúng SĐT ghi trên hồ sơ CRM** (không gọi số khách tự khai ở nơi khác).
2. Xác nhận người nghe máy **chính là người vừa đăng ký** (họ tên, thời điểm đăng ký, thông tin trên
   hồ sơ). Không xác nhận được ⇒ **Từ chối** (VIP ID giải phóng SĐT).
3. Bấm **Liên kết** hồ sơ có sẵn. VIP ID kích hoạt tài khoản nhưng **thay mật khẩu khách tự đặt bằng
   mật khẩu ngẫu nhiên** và đăng xuất mọi phiên (audit `khach.ho_so_cu.lien_ket_dat_lai_mk`): mật
   khẩu lúc đăng ký **không còn đăng nhập được**.
4. Bấm **"Cấp link đặt lại mật khẩu"** và gửi link **qua Zalo CHỈ tới SĐT trên hồ sơ CRM**. Link dùng
   một lần, hạn 30 phút. Khách đặt mật khẩu mới rồi đăng nhập bằng SĐT hoặc mã VG.
5. Không gửi link tới số khác, không đọc link qua điện thoại.

## Ghi nhận
Mọi lần duyệt/từ chối/cấp link đều ghi audit ở cả CRM và VIP ID (`tenant_id='khach'`).
