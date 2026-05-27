# Module Data User (Thành viên 3)

Đây là thư mục chứa mã nguồn dành cho Thành viên 3 (Đóng vai trò là User tải và giải mã bệnh án).

## Cấu trúc:
- `user_app.py`: Ứng dụng chính (CLI). Chạy lệnh này để xin key và giải mã.
- `cpabe_user.py`: Chứa class bọc `charm-crypto` để giải mã CP-ABE bằng SK.
- `aes_utils.py`: Chứa hàm giải mã dữ liệu y tế bằng AES-256-CBC.
- `azure_cloud.py`: Code kết nối Azure (hiện tại mô phỏng đọc file từ thư mục `data/`).
- `config.py`: File cấu hình mạng, cổng, IP của TA Server.
- `ta_client.py` & `ssl_utils.py`: Thư viện kết nối socket SSL tái sử dụng từ TV1.

## Hướng dẫn chạy:
1. Sửa `config.py` để trỏ tới đúng IP của máy tính Thành viên 1.
2. Xin Thành viên 1 file `ta_cert.pem` và đặt vào thư mục `certs/`.
3. Nhờ Thành viên 2 gửi cho 1 file mã hoá lưu vào thư mục `data/` với tên `cloud_record_123.json`.
4. Chạy app:
   ```bash
   python3 user_app.py --attrs DOCTOR HOSPITAL_A --record 123
   ```
