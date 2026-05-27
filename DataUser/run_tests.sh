#!/bin/bash
# ==============================================================================
# run_tests.sh — Kịch bản kiểm thử tự động hệ thống CP-ABE EHR (Module User - TV3)
# ==============================================================================

# Định dạng màu sắc hiển thị
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BLUE}   KỊCH BẢN KIỂM THỬ TỰ ĐỘNG - MODULE DATA USER (THÀNH VIÊN 3)      ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# Kiểm tra sự tồn tại của certs/ta_cert.pem
CERT_FILE="certs/ta_cert.pem"
if [ ! -f "$CERT_FILE" ]; then
    echo -e "${YELLOW}[CẢNH BÁO] Không tìm thấy file chứng chỉ SSL $CERT_FILE.${NC}"
    echo -e "${YELLOW}Vui lòng lấy cert từ Thành viên 1 và lưu vào thư mục certs/ để chạy online.${NC}"
fi

# Đảm bảo thư mục dữ liệu tồn tại
mkdir -p data
mkdir -p keys

# Kiểm tra xem có file dữ liệu mock chưa, nếu chưa có tạo một file mẫu cơ bản
MOCK_FILE="data/cloud_record_123.json"
if [ ! -f "$MOCK_FILE" ]; then
    echo -e "${YELLOW}[THÔNG TIN] Tạo file giả lập dữ liệu y tế mẫu tại $MOCK_FILE...${NC}"
    # Bản ghi mẫu giả lập dạng Base64
    cat <<EOF > "$MOCK_FILE"
{
  "public_key": "MOCK_PK_BASE64_PLACEHOLDER",
  "encrypted_aes_key": "MOCK_ENC_AES_KEY_BASE64_PLACEHOLDER",
  "ciphertext": "U2VuZCBpbiB0aGUgY2xvbmVzLCB0aGlzIGlzIGEgZGVjcnlwdGVkIEVIUiByZWNvcmQh"
}
EOF
fi

# ──── KỊCH BẢN 1: USER 1 (HỢP LỆ) ──────────────────────────────────────────────
echo -e "\n${BLUE}----------------------------------------------------------------------${NC}"
echo -e "${GREEN}[SCENARIO 1] Kiểm thử User 1: Thỏa mãn Access Policy (DOCTOR, HOSPITAL_A)${NC}"
echo -e "${BLUE}----------------------------------------------------------------------${NC}"
echo -e "Hệ thống sẽ thử nạp Secret Key của User 1 để giải mã hồ sơ..."

# Chạy thử nghiệm offline (hoặc kết nối TA online nếu có mạng)
# Nếu chạy thực tế online, bỏ cờ --offline và thêm --email, --password
python3 user_app.py --attrs DOCTOR HOSPITAL_A --record 123 --offline

if [ $? -eq 0 ]; then
    echo -e "\n${GREEN}==> KẾT QUẢ TEST 1: THÀNH CÔNG (Dữ liệu y tế giải mã thành công!)${NC}"
else
    echo -e "\n${YELLOW}==> KẾT QUẢ TEST 1: KHÔNG THÀNH CÔNG (Lưu ý: Test 1 cần khóa giải mã hợp lý từ Owner để hoàn tất)${NC}"
fi

# ──── KỊCH BẢN 2: USER 2 (KHÔNG HỢP LỆ) ─────────────────────────────────────────
echo -e "\n${BLUE}----------------------------------------------------------------------${NC}"
echo -e "${RED}[SCENARIO 2] Kiểm thử User 2: KHÔNG thỏa mãn Access Policy (NURSE, HOSPITAL_B)${NC}"
echo -e "${BLUE}----------------------------------------------------------------------${NC}"
echo -e "Hệ thống sẽ nạp thuộc tính không phù hợp, mong đợi hệ thống từ chối giải mã..."

# Xóa Secret Key local tạm thời để bắt buộc cập nhật SK mới từ thuộc tính không hợp lệ
if [ -f "keys/my_secret_key.sk" ]; then
    mv keys/my_secret_key.sk keys/my_secret_key.sk.bak
fi

# Chạy app với thuộc tính không thỏa mãn
python3 user_app.py --attrs NURSE HOSPITAL_B --record 123 --offline

# Khôi phục lại key cũ
if [ -f "keys/my_secret_key.sk.bak" ]; then
    mv keys/my_secret_key.sk.bak keys/my_secret_key.sk
fi

# Mong đợi chương trình thoát với mã lỗi do CP-ABE giải mã thất bại và in ra "Decryption failed"
if [ $? -ne 0 ]; then
    echo -e "\n${GREEN}==> KẾT QUẢ TEST 2: THÀNH CÔNG (Hệ thống từ chối và in ra 'Decryption failed' đúng chuẩn!)${NC}"
else
    echo -e "\n${RED}==> KẾT QUẢ TEST 2: THẤT BẠI (User không có quyền nhưng giải mã thành công - Lỗi bảo mật!)${NC}"
fi

echo -e "\n${BLUE}======================================================================${NC}"
echo -e "${GREEN}   HOÀN THÀNH KỊCH BẢN KIỂM THỬ TỰ ĐỘNG                             ${NC}"
echo -e "${BLUE}======================================================================${NC}"
