#!/usr/bin/env python3
"""
user_app.py — Ứng dụng chính của Data User (Thành viên 3)
Chức năng:
  1. Xác thực người dùng qua Firebase Auth REST API (Online)
  2. Xin Secret Key (SK) từ TA Server sử dụng SSL/TLS
  3. Tải dữ liệu từ Azure Cloud (Hỗ trợ truy vấn SQL thật và Mock local)
  4. Giải mã khóa AES bằng CP-ABE
  5. Giải mã dữ liệu y tế bằng AES-256-CBC
  6. Xuất kết quả giải mã ra file plaintext
"""

import os
import sys
import argparse
import base64
import logging
import requests

from config import Config
from ta_client import TAClient
from azure_cloud import AzureCloud
from cpabe_user import CPABEUser
from aes_utils import AESCipher

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("UserApp")

def firebase_login(email: str, password: str) -> str:
    """Xác thực người dùng qua Firebase Auth REST API để lấy ID Token"""
    logger.info(f"=== ĐĂNG NHẬP FIREBASE AUTH ({email}) ===")
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={Config.FIREBASE_API_KEY}"
    payload = {
        "email": email,
        "password": password,
        "returnSecureToken": True
    }
    
    try:
        response = requests.post(url, json=payload, timeout=10)
        res_data = response.json()
        if response.status_code == 200:
            logger.info("✓ Xác thực Firebase Auth thành công!")
            return res_data["idToken"]
        else:
            error_msg = res_data.get("error", {}).get("message", "Lỗi không xác định")
            logger.error(f"Đăng nhập Firebase thất bại: {error_msg}")
            sys.exit(1)
    except Exception as e:
        logger.error(f"Không thể kết nối tới dịch vụ Firebase Auth: {e}")
        sys.exit(1)

def step_1_get_sk(attributes: list, token: str = None) -> str:
    """Xin Secret Key từ TA"""
    logger.info(f"=== BƯỚC 1: XIN SECRET KEY VỚI ATTRIBUTES {attributes} ===")
    
    # Kiểm tra key local trước
    if os.path.exists(Config.SK_FILE):
        logger.info(f"Đã tìm thấy Secret Key tại local ({Config.SK_FILE}). Đang nạp...")
        with open(Config.SK_FILE, "r") as f:
            return f.read().strip()
            
    logger.info("Chưa có Secret Key. Tiến hành gửi yêu cầu tới TA Server...")
    # Khởi tạo client kết nối tới TA
    client = TAClient(host=Config.TA_HOST, port=Config.TA_PORT, ca_cert=Config.CERT_FILE)
    resp = client.get_sk(attributes, token=token)
    
    if resp.get("status") == "ok":
        sk_b64 = resp["data"]["sk"]
        with open(Config.SK_FILE, "w") as f:
            f.write(sk_b64)
        logger.info("✓ Nhận và lưu Secret Key thành công.")
        return sk_b64
    else:
        logger.error(f"Lỗi xin SK từ TA Server: {resp.get('message')}")
        sys.exit(1)

def step_2_download_data(record_id: str, offline: bool = False) -> dict:
    """Tải dữ liệu từ Cloud (Azure hoặc Mock Local)"""
    logger.info(f"=== BƯỚC 2: TẢI DỮ LIỆU MÃ HOÁ TỪ CLOUD (ID={record_id}) ===")
    data = AzureCloud.download_data(record_id, offline=offline)
    if not data:
        sys.exit(1)
    return data

def step_3_and_4_decrypt(sk_b64: str, cloud_data: dict) -> bytes:
    """Giải mã CP-ABE lấy AES key, rồi giải mã AES lấy plaintext"""
    logger.info("=== BƯỚC 3 & 4: GIẢI MÃ CP-ABE & AES ===")
    
    pk_b64 = cloud_data.get("public_key")
    ct_b64 = cloud_data.get("encrypted_aes_key")
    enc_data_b64 = cloud_data.get("ciphertext")
    
    if not all([pk_b64, ct_b64, enc_data_b64]):
        logger.error("Dữ liệu tải từ Cloud không đủ các trường yêu cầu!")
        sys.exit(1)
        
    try:
        cpabe = CPABEUser()
        
        # 3. Giải mã CP-ABE
        aes_key_bytes = cpabe.decrypt(pk_b64, sk_b64, ct_b64)
        logger.info("✓ Giải mã CP-ABE thành công. Đã phục hồi khoá AES.")
        
        # 4. Giải mã AES-256
        ciphertext_bytes = base64.b64decode(enc_data_b64)
        plaintext = AESCipher.decrypt(aes_key_bytes, ciphertext_bytes)
        logger.info("✓ Giải mã AES-256-CBC thành công!")
        
        return plaintext
        
    except PermissionError:
        # Bắt buộc in ra "Decryption failed" màu đỏ theo yêu cầu đề bài
        print("\n\033[91mDecryption failed\033[0m\n")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Lỗi hệ thống trong quá trình giải mã: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Data User App - Đồ án CP-ABE EHR")
    parser.add_argument("--attrs", nargs="*", default=[], help="Danh sách attributes (tùy chọn, để trống sẽ được cấp tự động theo role)")
    parser.add_argument("--record", required=True, help="ID của bản ghi y tế cần tải")
    parser.add_argument("--email", help="Email đăng nhập Firebase Auth")
    parser.add_argument("--password", help="Mật khẩu đăng nhập Firebase Auth")
    parser.add_argument("--offline", action="store_true", help="Chạy chế độ offline (Bỏ qua Firebase, tải mock data)")
    args = parser.parse_args()
    
    # 0. Xác thực Firebase Auth nếu không chạy offline và có email/pass
    token = None
    if not args.offline and args.email and args.password:
        token = firebase_login(args.email, args.password)
    elif not args.offline and (args.email or args.password):
        logger.warning("Cần cung cấp cả email và password để xác thực Firebase Auth. Đang chạy dùng Token mặc định.")
    
    # 1. Lấy SK
    sk_b64 = step_1_get_sk(args.attrs, token=token)
    
    # 2. Tải Data (Online hoặc Offline)
    cloud_data = step_2_download_data(args.record, offline=args.offline)
    
    # 3 & 4. Giải mã CP-ABE và AES
    plaintext = step_3_and_4_decrypt(sk_b64, cloud_data)
    
    # Giải mã JSON data từ plaintext
    try:
        import json
        plaintext_str = plaintext.decode("utf-8")
        record_json = json.loads(plaintext_str)
        patient_name = record_json.get("patient_name", "N/A")
        phone = record_json.get("phone", "N/A")
        prescription = record_json.get("prescription", "N/A")
        diagnosis = record_json.get("diagnosis", "N/A")
    except Exception:
        # Nếu không phải định dạng JSON (phiên bản cũ)
        patient_name = "N/A"
        phone = "N/A"
        prescription = "N/A"
        try:
            diagnosis = plaintext.decode("utf-8")
        except:
            diagnosis = str(plaintext)

    full_report = (
        f"===========================================================\n"
        f"    THÔNG TIN BỆNH ÁN BỆNH NHÂN (ĐÃ GIẢI MÃ THÀNH CÔNG)\n"
        f"===========================================================\n"
        f"• ID Bản ghi    : {args.record}\n"
        f"• Tên bệnh nhân : {patient_name}\n"
        f"• Số điện thoại : {phone}\n"
        f"• Thuốc điều trị: {prescription}\n"
        f"• Chẩn đoán     : {diagnosis}\n"
        f"==========================================================="
    )
    
    # 5. Xuất file kết quả
    output_file = os.path.join(Config.DATA_DIR, f"decrypted_record_{args.record}.txt")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(full_report)
            
    logger.info(f"✓ Đã xuất dữ liệu y tế giải mã thành công ra file: {output_file}")
    
    print("\n" + full_report + "\n")

if __name__ == "__main__":
    main()

