import os
import sys
import json
import base64
import hashlib
import getpass
import socket
import ssl

from charm.toolbox.pairinggroup import PairingGroup, GT
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import objectToBytes, bytesToObject

from aes_utils import encrypt_aes, decrypt_aes, key_to_b64, b64_to_key
from firebase_utils import login
from cloud_utils import (
    upload_ehr_record,
    download_ehr_record,
    list_ehr_records
)

# ========== CONFIG ==========
TA_HOST = "10.52.210.214"   # Đổi thành IP máy TV1
TA_PORT = 9999
BUFFER_SIZE = 4096
# ============================

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

# -------- Kết nối TA --------
def get_public_key_from_ta():
    """Kết nối TA qua SSL/TLS, lấy Public Key"""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    with socket.create_connection((TA_HOST, TA_PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=TA_HOST) as ssock:
            ssock.sendall("get_pubKey".encode())
            data = b""
            while True:
                chunk = ssock.recv(BUFFER_SIZE)
                if b"__end__" in chunk:
                    data += chunk.replace(b"__end__", b"")
                    break
                data += chunk
    pk = bytesToObject(data, group)
    print("  Lấy Public Key từ TA thành công!")
    return pk

# -------- CP-ABE helpers --------
def gt_to_aes_key(gt_element) -> bytes:
    """Chuyển GT element thành AES key 32 bytes qua SHA-256"""
    gt_bytes = objectToBytes(gt_element, group)
    return hashlib.sha256(gt_bytes).digest()

def cpabe_encrypt_aes_key(pk, aes_key: bytes, policy: str) -> str:
    """
    Sinh GT element, derive AES key từ đó,
    mã hóa GT element bằng CP-ABE
    Trả về (cpabe_ciphertext_b64, aes_key_derived)
    """
    # Policy phải UPPERCASE
    policy_upper = policy.upper()
    gt_msg = group.random(GT)
    ct = cpabe.encrypt(pk, gt_msg, policy_upper)
    ct_bytes = objectToBytes(ct, group)
    ct_b64 = base64.b64encode(ct_bytes).decode('utf-8')
    derived_key = gt_to_aes_key(gt_msg)
    return ct_b64, derived_key

def cpabe_decrypt_aes_key(pk, sk, ct_b64: str):
    """Giải mã CP-ABE ciphertext để lấy lại AES key"""
    ct_bytes = base64.b64decode(ct_b64)
    ct = bytesToObject(ct_bytes, group)
    gt_msg = cpabe.decrypt(pk, sk, ct)
    if gt_msg is False:
        raise Exception("Giải mã thất bại: không đủ thuộc tính!")
    return gt_to_aes_key(gt_msg)

# -------- Menu mã hóa file EHR --------
def menu_encrypt(pk):
    print("\n" + "="*45)
    print("          MÃ HÓA HỒ SƠ EHR (FILE)")
    print("="*45)

    file_path = input("  Nhập đường dẫn file (vd: sample_ehr.json): ").strip()
    if not os.path.exists(file_path):
        print("  File không tồn tại!")
        return

    record_id = input("  Nhập Record ID (để lưu trên cloud): ").strip()
    policy = input("  Nhập access policy (vd: DOCTOR OR BREAK_GLASS): ").strip().upper()

    # Đọc nội dung file
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Sinh GT element, derive AES key, mã hóa GT bằng CP-ABE
    print(f"  Đang sinh key và mã hóa CP-ABE với policy: {policy}")
    ct_b64, aes_key = cpabe_encrypt_aes_key(pk, None, policy)
    print(f"  AES key (derived): {key_to_b64(aes_key)[:20]}...")

    # Mã hóa dữ liệu bằng AES
    print(f"  Đang mã hóa dữ liệu file bằng AES-256-CBC...")
    encrypted_data_b64 = encrypt_aes(plaintext, aes_key)

    # Upload CP-ABE ciphertext kèm Public Key lên cloud (Mock)
    pk_bytes = objectToBytes(pk, group)
    pk_b64 = base64.b64encode(pk_bytes).decode('utf-8')
    
    upload_ehr_record(record_id, encrypted_data_b64, ct_b64, policy, pk_b64)

    print(f"\n  HOÀN THÀNH! File đã được mã hóa và lưu làm record {record_id}.")
    print(f"  Policy: {policy}")

# -------- Menu giải mã (Bỏ qua - User sẽ lo phần này) --------
def menu_decrypt(pk):
    print("\n  Lưu ý: Data Owner thường không giải mã. Hãy dùng DataUser client để test giải mã EHR.")
    pass

# -------- Main --------
def main():
    print("\n" + "="*45)
    print("   ATTRIBUTE-BASED ENCRYPTION")
    print("   Data Owner Module")
    print("="*45)

    # Đăng nhập Firebase
    print("\n  Đăng nhập hệ thống:")
    email = input("  Email: ").strip()
    password = getpass.getpass("  Password: ")

    try:
        user_info = login(email, password)
    except Exception as e:
        print(f"  Lỗi đăng nhập: {e}")
        sys.exit(1)

    # Lấy Public Key từ TA qua đúng giao thức bảo mật của nhóm bằng Firebase Token
    print("\n  Đang kết nối TA...")
    try:
        from ta_client import get_public_key
        pk = get_public_key(user_info["idToken"])
    except Exception as e:
        print(f"  Không kết nối được TA: {e}")
        print("  Kiểm tra lại TA_HOST trong config_owner.py")
        sys.exit(1)

    # Menu chính
    while True:
        print("\n" + "="*45)
        print("  1. Mã hóa cột database")
        print("  2. Giải mã / Restore database")
        print("  0. Thoát")
        print("="*45)
        choice = input("  Chọn: ").strip()

        if choice == "1":
            menu_encrypt(pk)
        elif choice == "2":
            menu_decrypt(pk)
        elif choice == "0":
            print("  Tạm biệt!")
            break
        else:
            print("  Lựa chọn không hợp lệ!")

if __name__ == "__main__":
    main()
