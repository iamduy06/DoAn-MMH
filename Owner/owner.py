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
    upload_encrypted_column,
    upload_encrypted_key,
    download_encrypted_keys,
    download_encrypted_data,
    upload_decrypted_column
)

# ========== CONFIG ==========
TA_HOST = "10.52.210.214"   # Đổi thành IP máy TV1
TA_PORT = 49999
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

# -------- Menu mã hóa --------
def menu_encrypt(pk):
    print("\n" + "="*45)
    print("          MÃ HÓA DATABASE")
    print("="*45)

    table = input("  Nhập tên bảng (vd: customers): ").strip()
    column = input("  Nhập tên cột cần mã hóa (vd: phone): ").strip()
    policy = input("  Nhập access policy (vd: MANAGER or DOCTOR): ").strip().upper()

    print(f"\n  Đang tải dữ liệu [{table}].[{column}]...")
    rows = download_encrypted_data(table, [column])
    if not rows:
        print("  Không có dữ liệu!")
        return

    # Sinh GT element, derive AES key, mã hóa GT bằng CP-ABE
    print(f"  Đang sinh key và mã hóa CP-ABE với policy: {policy}")
    ct_b64, aes_key = cpabe_encrypt_aes_key(pk, None, policy)
    print(f"  AES key (derived): {key_to_b64(aes_key)[:20]}...")

    # Mã hóa từng row bằng AES
    print(f"  Đang mã hóa {len(rows)} rows bằng AES-256-CBC...")
    for row in rows:
        row_id = row[0]
        plaintext = str(row[1]) if row[1] is not None else ""
        encrypted = encrypt_aes(plaintext.encode(), aes_key)
        upload_encrypted_column(table, column, row_id, encrypted)

    # Upload CP-ABE ciphertext lên cloud
    upload_encrypted_key(f"{table}.{column}", ct_b64, policy)

    print(f"\n  HOÀN THÀNH! Cột [{column}] đã được mã hóa.")
    print(f"  Policy: {policy}")

# -------- Menu giải mã --------
def menu_decrypt(pk):
    print("\n" + "="*45)
    print("          GIẢI MÃ / RESTORE DATABASE")
    print("="*45)

    sk_path = input("  Nhập đường dẫn file secret key: ").strip()
    if not os.path.exists(sk_path):
        print("  File không tồn tại!")
        return

    with open(sk_path, 'rb') as f:
        sk = bytesToObject(f.read(), group)

    # Tải danh sách keys từ cloud
    keys_data = download_encrypted_keys()
    if not keys_data:
        print("  Không có key nào trên cloud!")
        return

    print(f"\n  Tìm thấy {len(keys_data)} key(s):")
    for i, k in enumerate(keys_data):
        print(f"  [{i+1}] {k['column_name']} | policy: {k['policy']}")

    choice = int(input("\n  Chọn key (số thứ tự): ")) - 1
    selected = keys_data[choice]

    try:
        aes_key = cpabe_decrypt_aes_key(pk, sk, selected['cp_abe'])
        print(f"  Giải mã AES key thành công!")
    except Exception as e:
        print(f"  {e}")
        return

    # Giải mã từng row
    table, column = selected['column_name'].split('.')
    rows = download_encrypted_data(table, [column])
    print(f"  Đang giải mã {len(rows)} rows...")
    for row in rows:
        row_id = row[0]
        try:
            plaintext = decrypt_aes(str(row[1]), aes_key).decode('utf-8')
            upload_decrypted_column(table, column, row_id, plaintext)
            print(f"    Row {row_id}: OK")
        except Exception as e:
            print(f"    Row {row_id}: FAILED - {e}")

    print("\n  HOÀN THÀNH! Dữ liệu đã được restore.")

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

    # Lấy Public Key từ TA
    print("\n  Đang kết nối TA...")
    try:
        pk = get_public_key_from_ta()
    except Exception as e:
        print(f"  Không kết nối được TA: {e}")
        print("  Kiểm tra lại TA_HOST trong owner.py")
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
