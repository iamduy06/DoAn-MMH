"""
generate_offline_record.py — Kịch bản sinh dữ liệu bệnh án mã hoá offline đồng bộ với TA Server
Dự án CP-ABE EHR (Lớp NT219.P22.ANTT)
"""

import os
import sys
import json
import socket
import ssl
import struct
import base64
import hashlib

# ── Import Charm-Crypto & Cryptography ──────────────────
try:
    from charm.toolbox.pairinggroup import PairingGroup, GT
    from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
    from charm.core.engine.util import objectToBytes, bytesToObject
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    print(f"[ERROR] Thiếu thư viện: {e}")
    print("Vui lòng cài đặt: pip install charm-crypto cryptography")
    sys.exit(1)

# Nạp cấu hình từ DataUser
sys.path.append(os.path.dirname(__file__))
from config import Config

# Cấu hình Policy và Nội dung Bệnh án kiểm thử
POLICY = "((DOCTOR AND HOSPITAL_A) OR MANAGER)"
PLAINTEXT_RECORD = (
    "=== BỆNH ÁN CHI TIẾT (BẢN GỐC ĐÃ GIẢI MÃ) ===\n"
    "• ID Bệnh án: 1\n"
    "• Bệnh nhân: Nguyễn Văn A (Mã số: BN-9981)\n"
    "• Chẩn đoán: Viêm phổi cấp tính nặng (COVID-19 biến chứng)\n"
    "• Bác sĩ điều trị: Bác sĩ Nguyễn Văn B\n"
    "• Bệnh viện: Bệnh viện Đa khoa Tỉnh A (HOSPITAL_A)\n"
    "• Phác đồ điều trị: Kháng sinh thế hệ mới, hỗ trợ thở oxy dòng cao HFNC.\n"
    "• Trạng thái sức khoẻ: Đã ổn định, chuẩn bị xuất viện."
)

def encrypt_aes(plaintext: bytes, key: bytes) -> bytes:
    """Mã hoá dữ liệu bằng AES-256-CBC với IV sinh từ SHA-256 của key (đồng bộ với AESCipher)"""
    iv = hashlib.sha256(key).digest()[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 Padding
    pad_len = 16 - (len(plaintext) % 16)
    padded = plaintext + bytes([pad_len] * pad_len)
    
    return encryptor.update(padded) + encryptor.finalize()

def generate_mock():
    print("=" * 70)
    print("  KỊCH BẢN KHỞI TẠO BẢN GHI MÃ HOÁ OFFLINE (ĐỒNG BỘ 100% VỚI TA SERVER)")
    print("=" * 70)
    
    # 1. Kết nối tới TA Server đang chạy để lấy Public Key thực tế
    print(f"\n[1] Đang kết nối tới TA Server ({Config.TA_HOST}:{Config.TA_PORT}) để lấy Public Key...")
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((Config.TA_HOST, Config.TA_PORT), timeout=5) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=None) as ssock:
                # Gửi request lấy Public Key
                payload = {"action": "get_pk", "token": "dev"}
                data = json.dumps(payload).encode("utf-8")
                header = struct.pack(">I", len(data))
                ssock.sendall(header + data)
                
                # Nhận response
                raw_len = ssock.recv(4)
                if not raw_len:
                    raise ConnectionError("Server không phản hồi")
                msg_len = struct.unpack(">I", raw_len)[0]
                
                buf = b""
                while len(buf) < msg_len:
                    chunk = ssock.recv(msg_len - len(buf))
                    if not chunk:
                        break
                    buf += chunk
                
                resp = json.loads(buf.decode("utf-8"))
                if resp.get("status") != "ok":
                    raise ValueError(resp.get("message"))
                
                pk_b64 = resp["data"]["pk"]
                print("   ✓ Đã lấy Public Key từ TA Server thành công.")
    except Exception as e:
        print(f"   ❌ Lỗi kết nối TA Server để lấy PK: {e}")
        print("   Vui lòng chắc chắn rằng TA Server đang hoạt động.")
        sys.exit(1)
        
    # 2. Khởi tạo Pairing Group và nạp PK
    print("\n[2] Khởi tạo môi trường CP-ABE...")
    group = PairingGroup(Config.PAIRING_GROUP)
    cpabe = CPabe_BSW07(group)
    
    pk = bytesToObject(base64.b64decode(pk_b64), group)
    
    # 3. Mã hoá khoá AES bằng CP-ABE
    print(f"\n[3] Đang mã hoá khoá AES bằng CP-ABE với Policy: '{POLICY}'...")
    # Sinh GT element ngẫu nhiên
    gt_msg = group.random(GT)
    ct = cpabe.encrypt(pk, gt_msg, POLICY)
    
    # Derive AES Key từ GT element (đồng bộ 100% với Owner)
    gt_bytes = objectToBytes(gt_msg, group)
    aes_key = hashlib.sha256(gt_bytes).digest()
    
    # Convert CP-ABE Ciphertext về Base64
    ct_bytes = objectToBytes(ct, group)
    encrypted_aes_key_b64 = base64.b64encode(ct_bytes).decode("utf-8")
    print("   ✓ Sinh và mã hoá khoá CP-ABE thành công.")
    
    # 4. Mã hoá dữ liệu bệnh án bằng AES-256-CBC
    print("\n[4] Đang mã hoá nội dung bệnh án bằng AES-256-CBC...")
    ciphertext_bytes = encrypt_aes(PLAINTEXT_RECORD.encode("utf-8"), aes_key)
    ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode("utf-8")
    print("   ✓ Mã hoá AES-256-CBC thành công.")
    
    # 5. Lưu ra file JSON
    output_path = os.path.join(Config.DATA_DIR, "cloud_record_1.json")
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    record_data = {
        "ciphertext": ciphertext_b64,
        "encrypted_aes_key": encrypted_aes_key_b64,
        "public_key": pk_b64
    }
    
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(record_data, f, indent=4)
        
    print(f"\n🎉 HOÀN THÀNH RỰC RỠ! Đã tạo thành công bản ghi bệnh án mã hoá tại:")
    print(f"👉 {output_path}")
    print("=" * 70)

if __name__ == "__main__":
    generate_mock()
