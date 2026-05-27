import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

def generate_aes_key():
    """Sinh AES key ngẫu nhiên 32 bytes (256 bits)"""
    return os.urandom(32)

def derive_iv(key: bytes) -> bytes:
    """Tạo IV từ key bằng SHA-256, lấy 16 byte đầu"""
    return hashlib.sha256(key).digest()[:16]

def encrypt_aes(plaintext: bytes, key: bytes) -> bytes:
    """Mã hóa dữ liệu bằng AES-256-CBC"""
    iv = derive_iv(key)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Padding PKCS7
    pad_len = 16 - (len(plaintext) % 16)
    plaintext_padded = plaintext + bytes([pad_len] * pad_len)
    ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_aes(ciphertext_b64: str, key: bytes) -> bytes:
    """Giải mã dữ liệu AES-256-CBC"""
    iv = derive_iv(key)
    ciphertext = base64.b64decode(ciphertext_b64)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    # Xóa padding
    pad_len = plaintext_padded[-1]
    return plaintext_padded[:-pad_len]

def key_to_b64(key: bytes) -> str:
    """Chuyển key bytes sang base64 string để lưu trữ"""
    return base64.b64encode(key).decode('utf-8')

def b64_to_key(key_b64: str) -> bytes:
    """Chuyển base64 string về key bytes"""
    return base64.b64decode(key_b64)
