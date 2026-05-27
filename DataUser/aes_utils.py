import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class AESCipher:
    """
    Tiện ích giải mã dữ liệu y tế bằng AES-256-CBC.
    Sử dụng 16 byte đầu của mã băm SHA-256 của khoá làm IV.
    """
    
    @staticmethod
    def _get_iv(key_bytes: bytes) -> bytes:
        """Sinh IV (16 bytes) từ SHA-256 của AES key."""
        return hashlib.sha256(key_bytes).digest()[:16]

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes) -> bytes:
        """
        Giải mã AES-256-CBC.
        
        Args:
            key (bytes): Khoá AES-256 (32 bytes).
            ciphertext (bytes): Dữ liệu đã mã hoá.
            
        Returns:
            bytes: Dữ liệu gốc (plaintext).
        """
        iv = AESCipher._get_iv(key)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Bỏ padding (PKCS7)
        pad_len = padded_plaintext[-1]
        return padded_plaintext[:-pad_len]
