"""
cpabe_user.py — Quản lý giải mã CP-ABE cho phía Data User
Sử dụng Charm-Crypto với scheme BSW07.
"""
import base64
import logging
try:
    from charm.toolbox.pairinggroup import PairingGroup, GT
    from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
    from charm.core.engine.util import objectToBytes, bytesToObject
    CHARM_AVAILABLE = True
except ImportError:
    CHARM_AVAILABLE = False

from config import Config

logger = logging.getLogger("UserApp")

class CPABEUser:
    """Class dùng để nhận Public Key, Secret Key và tiến hành giải mã CP-ABE"""
    def __init__(self, group_name: str = Config.PAIRING_GROUP):
        if not CHARM_AVAILABLE:
            raise RuntimeError("Charm-Crypto chưa được cài đặt!")
        
        self.group = PairingGroup(group_name)
        self.cpabe = CPabe_BSW07(self.group)

    def deserialize_object(self, b64_str: str):
        """Chuyển base64 string → Charm object."""
        raw = base64.b64decode(b64_str.encode("utf-8"))
        return bytesToObject(raw, self.group)

    def decrypt(self, pk_b64: str, sk_b64: str, ct_b64: str) -> bytes:
        """
        Giải mã Ciphertext của CP-ABE để lấy ra AES Key nguyên bản.
        
        Args:
            pk_b64: Public Key dạng base64 (lấy từ TA hoặc đính kèm theo file)
            sk_b64: Secret Key dạng base64 (lấy từ TA)
            ct_b64: Encrypted AES Key dạng base64 (tải từ Azure)
            
        Returns:
            Khoá AES nguyên bản dạng bytes.
        """
        try:
            # Giải nén object
            pk = self.deserialize_object(pk_b64)
            sk = self.deserialize_object(sk_b64)
            ct = self.deserialize_object(ct_b64)
            
            # Giải mã
            logger.info("Đang thực hiện giải mã CP-ABE...")
            pt_gt = self.cpabe.decrypt(pk, sk, ct)
            
            if pt_gt is False or pt_gt is None:
                raise PermissionError("Decryption failed: Thuộc tính không thoả mãn Policy!")
                
            # Tuỳ theo cách Owner mã hoá, thông thường người ta convert GT Element về bytes.
            aes_key_bytes = objectToBytes(pt_gt, self.group)
            
            # (Hack nhỏ: nếu AES key là string base64 bọc trong objectToBytes, cần làm sạch)
            # Trong thực tế tuỳ vào cách TV2 pack AES key
            return aes_key_bytes
            
        except PermissionError as pe:
            logger.error(str(pe))
            raise pe
        except Exception as e:
            logger.error(f"Lỗi khi giải mã CP-ABE: {e}")
            raise RuntimeError("Decryption failed")
