"""
ssl_utils.py — Tạo và nạp chứng chỉ SSL/TLS tự ký
Sử dụng: ECC (SECP256R1 = P-256) + SHA256
"""
import ssl
import os
import datetime
from config import Config

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ──────────────────────────────────────────────────────────
# Tạo self-signed certificate bằng ECC + SHA256
# ──────────────────────────────────────────────────────────
def generate_self_signed_cert(
    cert_path: str = Config.CERT_FILE,
    key_path:  str = "", # Không cần cho User
    common_name: str = "TA_SERVER",
    org_name: str    = "EHR",
    valid_days: int  = 365,
) -> None:
    pass

# ──────────────────────────────────────────────────────────
# Tạo SSL Context cho server
# ──────────────────────────────────────────────────────────
def create_ssl_context(
    cert_path: str = Config.CERT_FILE,
    key_path:  str = "",
    auto_generate: bool = True,
) -> ssl.SSLContext:
    pass

# ──────────────────────────────────────────────────────────
# Tạo SSL Context cho client (kết nối tới TA)
# ──────────────────────────────────────────────────────────
def create_client_ssl_context(
    ca_cert_path: str = Config.CERT_FILE,
) -> ssl.SSLContext:
    """
    SSL context phía client — dùng cert của TA làm CA để xác thực.
    Bắt buộc verify_mode = CERT_REQUIRED để đảm bảo an toàn,
    nhưng tắt check_hostname để hỗ trợ các kết nối qua IP ảo ZeroTier.
    """
    if not os.path.exists(ca_cert_path):
        raise FileNotFoundError(
            f"Không tìm thấy chứng chỉ SSL '{ca_cert_path}'."
        )
        
    # Sử dụng PROTOCOL_TLS để cho phép tắt check_hostname dưới chế độ CERT_REQUIRED của Python
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca_cert_path)
    ctx.check_hostname = False  # Bỏ qua đối chiếu IP hostname
    ctx.verify_mode    = ssl.CERT_REQUIRED  # Bắt buộc xác thực chứng chỉ thật
    return ctx

