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
    key_path:  str = Config.KEY_FILE,
    common_name: str = Config.CERT_COMMON_NAME,
    org_name: str    = Config.CERT_ORG,
    valid_days: int  = Config.CERT_VALID_DAYS,
) -> None:
    """
    Sinh ECC private key (SECP256R1) và self-signed certificate (SHA256).
    Lưu vào file PEM.

    Args:
        cert_path  : đường dẫn file certificate (.pem)
        key_path   : đường dẫn file private key  (.pem)
        common_name: CN cho certificate
        org_name   : Organization name
        valid_days : số ngày certificate có hiệu lực
    """
    if not CRYPTO_AVAILABLE:
        raise ImportError(
            "Thư viện 'cryptography' chưa được cài. "
            "Chạy: pip install cryptography"
        )

    os.makedirs(os.path.dirname(cert_path), exist_ok=True)
    os.makedirs(os.path.dirname(key_path),  exist_ok=True)

    # ── 1. Sinh ECC private key (SECP256R1 / P-256) ──
    private_key = ec.generate_private_key(
        curve=ec.SECP256R1(),
        backend=default_backend()
    )

    # ── 2. Xây dựng thông tin Subject / Issuer ──
    name_attrs = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,         common_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,   org_name),
        x509.NameAttribute(NameOID.COUNTRY_NAME,        "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Ho Chi Minh"),
    ])

    now = datetime.datetime.utcnow()

    # ── 3. Build certificate ──
    cert = (
        x509.CertificateBuilder()
        .subject_name(name_attrs)
        .issuer_name(name_attrs)                        # self-signed → subject = issuer
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=valid_days))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName(common_name),
            ]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )

    # ── 4. Ghi certificate PEM ──
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    # ── 5. Ghi private key PEM (không mã hóa passphrase) ──
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print(f"[SSL] Certificate tạo thành công:")
    print(f"      Cert : {cert_path}")
    print(f"      Key  : {key_path}")
    print(f"      Algo : ECC SECP256R1 + SHA256")
    print(f"      Valid: {valid_days} ngày")


# ──────────────────────────────────────────────────────────
# Tạo SSL Context cho server
# ──────────────────────────────────────────────────────────
def create_ssl_context(
    cert_path: str = Config.CERT_FILE,
    key_path:  str = Config.KEY_FILE,
    auto_generate: bool = True,
) -> ssl.SSLContext:
    """
    Tạo ssl.SSLContext cho server với TLS 1.2+.

    Args:
        cert_path     : đường dẫn certificate
        key_path      : đường dẫn private key
        auto_generate : nếu True, tự tạo cert nếu chưa có

    Returns:
        ssl.SSLContext đã cấu hình
    """
    if auto_generate and (
        not os.path.exists(cert_path) or not os.path.exists(key_path)
    ):
        print("[SSL] Chưa có certificate, đang tạo self-signed cert ...")
        generate_self_signed_cert(cert_path, key_path)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

    # Chỉ cho phép TLS 1.2 trở lên
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    # Tắt các cipher yếu
    ctx.set_ciphers(
        "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!RC4"
    )

    ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)

    # Không yêu cầu client certificate (one-way TLS)
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


# ──────────────────────────────────────────────────────────
# Tạo SSL Context cho client (kết nối tới TA)
# ──────────────────────────────────────────────────────────
def create_client_ssl_context(
    ca_cert_path: str = Config.CERT_FILE,
) -> ssl.SSLContext:
    """
    SSL context phía client — dùng cert của TA làm CA để xác thực.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=ca_cert_path)
    ctx.check_hostname = False  # self-signed không có hostname hợp lệ
    ctx.verify_mode    = ssl.CERT_REQUIRED
    return ctx
