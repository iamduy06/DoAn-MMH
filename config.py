"""
config.py — Cấu hình toàn cục cho Trusted Authority Server
"""
import os

class Config:
    # ──────────────────────────────────────────
    # Cài đặt Socket Server
    # ──────────────────────────────────────────
    HOST = os.getenv("TA_HOST", "0.0.0.0")
    PORT = int(os.getenv("TA_PORT", 9999))
    MAX_CONNECTIONS = int(os.getenv("MAX_CONNECTIONS", 10))
    BUFFER_SIZE = 65536          # 64 KB mỗi chunk
    TIMEOUT = 30                 # giây

    # ──────────────────────────────────────────
    # SSL/TLS (ECC + SHA256)
    # ──────────────────────────────────────────
    CERT_FILE = os.getenv("CERT_FILE", "certs/ta_cert.pem")
    KEY_FILE  = os.getenv("KEY_FILE",  "certs/ta_key.pem")
    CERT_COMMON_NAME  = "TA_CP_ABE_Server"
    CERT_ORG          = "CP-ABE EHR System"
    CERT_VALID_DAYS   = 365

    # ──────────────────────────────────────────
    # Firebase Authentication
    # ──────────────────────────────────────────
    FIREBASE_CRED_PATH = os.getenv("FIREBASE_CRED_PATH", "firebase_credentials.json")
    # Bật False khi chạy thử offline (không cần Firebase)
    AUTH_ENABLED = os.getenv("AUTH_ENABLED", "true").lower() == "true"

    # ──────────────────────────────────────────
    # CP-ABE Key Files
    # ──────────────────────────────────────────
    PK_FILE = os.getenv("PK_FILE", "keys/public_key.pkl")
    MK_FILE = os.getenv("MK_FILE", "keys/master_key.pkl")

    # ──────────────────────────────────────────
    # Logging
    # ──────────────────────────────────────────
    LOG_FILE  = os.getenv("LOG_FILE",  "logs/ta_server.log")
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

    # ──────────────────────────────────────────
    # Pairing group cho Charm-Crypto
    # ──────────────────────────────────────────
    PAIRING_GROUP = "BN254"
