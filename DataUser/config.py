import os

class Config:
    # ── Mạng và TA Server ──────────────────────────────────
    TA_HOST = "10.52.210.214"    # Nên đổi sang IP Tailscale của TA (vd: 100.94.1.10)
    TA_PORT = 9999
    CERT_FILE = os.path.join(os.path.dirname(__file__), "certs", "ta_cert.pem")

    # ── Firebase Authentication ──────────────────────────
    # Lấy Web API Key từ Firebase Console (Project Settings -> General)
    FIREBASE_API_KEY = os.getenv("FIREBASE_API_KEY", "AIzaSyBWaGOg5a00zBaNSTb3YYmSDxdX8A3QirE")


    # ── Azure SQL Database ──────────────────────────────
    AZURE_SERVER = os.getenv("AZURE_SERVER", "cpabe-ehr-server.database.windows.net")
    AZURE_DB = os.getenv("AZURE_DB", "cpabe-ehr-db")
    AZURE_UID = os.getenv("AZURE_UID", "cpabeadmin")
    AZURE_PWD = os.getenv("AZURE_PWD", "linhquang206!")
    AZURE_DRIVER = os.getenv("AZURE_DRIVER", "{ODBC Driver 18 for SQL Server}")



    # ── Cấu hình CP-ABE ──────────────────────────────────
    PAIRING_GROUP = "SS512"

    # ── Thư mục lưu trữ nội bộ ───────────────────────────
    KEYS_DIR = os.path.join(os.path.dirname(__file__), "keys")
    DATA_DIR = os.path.join(os.path.dirname(__file__), "data")

    # Đảm bảo các thư mục tồn tại
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(os.path.dirname(CERT_FILE), exist_ok=True)

    # ── Tên file lưu Secret Key ──────────────────────────
    SK_FILE = os.path.join(KEYS_DIR, "my_secret_key.sk")
