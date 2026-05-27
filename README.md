# 🔐 Trusted Authority (TA) — CP-ABE EHR System

Module của **Thành viên 1**: triển khai Trusted Authority Server cho hệ thống
chia sẻ hồ sơ y tế điện tử (EHR) bảo mật bằng CP-ABE.

---

## 📁 Cấu trúc thư mục

```
ta_module/
├── ta_server.py        ← Server chính (entry point)
├── ta_client.py        ← Client test & demo
├── cpabe_manager.py    ← Quản lý CP-ABE (setup, keygen, serialize)
├── firebase_auth.py    ← Xác thực Firebase ID Token
├── ssl_utils.py        ← Tạo & nạp SSL/TLS (ECC + SHA256)
├── ta_logger.py        ← Hệ thống ghi log có màu
├── config.py           ← Cấu hình toàn cục
├── setup.sh            ← Script thiết lập môi trường
├── requirements.txt    ← Danh sách thư viện
├── certs/
│   ├── ta_cert.pem     ← Self-signed certificate (ECC)
│   └── ta_key.pem      ← Private key
├── keys/
│   ├── public_key.pkl  ← CP-ABE Public Key
│   └── master_key.pkl  ← CP-ABE Master Key (BÍ MẬT)
└── logs/
    └── ta_server.log   ← Log phiên hoạt động
```

---

## 🔄 Luồng hoạt động

```
Owner                 TA Server                  User
  │                       │                        │
  │──── get_pk ──────────►│                        │
  │     (token)           │── verify Firebase ─►  │
  │◄─── PK (base64) ──────│                        │
  │                       │                        │
  │                       │◄────── get_sk ─────────│
  │                       │       (token, attrs)   │
  │                       │── verify Firebase      │
  │                       │── keygen(pk, mk, attrs)│
  │                       │────── SK (base64) ─────►
```

---

## ⚡ Cài đặt nhanh

```bash
# 1. Clone / vào thư mục TA
cd ta_module

# 2. Chạy script setup tự động
bash setup.sh

# 3. Chạy server
source venv/bin/activate
python3 ta_server.py

# 4. Test (terminal khác)
python3 ta_client.py --action test
```

---

## 🔧 Cài đặt Charm-Crypto (thủ công)

Charm-Crypto cần build từ source:

```bash
# Ubuntu/Debian — cài dependencies
sudo apt-get install -y \
    python3-dev libssl-dev libgmp-dev \
    flex bison libpbc-dev

# Clone và cài
git clone https://github.com/JHUISI/charm.git
cd charm && pip install . && cd ..

# Kiểm tra
python3 -c "from charm.toolbox.pairinggroup import PairingGroup; print('Charm OK')"
```

### Docker (khuyến nghị khi gặp khó khăn build)
```bash
docker pull jhuisi/charm
docker run -it -p 9999:9999 -v $(pwd):/app jhuisi/charm bash
cd /app && python3 ta_server.py
```

---

## 📡 Giao thức Socket

**Định dạng:** JSON qua SSL, length-prefixed (4 bytes big-endian + data)

### Request từ Client

| Field        | Type     | Bắt buộc | Mô tả                           |
|:-------------|:---------|:----------|:--------------------------------|
| `action`     | string   | ✓         | `ping` / `get_pk` / `get_sk`   |
| `token`      | string   | ✓*        | Firebase ID Token               |
| `attributes` | string[] | chỉ get_sk | Danh sách thuộc tính           |

> *Không cần cho `ping`

### Response từ Server

```json
{
  "status" : "ok" | "error",
  "data"   : { ... },
  "message": "mô tả kết quả"
}
```

### Ví dụ: Lấy PK
```json
// Request
{ "action": "get_pk", "token": "<firebase_id_token>" }

// Response
{
  "status": "ok",
  "data": {
    "pk": "<base64_encoded_pk>",
    "pairing_group": "SS512",
    "scheme": "CP-ABE BSW07"
  },
  "message": "Lấy PK thành công"
}
```

### Ví dụ: Lấy SK
```json
// Request
{
  "action"    : "get_sk",
  "token"     : "<firebase_id_token>",
  "attributes": ["DOCTOR", "CARDIOLOGY", "HOSPITAL_A"]
}

// Response
{
  "status": "ok",
  "data": {
    "sk"        : "<base64_encoded_sk>",
    "attributes": ["DOCTOR", "CARDIOLOGY", "HOSPITAL_A"],
    "uid"       : "user_firebase_uid"
  },
  "message": "Sinh SK thành công cho 3 attributes"
}
```

---

## 🔐 Bảo mật SSL/TLS

- **Thuật toán:** ECC SECP256R1 (P-256) + SHA-256
- **Phiên bản TLS:** 1.2 tối thiểu (TLS 1.3 nếu hỗ trợ)
- **Cipher suites:** ECDHE+AESGCM, ECDHE+CHACHA20 (loại bỏ RC4, MD5)
- **Certificate:** Self-signed, 365 ngày, tự tạo khi khởi động nếu chưa có
- **Xác thực:** One-way TLS (server auth) — client không cần cert

---

## 🔥 Firebase Authentication

1. Vào [Firebase Console](https://console.firebase.google.com)
2. **Project Settings → Service Accounts → Generate new private key**
3. Lưu file JSON vào `firebase_credentials.json`
4. Đặt `AUTH_ENABLED=true` trong `.env`

**Chạy offline (không Firebase):**
```bash
# Trong .env
AUTH_ENABLED=false
```
Server sẽ chấp nhận mọi token và trả về user giả định.

---

## 📋 Biến môi trường (.env)

| Biến                 | Mặc định                   | Mô tả                        |
|:---------------------|:---------------------------|:-----------------------------|
| `TA_HOST`            | `0.0.0.0`                 | Địa chỉ bind                 |
| `TA_PORT`            | `9999`                    | Cổng lắng nghe               |
| `CERT_FILE`          | `certs/ta_cert.pem`       | Đường dẫn certificate        |
| `KEY_FILE`           | `certs/ta_key.pem`        | Đường dẫn private key        |
| `FIREBASE_CRED_PATH` | `firebase_credentials.json`| Credentials Firebase         |
| `AUTH_ENABLED`       | `true`                    | Bật/tắt xác thực Firebase    |
| `PK_FILE`            | `keys/public_key.pkl`     | Lưu Public Key               |
| `MK_FILE`            | `keys/master_key.pkl`     | Lưu Master Key               |
| `LOG_FILE`           | `logs/ta_server.log`      | File log                     |
| `LOG_LEVEL`          | `INFO`                    | Mức log (DEBUG/INFO/WARNING) |

---

## 🧪 Sử dụng Client Test

```bash
# Chạy toàn bộ test tự động
python3 ta_client.py --action test

# Ping server
python3 ta_client.py --action ping

# Lấy Public Key
python3 ta_client.py --action get_pk --token "my_firebase_token"

# Lấy Secret Key
python3 ta_client.py --action get_sk \
    --token "my_firebase_token" \
    --attrs doctor cardiology hospital_a

# Server khác
python3 ta_client.py --host 192.168.1.10 --port 9999 --action ping

# Xem đầy đủ response
python3 ta_client.py --action get_pk --verbose
```

---

## 📊 Log mẫu

```
2024-01-15 10:23:41 | INFO     | TA_Server | [CONNECT ] 127.0.0.1:54321 | uid=unknown | action=— | Kết nối mới | OK
2024-01-15 10:23:41 | INFO     | TA_Server | [AUTH    ] 127.0.0.1:54321 | uid=doctor_001 | action=get_sk | role=doctor | OK
2024-01-15 10:23:42 | INFO     | TA_Server | [GET_SK  ] 127.0.0.1:54321 | uid=doctor_001 | action=get_sk | attrs=['DOCTOR','HOSPITAL_A'] | OK
2024-01-15 10:23:42 | INFO     | TA_Server | [DISCONNECT] 127.0.0.1:54321 | uid=unknown | action=— | Đã đóng kết nối | OK
```

---

## 🔗 Tích hợp với các module khác

### Module Owner nhận PK
```python
from ta_client import TAClient

client = TAClient(host="ta_server_ip", token=firebase_token)
resp   = client.get_pk()
if resp["status"] == "ok":
    pk_b64 = resp["data"]["pk"]   # truyền cho Owner để encrypt
```

### Module User nhận SK
```python
resp = client.get_sk(attributes=["doctor", "hospital_a"])
if resp["status"] == "ok":
    sk_b64 = resp["data"]["sk"]   # dùng để decrypt bản mã CP-ABE
```

---

## 📚 Tài liệu tham khảo

- Bethencourt, Sahai, Waters — *Ciphertext-Policy Attribute-Based Encryption* (IEEE S&P 2007)
- [Charm-Crypto GitHub](https://github.com/JHUISI/charm)
- [Firebase Admin SDK Python](https://firebase.google.com/docs/admin/setup)
- RFC 8422 — ECC trong TLS
