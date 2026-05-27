#!/bin/bash
# setup.sh — Thiết lập môi trường cho Trusted Authority Server
# Đồ án CP-ABE EHR System
# ════════════════════════════════════════════════════════

set -e  # dừng ngay khi có lỗi

# ── Màu sắc ──────────────────────────────────────────────
GREEN="\033[92m"
YELLOW="\033[93m"
RED="\033[91m"
CYAN="\033[96m"
BOLD="\033[1m"
RESET="\033[0m"

ok()   { echo -e "${GREEN}✓${RESET} $1"; }
warn() { echo -e "${YELLOW}⚠${RESET}  $1"; }
err()  { echo -e "${RED}✗${RESET} $1"; exit 1; }
info() { echo -e "${CYAN}ℹ${RESET}  $1"; }

echo -e "\n${BOLD}${CYAN}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${CYAN}  Setup: Trusted Authority (TA) Module${RESET}"
echo -e "${BOLD}${CYAN}══════════════════════════════════════════════${RESET}\n"

# ════════════════════════════════════════════════════════
# 1. Kiểm tra Python
# ════════════════════════════════════════════════════════
info "Kiểm tra Python..."
PY=$(python3 --version 2>&1)
if [ $? -ne 0 ]; then
    err "Python3 chưa được cài đặt!"
fi
ok "$PY"

# ════════════════════════════════════════════════════════
# 2. Tạo và kích hoạt virtual environment
# ════════════════════════════════════════════════════════
info "Tạo virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    ok "Đã tạo venv/"
else
    warn "venv/ đã tồn tại — bỏ qua."
fi

# Kích hoạt venv
source venv/bin/activate
ok "Đã kích hoạt venv"

# ════════════════════════════════════════════════════════
# 3. Cài thư viện Python
# ════════════════════════════════════════════════════════
info "Nâng cấp pip..."
pip install --quiet --upgrade pip

info "Cài đặt cryptography và firebase-admin..."
pip install --quiet cryptography firebase-admin python-dotenv
ok "Đã cài: cryptography, firebase-admin, python-dotenv"

# ════════════════════════════════════════════════════════
# 4. Cài Charm-Crypto (nếu chưa có)
# ════════════════════════════════════════════════════════
info "Kiểm tra Charm-Crypto..."
python3 -c "from charm.toolbox.pairinggroup import PairingGroup" 2>/dev/null
if [ $? -eq 0 ]; then
    ok "Charm-Crypto đã được cài."
else
    warn "Charm-Crypto chưa có. Đang thử cài từ source..."

    # Kiểm tra dependencies hệ thống
    echo ""
    info "Cần cài thư viện hệ thống trước (yêu cầu sudo):"
    echo "    Ubuntu/Debian : sudo apt-get install -y python3-dev libssl-dev libgmp-dev libpbc-dev"
    echo "    macOS         : brew install gmp pbc openssl"
    echo ""
    warn "Nếu chưa cài, script sẽ bỏ qua Charm và bạn cần cài thủ công."

    if command -v apt-get &>/dev/null; then
        info "Phát hiện apt-get — thử cài tự động (cần sudo)..."
        sudo apt-get install -y python3-dev libssl-dev libgmp-dev flex bison libpbc-dev 2>/dev/null || \
            warn "Không thể cài tự động. Cài thủ công rồi chạy lại."
    fi

    if [ -d "/tmp/charm" ]; then
        rm -rf /tmp/charm
    fi

    git clone --quiet https://github.com/JHUISI/charm.git /tmp/charm 2>/dev/null && \
        cd /tmp/charm && pip install --quiet . && cd - > /dev/null && \
        ok "Charm-Crypto đã được cài từ source." || \
        warn "Không cài được Charm-Crypto. Xem requirements.txt để cài thủ công."
fi

# ════════════════════════════════════════════════════════
# 5. Tạo cấu trúc thư mục
# ════════════════════════════════════════════════════════
info "Tạo thư mục cần thiết..."
mkdir -p certs keys logs
ok "Đã tạo: certs/ keys/ logs/"

# ════════════════════════════════════════════════════════
# 6. Tạo SSL Certificate (ECC + SHA256)
# ════════════════════════════════════════════════════════
info "Tạo self-signed certificate (ECC SECP256R1 + SHA256)..."
python3 -c "
from ssl_utils import generate_self_signed_cert
generate_self_signed_cert()
"
if [ $? -eq 0 ]; then
    ok "Certificate đã tạo: certs/ta_cert.pem"
    ok "Private Key đã tạo: certs/ta_key.pem"
else
    warn "Không tạo được certificate ngay — sẽ tự tạo khi server khởi động."
fi

# ════════════════════════════════════════════════════════
# 7. Tạo file .env mẫu
# ════════════════════════════════════════════════════════
if [ ! -f ".env" ]; then
    info "Tạo file .env mẫu..."
    cat > .env << 'EOF'
# ── TA Server Configuration ──────────────────────────
TA_HOST=0.0.0.0
TA_PORT=9999
MAX_CONNECTIONS=10

# ── SSL/TLS ──────────────────────────────────────────
CERT_FILE=certs/ta_cert.pem
KEY_FILE=certs/ta_key.pem

# ── Firebase Auth ────────────────────────────────────
FIREBASE_CRED_PATH=firebase_credentials.json
# Đặt AUTH_ENABLED=false khi test offline
AUTH_ENABLED=false

# ── CP-ABE Keys ──────────────────────────────────────
PK_FILE=keys/public_key.pkl
MK_FILE=keys/master_key.pkl

# ── Logging ──────────────────────────────────────────
LOG_FILE=logs/ta_server.log
LOG_LEVEL=INFO
EOF
    ok "Đã tạo .env (AUTH_ENABLED=false — dev mode)"
else
    warn ".env đã tồn tại — bỏ qua."
fi

# ════════════════════════════════════════════════════════
# Hoàn tất
# ════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  Setup hoàn tất!${RESET}"
echo -e "${BOLD}${GREEN}══════════════════════════════════════════════${RESET}"
echo ""
echo -e "  Chạy server  : ${CYAN}python3 ta_server.py${RESET}"
echo -e "  Test client  : ${CYAN}python3 ta_client.py --action test${RESET}"
echo -e "  Ping server  : ${CYAN}python3 ta_client.py --action ping${RESET}"
echo -e "  Lấy PK       : ${CYAN}python3 ta_client.py --action get_pk${RESET}"
echo -e "  Lấy SK       : ${CYAN}python3 ta_client.py --action get_sk --attrs doctor hospital_a${RESET}"
echo ""
