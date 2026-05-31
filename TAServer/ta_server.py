"""
ta_server.py — Trusted Authority Server (CP-ABE EHR)
=====================================================
Server lắng nghe kết nối SSL từ Owner và User.
Xử lý 3 loại request:
  • get_pk  → trả Public Key (PK) cho bất kỳ ai
  • get_sk  → xác thực User → sinh Secret Key theo attributes
  • ping    → kiểm tra kết nối server

Giao thức: JSON qua SSL socket, length-prefixed (4 bytes big-endian)

Cấu trúc message từ client:
  {
    "action"    : "get_pk" | "get_sk" | "ping",
    "token"     : "<Firebase ID Token>",
    "attributes": ["DOCTOR", "HOSPITAL_A", ...]   // chỉ dùng cho get_sk
  }

Cấu trúc response từ server:
  {
    "status" : "ok" | "error",
    "data"   : { ... },
    "message": "mô tả"
  }
"""

import json
import socket
import ssl
import struct
import threading
import logging
import sys
import os
import signal

from config       import Config
from ta_logger    import setup_logger, log_session
from ssl_utils    import create_ssl_context
from cpabe_manager import CPABEManager
from firebase_auth import FirebaseAuthenticator

# ─── Khởi tạo logger ────────────────────────────────────
logger = setup_logger("TA_Server", Config.LOG_FILE, Config.LOG_LEVEL)


# ═══════════════════════════════════════════════════════════
# Lớp xử lý từng kết nối client
# ═══════════════════════════════════════════════════════════
class ClientHandler(threading.Thread):
    """
    Mỗi kết nối client được xử lý trong một thread riêng.
    Kế thừa threading.Thread để dễ quản lý.
    """

    def __init__(self,
                 conn: ssl.SSLSocket,
                 addr: tuple,
                 cpabe: CPABEManager,
                 auth: FirebaseAuthenticator):
        super().__init__(daemon=True)
        self.conn  = conn
        self.addr  = addr
        self.cpabe = cpabe
        self.auth  = auth

    # ──────────────────────────────────────────────────────
    # Giao thức: Length-prefixed message (4 bytes + data)
    # ──────────────────────────────────────────────────────
    def _recv_message(self) -> dict:
        """Nhận message: đọc 4 byte header → độ dài → đọc data."""
        raw_len = self._recvall(4)
        if not raw_len:
            raise ConnectionResetError("Client ngắt kết nối bất ngờ.")
        msg_len = struct.unpack(">I", raw_len)[0]

        if msg_len > 10 * 1024 * 1024:   # giới hạn 10 MB
            raise ValueError(f"Message quá lớn: {msg_len} bytes")

        raw_data = self._recvall(msg_len)
        return json.loads(raw_data.decode("utf-8"))

    def _send_message(self, payload: dict) -> None:
        """Gửi message: serialize JSON → 4 byte header → data."""
        data    = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        header  = struct.pack(">I", len(data))
        self.conn.sendall(header + data)

    def _recvall(self, n: int) -> bytes:
        """Đọc đúng n bytes từ socket."""
        buf = b""
        while len(buf) < n:
            chunk = self.conn.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf

    # ──────────────────────────────────────────────────────
    # Thread entry point
    # ──────────────────────────────────────────────────────
    def run(self):
        log_session(logger, "CONNECT", self.addr,
                    action="—", detail="Kết nối mới", success=True)
        try:
            self.conn.settimeout(Config.TIMEOUT)
            request = self._recv_message()
            self._route(request)
        except json.JSONDecodeError:
            self._send_error("Request không đúng định dạng JSON.")
        except ConnectionResetError as e:
            logger.warning(f"[{self.addr}] Kết nối bị ngắt: {e}")
        except socket.timeout:
            logger.warning(f"[{self.addr}] Timeout sau {Config.TIMEOUT}s.")
        except Exception as e:
            logger.error(f"[{self.addr}] Lỗi không xác định: {e}", exc_info=True)
            self._send_error(f"Lỗi server nội bộ: {e}")
        finally:
            self.conn.close()
            log_session(logger, "DISCONNECT", self.addr,
                        action="—", detail="Đã đóng kết nối", success=True)

    # ──────────────────────────────────────────────────────
    # Router — phân luồng theo action
    # ──────────────────────────────────────────────────────
    def _route(self, request: dict):
        action = request.get("action", "").lower()
        token  = request.get("token", "")

        if action == "ping":
            self._handle_ping()
            return

        # Xác thực Firebase token cho mọi action khác
        user_info = self.auth.verify_token(token)
        if user_info is None:
            log_session(logger, "AUTH_FAIL", self.addr,
                        action=action, detail="Token không hợp lệ", success=False)
            self._send_error("Xác thực thất bại — token không hợp lệ.")
            return

        uid = user_info["uid"]

        if action == "get_pk":
            self._handle_get_pk(uid, user_info)
        elif action == "get_sk":
            attrs = request.get("attributes", [])
            self._handle_get_sk(uid, user_info, attrs)
        else:
            self._send_error(f"Action không hợp lệ: '{action}'")

    # ──────────────────────────────────────────────────────
    # Handler: ping
    # ──────────────────────────────────────────────────────
    def _handle_ping(self):
        self._send_ok({"server": "TA_CP_ABE", "status": "alive"}, "pong")
        logger.debug(f"[{self.addr}] PING → PONG")

    # ──────────────────────────────────────────────────────
    # Handler: get_pk — cấp Public Key cho Owner/User
    # ──────────────────────────────────────────────────────
    def _handle_get_pk(self, uid: str, user_info: dict):
        """
        Trả về Public Key (PK) serialize dạng base64.
        Không yêu cầu role cụ thể — ai cũng lấy được PK.
        """
        try:
            pk_b64 = self.cpabe.serialize_pk()
            self._send_ok({
                "pk"           : pk_b64,
                "pairing_group": Config.PAIRING_GROUP,
                "scheme"       : "CP-ABE BSW07",
            }, "Lấy PK thành công")

            log_session(logger, "GET_PK", self.addr, uid=uid,
                        action="get_pk",
                        detail=f"role={user_info.get('role', '?')}",
                        success=True)
        except Exception as e:
            logger.error(f"[GET_PK] Lỗi: {e}")
            log_session(logger, "GET_PK", self.addr, uid=uid,
                        action="get_pk", detail=str(e), success=False)
            self._send_error(f"Không thể lấy PK: {e}")

    # ──────────────────────────────────────────────────────
    # Handler: get_sk — sinh Secret Key theo attributes
    # ──────────────────────────────────────────────────────
    def _handle_get_sk(self, uid: str, user_info: dict, attributes: list):
        """
        Nhận attribute list từ user → sinh SK tương ứng → trả về.

        Chỉ user có role 'user' hoặc 'patient' mới được phép.
        """
        # Kiểm tra quyền (Owner không được lấy SK của người khác)
        role = user_info.get("role", "").lower()
        if role not in ("user", "patient", "doctor", "admin", "developer"):
            log_session(logger, "GET_SK", self.addr, uid=uid,
                        action="get_sk",
                        detail=f"Từ chối — role={role}",
                        success=False)
            self._send_error(f"Role '{role}' không được phép lấy SK.")
            return

        if not attributes:
            self._send_error("Danh sách attributes không được rỗng.")
            return

        clean = [a.strip().upper() for a in attributes]

        # ─── Xử lý Break-Glass ───
        is_break_glass = False
        if "BREAK_GLASS" in clean:
            if role != "doctor" and role != "admin":
                self._send_error("Chỉ DOCTOR mới được phép sử dụng quyền BREAK_GLASS.")
                return
            is_break_glass = True

        # ─── Xử lý Revocation (Time-based Attributes / TTL) ───
        # Automatically append a time attribute if the system requires short TTL
        from datetime import datetime, timedelta
        # Ví dụ cấp cho thuộc tính ngày hôm nay
        today_attr = f"DATE:{datetime.utcnow().strftime('%Y-%m-%d')}"
        if today_attr not in clean:
            clean.append(today_attr)
        
        # Nếu user yêu cầu một attribute EXP (Expiration) cụ thể
        for attr in clean:
            if attr.startswith("EXP:"):
                # Có thể thêm logic parse ngày và giới hạn tối đa 30 ngày TTL
                pass

        try:
            sk      = self.cpabe.keygen(clean)
            sk_b64  = self.cpabe.serialize_key(sk)

            self._send_ok({
                "sk"        : sk_b64,
                "attributes": clean,
                "uid"       : uid,
            }, f"Sinh SK thành công cho {len(clean)} attributes")

            detail_msg = f"attrs={clean}"
            if is_break_glass:
                detail_msg = f"BREAK_GLASS ACTIVATED | {detail_msg}"

            log_session(logger, "GET_SK", self.addr, uid=uid,
                        action="get_sk",
                        detail=detail_msg,
                        success=True)

        except ValueError as e:
            self._send_error(str(e))
        except Exception as e:
            logger.error(f"[GET_SK] Lỗi sinh SK: {e}", exc_info=True)
            log_session(logger, "GET_SK", self.addr, uid=uid,
                        action="get_sk", detail=str(e), success=False)
            self._send_error(f"Không thể sinh SK: {e}")

    # ──────────────────────────────────────────────────────
    # Tiện ích gửi response
    # ──────────────────────────────────────────────────────
    def _send_ok(self, data: dict, message: str = "OK"):
        self._send_message({"status": "ok", "data": data, "message": message})

    def _send_error(self, message: str):
        try:
            self._send_message({"status": "error", "data": {}, "message": message})
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
# Trusted Authority Server
# ═══════════════════════════════════════════════════════════
class TrustedAuthorityServer:
    """
    Server chính của Trusted Authority.
    Lắng nghe kết nối SSL, spawn thread cho mỗi client.
    """

    def __init__(self):
        self.host     = Config.HOST
        self.port     = Config.PORT
        self.running  = False
        self.sock     = None
        self.ssl_ctx  = None
        self.cpabe    = None
        self.auth     = None

    # ──────────────────────────────────────────────────────
    # Khởi tạo
    # ──────────────────────────────────────────────────────
    def initialize(self) -> None:
        """Khởi tạo toàn bộ hệ thống: CP-ABE, SSL, Auth."""
        logger.info("=" * 60)
        logger.info("  Trusted Authority Server — CP-ABE EHR")
        logger.info("=" * 60)

        # 1. Khởi tạo CP-ABE
        logger.info("[1/3] Khởi tạo CP-ABE ...")
        self.cpabe = CPABEManager()
        self.cpabe.setup()
        info = self.cpabe.info()
        logger.info(f"      Scheme       : {info['scheme']}")
        logger.info(f"      Pairing Group: {info['pairing_group']}")
        logger.info(f"      PK File      : {info['pk_file']}")

        # 2. Tạo SSL Context
        logger.info("[2/3] Cấu hình SSL/TLS (ECC + SHA256) ...")
        self.ssl_ctx = create_ssl_context(
            cert_path=Config.CERT_FILE,
            key_path=Config.KEY_FILE,
            auto_generate=True,
        )
        logger.info(f"      Cert: {Config.CERT_FILE}")

        # 3. Khởi tạo Firebase Auth
        logger.info("[3/3] Khởi tạo Firebase Authentication ...")
        self.auth = FirebaseAuthenticator(
            cred_path=Config.FIREBASE_CRED_PATH,
            auth_enabled=Config.AUTH_ENABLED,
        )
        mode = "BẬT" if Config.AUTH_ENABLED else "TẮT (dev mode)"
        logger.info(f"      Auth: {mode}")

        logger.info("=" * 60)
        logger.info(f"  Server sẵn sàng: {self.host}:{self.port}")
        logger.info("=" * 60)

    # ──────────────────────────────────────────────────────
    # Chạy server
    # ──────────────────────────────────────────────────────
    def start(self) -> None:
        """Bắt đầu lắng nghe kết nối."""
        self.initialize()

        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        raw_sock.bind((self.host, self.port))
        raw_sock.listen(Config.MAX_CONNECTIONS)

        self.sock    = self.ssl_ctx.wrap_socket(raw_sock, server_side=True)
        self.running = True

        # Xử lý tín hiệu dừng (Ctrl+C, kill)
        signal.signal(signal.SIGINT,  self._shutdown_handler)
        signal.signal(signal.SIGTERM, self._shutdown_handler)

        logger.info(f"Đang lắng nghe tại {self.host}:{self.port} (SSL) ...")

        try:
            while self.running:
                try:
                    conn, addr = self.sock.accept()
                    logger.debug(f"Kết nối mới từ {addr[0]}:{addr[1]}")

                    handler = ClientHandler(conn, addr, self.cpabe, self.auth)
                    handler.start()

                except ssl.SSLError as e:
                    logger.warning(f"SSL handshake thất bại: {e}")
                except OSError:
                    # Socket đã đóng khi shutdown
                    break

        finally:
            self._cleanup()

    # ──────────────────────────────────────────────────────
    # Dọn dẹp
    # ──────────────────────────────────────────────────────
    def _shutdown_handler(self, signum, frame):
        logger.info(f"\n[SHUTDOWN] Nhận tín hiệu {signum} — đang dừng server ...")
        self.running = False
        if self.sock:
            self.sock.close()

    def _cleanup(self):
        logger.info("[SHUTDOWN] Server đã dừng. Tạm biệt!")


# ═══════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    server = TrustedAuthorityServer()
    server.start()
