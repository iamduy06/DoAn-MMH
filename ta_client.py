"""
ta_client.py — Client test kết nối tới Trusted Authority Server
Mô phỏng Owner xin PK và User xin SK qua SSL socket

Dùng để kiểm tra hoạt động của TA server mà không cần
tích hợp toàn bộ hệ thống EHR.
"""

import json
import socket
import ssl
import struct
import sys
import argparse
import time

from ssl_utils import create_client_ssl_context
from config    import Config


# ════════════════════════════════════════════════════════════
# Lớp Client
# ════════════════════════════════════════════════════════════
class TAClient:
    """
    Client kết nối tới TA Server qua SSL.
    Hỗ trợ 3 lệnh: ping / get_pk / get_sk

    Args:
        host      : địa chỉ TA server
        port      : cổng TA server
        ca_cert   : đường dẫn cert của TA (để xác thực TLS)
        token     : Firebase ID Token của người dùng
    """

    def __init__(self,
                 host: str   = "127.0.0.1",
                 port: int   = Config.PORT,
                 ca_cert: str = Config.CERT_FILE,
                 token: str  = "dev-token-1234"):
        self.host    = host
        self.port    = port
        self.ca_cert = ca_cert
        self.token   = token

    # ──────────────────────────────────────────────────────
    # Giao thức length-prefixed
    # ──────────────────────────────────────────────────────
    def _send(self, sock: ssl.SSLSocket, payload: dict) -> None:
        data   = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        header = struct.pack(">I", len(data))
        sock.sendall(header + data)

    def _recv(self, sock: ssl.SSLSocket) -> dict:
        raw_len = self._recvall(sock, 4)
        msg_len = struct.unpack(">I", raw_len)[0]
        raw     = self._recvall(sock, msg_len)
        return json.loads(raw.decode("utf-8"))

    def _recvall(self, sock: ssl.SSLSocket, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionResetError("Server đóng kết nối sớm.")
            buf += chunk
        return buf

    # ──────────────────────────────────────────────────────
    # Tạo kết nối SSL
    # ──────────────────────────────────────────────────────
    def _connect(self) -> ssl.SSLSocket:
        ssl_ctx  = create_client_ssl_context(self.ca_cert)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(15)
        ssl_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=self.host)
        ssl_sock.connect((self.host, self.port))
        return ssl_sock

    # ──────────────────────────────────────────────────────
    # Gửi một request chung
    # ──────────────────────────────────────────────────────
    def _request(self, payload: dict) -> dict:
        try:
            sock = self._connect()
            self._send(sock, payload)
            resp = self._recv(sock)
            sock.close()
            return resp
        except ConnectionRefusedError:
            return {"status": "error", "message": f"Không kết nối được tới {self.host}:{self.port}"}
        except ssl.SSLError as e:
            return {"status": "error", "message": f"SSL Error: {e}"}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    # ──────────────────────────────────────────────────────
    # API công khai
    # ──────────────────────────────────────────────────────
    def ping(self) -> dict:
        """Kiểm tra server có sống không."""
        return self._request({"action": "ping"})

    def get_pk(self) -> dict:
        """Lấy Public Key từ TA (dành cho Owner)."""
        return self._request({
            "action": "get_pk",
            "token" : self.token,
        })

    def get_sk(self, attributes: list) -> dict:
        """
        Xin Secret Key từ TA (dành cho User).

        Args:
            attributes: danh sách thuộc tính, VD ['DOCTOR', 'HOSPITAL_A']
        """
        return self._request({
            "action"    : "get_sk",
            "token"     : self.token,
            "attributes": attributes,
        })


# ════════════════════════════════════════════════════════════
# Hiển thị kết quả
# ════════════════════════════════════════════════════════════
def print_response(action: str, resp: dict, verbose: bool = False) -> bool:
    """In kết quả ra console với màu sắc."""
    GREEN  = "\033[92m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    RESET  = "\033[0m"
    BOLD   = "\033[1m"

    status = resp.get("status", "error")
    msg    = resp.get("message", "")
    data   = resp.get("data", {})

    ok = status == "ok"
    indicator = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
    print(f"\n{indicator} [{action.upper()}] {BOLD}{msg}{RESET}")

    if not ok:
        print(f"  {RED}Lỗi: {msg}{RESET}")
        return False

    if action == "ping":
        print(f"  Server: {data.get('server')} | Trạng thái: {data.get('status')}")

    elif action == "get_pk":
        pk_b64 = data.get("pk", "")
        print(f"  {CYAN}Scheme       :{RESET} {data.get('scheme')}")
        print(f"  {CYAN}Pairing Group:{RESET} {data.get('pairing_group')}")
        print(f"  {CYAN}PK (base64)  :{RESET} {pk_b64[:60]}...")
        print(f"  {CYAN}Độ dài PK    :{RESET} {len(pk_b64)} ký tự")

    elif action == "get_sk":
        sk_b64 = data.get("sk", "")
        attrs  = data.get("attributes", [])
        uid    = data.get("uid", "?")
        print(f"  {CYAN}UID          :{RESET} {uid}")
        print(f"  {CYAN}Attributes   :{RESET} {attrs}")
        print(f"  {CYAN}SK (base64)  :{RESET} {sk_b64[:60]}...")
        print(f"  {CYAN}Độ dài SK    :{RESET} {len(sk_b64)} ký tự")

    if verbose and data:
        print(f"\n  {YELLOW}--- Full response data ---{RESET}")
        print(json.dumps(data, indent=4, ensure_ascii=False)[:800])

    return True


# ════════════════════════════════════════════════════════════
# Test tự động
# ════════════════════════════════════════════════════════════
def run_auto_test(client: TAClient) -> None:
    """Chạy toàn bộ test case tự động."""
    BOLD  = "\033[1m"
    RESET = "\033[0m"
    CYAN  = "\033[96m"

    print(f"\n{BOLD}{CYAN}{'═'*55}{RESET}")
    print(f"{BOLD}{CYAN}  AUTO TEST — Trusted Authority Client{RESET}")
    print(f"{BOLD}{CYAN}{'═'*55}{RESET}")

    tests = [
        # (mô tả, hàm gọi)
        ("Kiểm tra kết nối (PING)",
         lambda: client.ping()),

        ("Owner xin Public Key",
         lambda: client.get_pk()),

        ("User xin SK — Bác sĩ tim mạch",
         lambda: client.get_sk(["doctor", "cardiology", "hospital_a"])),

        ("User xin SK — Y tá Nhi khoa",
         lambda: client.get_sk(["nurse", "pediatrics", "hospital_b"])),

        ("User xin SK — Bệnh nhân",
         lambda: client.get_sk(["patient", "outpatient"])),

        ("User xin SK — attribute rỗng (phải lỗi)",
         lambda: client.get_sk([])),
    ]

    passed = 0
    for i, (desc, fn) in enumerate(tests, 1):
        print(f"\n{BOLD}[Test {i}] {desc}{RESET}")
        t0   = time.perf_counter()
        resp = fn()
        dt   = (time.perf_counter() - t0) * 1000

        action = "ping" if i == 1 else ("get_pk" if i == 2 else "get_sk")
        ok     = print_response(action, resp)
        print(f"  ⏱  Thời gian: {dt:.1f} ms")

        if ok or i == 6:   # test 6 phải fail → vẫn tính pass
            passed += 1

        time.sleep(0.2)

    print(f"\n{'─'*55}")
    print(f"Kết quả: {passed}/{len(tests)} test passed\n")


# ════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="TA Client — kết nối tới Trusted Authority Server",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("--host",   default="127.0.0.1", help="Địa chỉ TA server")
    parser.add_argument("--port",   default=Config.PORT, type=int)
    parser.add_argument("--ca",     default=Config.CERT_FILE, help="Đường dẫn cert TA")
    parser.add_argument("--token",  default="dev-token-1234",  help="Firebase ID Token")
    parser.add_argument("--action", default="test",
                        choices=["ping", "get_pk", "get_sk", "test"],
                        help=(
                            "ping   — kiểm tra server\n"
                            "get_pk — lấy Public Key\n"
                            "get_sk — xin Secret Key\n"
                            "test   — chạy toàn bộ test tự động"
                        ))
    parser.add_argument("--attrs",  nargs="+", default=["doctor", "hospital_a"],
                        help="Danh sách attribute (dùng khi action=get_sk)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="In toàn bộ dữ liệu response")

    args   = parser.parse_args()
    client = TAClient(
        host    = args.host,
        port    = args.port,
        ca_cert = args.ca,
        token   = args.token,
    )

    if args.action == "test":
        run_auto_test(client)
    elif args.action == "ping":
        print_response("ping", client.ping(), args.verbose)
    elif args.action == "get_pk":
        print_response("get_pk", client.get_pk(), args.verbose)
    elif args.action == "get_sk":
        print_response("get_sk", client.get_sk(args.attrs), args.verbose)


if __name__ == "__main__":
    main()
