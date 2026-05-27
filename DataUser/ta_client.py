"""
ta_client.py — Client test kết nối tới Trusted Authority Server
"""

import json
import socket
import ssl
import struct

from ssl_utils import create_client_ssl_context
from config    import Config


class TAClient:
    def __init__(self,
                 host: str   = Config.TA_HOST,
                 port: int   = Config.TA_PORT,
                 ca_cert: str = Config.CERT_FILE,
                 token: str  = "dev-token-1234"):
        self.host    = host
        self.port    = port
        self.ca_cert = ca_cert
        self.token   = token

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

    def _connect(self) -> ssl.SSLSocket:
        ssl_ctx  = create_client_ssl_context(self.ca_cert)
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(15)
        # Đặt server_hostname=None vì check_hostname đã được tắt trong ssl_utils
        ssl_sock = ssl_ctx.wrap_socket(raw_sock, server_hostname=None)
        ssl_sock.connect((self.host, self.port))
        return ssl_sock

    def _request(self, payload: dict) -> dict:
        try:
            sock = self._connect()
            self._send(sock, payload)
            resp = self._recv(sock)
            sock.close()
            return resp
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def get_sk(self, attributes: list, token: str = None) -> dict:
        """Xin Secret Key từ TA"""
        return self._request({
            "action"    : "get_sk",
            "token"     : token if token is not None else self.token,
            "attributes": attributes,
        })

