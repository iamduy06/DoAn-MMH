"""
ta_client.py — Kết nối TA Server để lấy PK và SK
Dùng đúng protocol của TV1: JSON + length-prefixed + SSL
"""
import json
import socket
import ssl
import struct
import base64

from charm.toolbox.pairinggroup import PairingGroup
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
from charm.core.engine.util import bytesToObject

from config_owner import TA_HOST, TA_PORT

group = PairingGroup('SS512')
cpabe = CPabe_BSW07(group)

def _get_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _send_message(sock, payload: dict):
    data = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    header = struct.pack('>I', len(data))
    sock.sendall(header + data)

def _recv_message(sock) -> dict:
    raw_len = _recvall(sock, 4)
    msg_len = struct.unpack('>I', raw_len)[0]
    raw_data = _recvall(sock, msg_len)
    return json.loads(raw_data.decode('utf-8'))

def _recvall(sock, n: int) -> bytes:
    buf = b''
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError('Socket đóng sớm')
        buf += chunk
    return buf

def ping_ta() -> bool:
    """Kiểm tra TA server còn sống không"""
    try:
        ctx = _get_ssl_context()
        with socket.create_connection((TA_HOST, TA_PORT), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=None) as sock:
                _send_message(sock, {'action': 'ping', 'token': ''})
                resp = _recv_message(sock)
                return resp.get('status') == 'ok'
    except Exception as e:
        print(f'  Ping TA thất bại: {e}')
        return False

def get_public_key(id_token: str):
    """Lấy Public Key từ TA"""
    ctx = _get_ssl_context()
    with socket.create_connection((TA_HOST, TA_PORT), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=None) as sock:
            _send_message(sock, {
                'action': 'get_pk',
                'token': id_token
            })
            resp = _recv_message(sock)

    if resp.get('status') != 'ok':
        raise Exception(f"Lấy PK thất bại: {resp.get('message')}")

    pk_b64 = resp['data']['pk']
    pk_bytes = base64.b64decode(pk_b64)
    pk = bytesToObject(pk_bytes, group)
    print('  Lấy Public Key từ TA thành công!')
    return pk

def get_secret_key(id_token: str, attributes: list):
    """Lấy Secret Key từ TA theo attributes"""
    attrs_upper = [a.strip().upper() for a in attributes]
    ctx = _get_ssl_context()
    with socket.create_connection((TA_HOST, TA_PORT), timeout=10) as raw:
        with ctx.wrap_socket(raw, server_hostname=None) as sock:
            _send_message(sock, {
                'action': 'get_sk',
                'token': id_token,
                'attributes': attrs_upper
            })
            resp = _recv_message(sock)

    if resp.get('status') != 'ok':
        raise Exception(f"Lấy SK thất bại: {resp.get('message')}")

    sk_b64 = resp['data']['sk']
    sk_bytes = base64.b64decode(sk_b64)
    sk = bytesToObject(sk_bytes, group)
    print(f"  Lấy Secret Key thành công! Attributes: {attrs_upper}")
    return sk
