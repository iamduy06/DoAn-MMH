"""
cpabe_manager.py — Quản lý CP-ABE với Charm-Crypto
Scheme: Bethencourt-Sahai-Waters 2007 (abenc_bsw07)

Chức năng:
  - setup()   : khởi tạo Public Key (PK) + Master Key (MK)
  - keygen()  : sinh Secret Key (SK) cho một user theo attribute list
  - serialize / deserialize PK, MK, SK
  - lưu/nạp key từ file
"""
import os
import pickle
import base64
import logging

from config import Config

logger = logging.getLogger("TA_Server")

# ── Import Charm-Crypto ──────────────────────────────────
try:
    from charm.toolbox.pairinggroup import PairingGroup, GT
    from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
    from charm.core.engine.util import objectToBytes, bytesToObject
    CHARM_AVAILABLE = True
except ImportError:
    CHARM_AVAILABLE = False
    logger.critical(
        "Charm-Crypto chưa được cài đặt!\n"
        "Cài đặt: pip install charm-crypto\n"
        "Hoặc xem: https://github.com/JHUISI/charm"
    )


class CPABEManager:
    """
    Quản lý vòng đời khoá CP-ABE của Trusted Authority.

    Attributes:
        group (PairingGroup): nhóm pairing dùng trong toàn hệ thống
        cpabe (CPabe_BSW07) : đối tượng scheme
        pk    (dict)        : Public Key  — chia sẻ công khai
        mk    (dict)        : Master Key  — TA giữ bí mật tuyệt đối
    """

    def __init__(self,
                 pk_file: str = Config.PK_FILE,
                 mk_file: str = Config.MK_FILE,
                 group_name: str = Config.PAIRING_GROUP):
        if not CHARM_AVAILABLE:
            raise RuntimeError("Charm-Crypto không khả dụng.")

        self.pk_file    = pk_file
        self.mk_file    = mk_file
        self.group_name = group_name

        self.group = PairingGroup(group_name)
        self.cpabe = CPabe_BSW07(self.group)

        self.pk = None
        self.mk = None

    # ──────────────────────────────────────────────────────
    # Setup — Khởi tạo hệ thống
    # ──────────────────────────────────────────────────────
    def setup(self, force: bool = False) -> tuple:
        """
        Khởi tạo PK và MK.
        Nếu file đã tồn tại → nạp từ file (trừ khi force=True).

        Args:
            force: nếu True, tạo lại key mới dù file đã tồn tại

        Returns:
            (pk, mk) tuple
        """
        os.makedirs(os.path.dirname(self.pk_file), exist_ok=True)
        os.makedirs(os.path.dirname(self.mk_file), exist_ok=True)

        if not force and os.path.exists(self.pk_file) and os.path.exists(self.mk_file):
            logger.info("Tìm thấy key cũ — đang nạp PK và MK từ file ...")
            self.pk, self.mk = self._load_keys()
            logger.info("✓ Nạp PK/MK thành công.")
        else:
            logger.info("Đang khởi tạo hệ thống CP-ABE (BSW07) ...")
            self.pk, self.mk = self.cpabe.setup()
            self._save_keys(self.pk, self.mk)
            logger.info("✓ Setup CP-ABE hoàn tất — PK và MK đã lưu.")

        return self.pk, self.mk

    # ──────────────────────────────────────────────────────
    # Keygen — Sinh Secret Key cho User
    # ──────────────────────────────────────────────────────
    def keygen(self, attributes: list) -> dict:
        """
        Sinh Secret Key (SK) cho user với danh sách thuộc tính.

        Args:
            attributes: danh sách chuỗi thuộc tính, ví dụ:
                        ['DOCTOR', 'HOSPITAL_A', 'CARDIOLOGY']

        Returns:
            sk (dict): Secret Key của user

        Raises:
            RuntimeError: nếu PK hoặc MK chưa được khởi tạo
        """
        if self.pk is None or self.mk is None:
            raise RuntimeError("PK/MK chưa được khởi tạo. Gọi setup() trước.")

        # Chuẩn hoá attribute thành chữ HOA, loại bỏ khoảng trắng thừa
        clean_attrs = [a.strip().upper() for a in attributes if a.strip()]

        if not clean_attrs:
            raise ValueError("Danh sách attribute không được rỗng.")

        logger.info(f"Đang sinh SK cho attributes: {clean_attrs}")
        sk = self.cpabe.keygen(self.pk, self.mk, clean_attrs)
        logger.info(f"✓ Sinh SK thành công cho {len(clean_attrs)} attributes.")
        return sk

    # ──────────────────────────────────────────────────────
    # Serialize / Deserialize (để truyền qua socket)
    # ──────────────────────────────────────────────────────
    def serialize_key(self, key: dict) -> str:
        """
        Chuyển Charm object → bytes → base64 string (an toàn khi truyền JSON).
        """
        raw = objectToBytes(key, self.group)
        return base64.b64encode(raw).decode("utf-8")

    def deserialize_key(self, b64_str: str) -> dict:
        """
        Chuyển base64 string → bytes → Charm object.
        """
        raw = base64.b64decode(b64_str.encode("utf-8"))
        return bytesToObject(raw, self.group)

    def serialize_pk(self) -> str:
        """Lấy PK đã được serialize thành base64."""
        if self.pk is None:
            raise RuntimeError("PK chưa được khởi tạo.")
        return self.serialize_key(self.pk)

    # ──────────────────────────────────────────────────────
    # Lưu / Nạp key file
    # ──────────────────────────────────────────────────────
    def _save_keys(self, pk: dict, mk: dict) -> None:
        """Lưu PK và MK vào file dùng pickle (binary)."""
        pk_bytes = objectToBytes(pk, self.group)
        mk_bytes = objectToBytes(mk, self.group)

        with open(self.pk_file, "wb") as f:
            pickle.dump(pk_bytes, f)
        with open(self.mk_file, "wb") as f:
            pickle.dump(mk_bytes, f)

        logger.debug(f"Đã lưu PK → {self.pk_file}")
        logger.debug(f"Đã lưu MK → {self.mk_file}")

    def _load_keys(self) -> tuple:
        """Nạp PK và MK từ file."""
        with open(self.pk_file, "rb") as f:
            pk_bytes = pickle.load(f)
        with open(self.mk_file, "rb") as f:
            mk_bytes = pickle.load(f)

        pk = bytesToObject(pk_bytes, self.group)
        mk = bytesToObject(mk_bytes, self.group)
        return pk, mk

    # ──────────────────────────────────────────────────────
    # Thông tin hệ thống
    # ──────────────────────────────────────────────────────
    def is_ready(self) -> bool:
        return self.pk is not None and self.mk is not None

    def info(self) -> dict:
        return {
            "scheme"       : "CP-ABE BSW07",
            "pairing_group": self.group_name,
            "pk_file"      : self.pk_file,
            "mk_file"      : self.mk_file,
            "initialized"  : self.is_ready(),
        }
