"""
firebase_auth.py — Xác thực Owner và User qua Firebase Auth
Xác minh ID Token gửi từ client, trả về thông tin user đã xác thực.
"""
import logging
from typing import Optional
from config import Config

logger = logging.getLogger("TA_Server")

# ── Import Firebase Admin SDK ────────────────────────────
try:
    import firebase_admin
    from firebase_admin import credentials, auth as firebase_auth_module
    FIREBASE_AVAILABLE = True
except ImportError:
    FIREBASE_AVAILABLE = False
    logger.warning(
        "firebase-admin chưa được cài. "
        "Chạy: pip install firebase-admin\n"
        "Auth sẽ bị bỏ qua nếu AUTH_ENABLED=false"
    )


# ────────────────────────────────────────────────────────
# Lớp xác thực trung tâm
# ────────────────────────────────────────────────────────
class FirebaseAuthenticator:
    """
    Quản lý xác thực người dùng thông qua Firebase Admin SDK.
    Hỗ trợ chế độ offline (auth_enabled=False) để test.
    """

    _initialized = False   # singleton flag

    def __init__(self,
                 cred_path: str  = Config.FIREBASE_CRED_PATH,
                 auth_enabled: bool = Config.AUTH_ENABLED):
        """
        Args:
            cred_path   : đường dẫn file serviceAccountKey.json của Firebase
            auth_enabled: False → bỏ qua xác thực (chỉ dùng khi test)
        """
        self.auth_enabled = auth_enabled

        if not auth_enabled:
            logger.warning(
                "[AUTH] Chế độ xác thực đang TẮT — "
                "chỉ dùng cho môi trường phát triển!"
            )
            return

        if not FIREBASE_AVAILABLE:
            raise RuntimeError(
                "firebase-admin chưa cài. "
                "Tắt AUTH hoặc cài: pip install firebase-admin"
            )

        if not FirebaseAuthenticator._initialized:
            self._init_firebase(cred_path)
            FirebaseAuthenticator._initialized = True

    # ──────────────────────────────────────────────────────
    # Khởi tạo Firebase App
    # ──────────────────────────────────────────────────────
    def _init_firebase(self, cred_path: str) -> None:
        """Khởi tạo Firebase Admin SDK một lần duy nhất."""
        import os
        if not os.path.exists(cred_path):
            raise FileNotFoundError(
                f"Không tìm thấy Firebase credentials: {cred_path}\n"
                "Tải file từ: Firebase Console → Project Settings → Service Accounts"
            )
        cred = credentials.Certificate(cred_path)
        firebase_admin.initialize_app(cred)
        logger.info(f"[AUTH] Firebase Admin SDK khởi tạo từ: {cred_path}")

    # ──────────────────────────────────────────────────────
    # Xác thực ID Token
    # ──────────────────────────────────────────────────────
    def verify_token(self, id_token: str) -> Optional[dict]:
        """
        Xác minh Firebase ID Token gửi từ client.

        Args:
            id_token: JWT token do Firebase client SDK cung cấp

        Returns:
            dict chứa thông tin user nếu hợp lệ:
                {
                    "uid"         : "user_unique_id",
                    "email"       : "user@example.com",
                    "name"        : "Nguyen Van A",
                    "role"        : "doctor",      # custom claim (nếu có)
                    "verified"    : True,
                }
            None nếu token không hợp lệ
        """
        # Chế độ offline: chấp nhận mọi token, trả về user giả
        if not self.auth_enabled:
            logger.debug("[AUTH] Bỏ qua xác thực (AUTH_ENABLED=false)")
            return {
                "uid"     : f"dev_{id_token[:8]}",
                "email"   : "dev@localhost",
                "name"    : "Dev User",
                "role"    : "developer",
                "verified": True,
            }

        try:
            decoded = firebase_auth_module.verify_id_token(id_token)
            email = decoded.get("email", "").lower()
            role = decoded.get("role", "")

            # Tự động gán vai trò dựa trên tiền tố/tên email nếu custom claims của Firebase trống
            if not role:
                if "admin" in email:
                    role = "admin"
                elif "doctor" in email:
                    role = "doctor"
                elif "manager" in email:
                    role = "user"
                elif "nurse" in email:
                    role = "user"
                elif "patient" in email:
                    role = "patient"
                elif "researcher" in email:
                    role = "user"
                else:
                    role = "user"  # Mặc định

            user_info = {
                "uid"     : decoded.get("uid"),
                "email"   : email,
                "name"    : decoded.get("name", ""),
                "role"    : role,
                "verified": decoded.get("email_verified", False),
            }

            logger.info(
                f"[AUTH] Xác thực OK — uid={user_info['uid']} "
                f"email={user_info['email']} role={user_info['role']}"
            )
            return user_info

        except firebase_auth_module.ExpiredIdTokenError:
            logger.warning("[AUTH] Token đã hết hạn.")
        except firebase_auth_module.InvalidIdTokenError as e:
            logger.warning(f"[AUTH] Token không hợp lệ: {e}")
        except firebase_auth_module.RevokedIdTokenError:
            logger.warning("[AUTH] Token đã bị thu hồi.")
        except Exception as e:
            logger.error(f"[AUTH] Lỗi xác thực không xác định: {e}")

        return None

    # ──────────────────────────────────────────────────────
    # Kiểm tra phân quyền
    # ──────────────────────────────────────────────────────
    def is_authorized(self, user_info: dict, required_role: str) -> bool:
        """
        Kiểm tra user có role cần thiết không.

        Args:
            user_info    : dict trả về từ verify_token()
            required_role: role cần thiết ("owner", "user", "admin")

        Returns:
            True nếu user có đủ quyền
        """
        if not user_info:
            return False

        role = user_info.get("role", "").lower()

        # Admin có toàn quyền
        if role == "admin":
            return True

        return role == required_role.lower()

    def get_user_by_uid(self, uid: str) -> Optional[dict]:
        """
        Lấy thông tin user từ Firebase theo UID.
        Dùng khi cần kiểm tra thêm thông tin ngoài token.
        """
        if not self.auth_enabled or not FIREBASE_AVAILABLE:
            return None
        try:
            user = firebase_auth_module.get_user(uid)
            return {
                "uid"          : user.uid,
                "email"        : user.email,
                "display_name" : user.display_name,
                "disabled"     : user.disabled,
                "custom_claims": user.custom_claims or {},
            }
        except Exception as e:
            logger.error(f"[AUTH] Không lấy được user {uid}: {e}")
            return None
