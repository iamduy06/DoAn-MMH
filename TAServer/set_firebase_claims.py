"""
set_firebase_claims.py — Tự động cấu hình Custom Claims và tạo tài khoản kiểm thử Firebase
Dành cho đề tài CP-ABE EHR (Lớp NT219.P22.ANTT)
"""

import os
import sys

# ── Import Firebase Admin SDK ────────────────────────────
try:
    import firebase_admin
    from firebase_admin import credentials, auth
except ImportError:
    print("[ERROR] Chưa cài đặt thư viện 'firebase-admin'.")
    print("Vui lòng chạy lệnh: pip install firebase-admin")
    sys.exit(1)

# Đường dẫn tệp cấu hình tài khoản dịch vụ (Service Account JSON)
CRED_PATH = os.path.join(os.path.dirname(__file__), "firebase_credentials.json")

if not os.path.exists(CRED_PATH):
    print(f"[ERROR] Không tìm thấy tệp cấu hình Firebase tại: {CRED_PATH}")
    print("Vui lòng tải tệp 'serviceAccountKey.json' từ Firebase Console, "
          "đổi tên thành 'firebase_credentials.json' và lưu vào thư mục TAServer/.")
    sys.exit(1)

# Khởi tạo ứng dụng Firebase Admin
try:
    cred = credentials.Certificate(CRED_PATH)
    firebase_admin.initialize_app(cred)
except Exception as e:
    print(f"[ERROR] Không thể khởi tạo Firebase Admin SDK: {e}")
    sys.exit(1)

# Danh sách tài khoản kiểm thử mặc định và vai trò (Custom Claims) tương ứng
TEST_USERS = {
    "doctor@ehr.com": {"role": "doctor"},
    "manager@ehr.com": {"role": "user"},
    "nurse@ehr.com": {"role": "user"},
    "researcher@ehr.com": {"role": "user"},
    "patient@ehr.com": {"role": "patient"},
    "admin@ehr.com": {"role": "admin"}
}

DEFAULT_PASSWORD = "Password123"

def run_setup():
    print("=" * 70)
    print("  KỊCH BẢN CẤU HÌNH TỰ ĐỘNG FIREBASE CUSTOM CLAIMS & TÀI KHOẢN DỰ ÁN")
    print("=" * 70)
    
    success_count = 0
    
    for email, claims in TEST_USERS.items():
        role_name = claims["role"]
        print(f"\n⚡ Đang xử lý tài khoản: {email} ...")
        
        try:
            # 1. Tra cứu xem tài khoản đã tồn tại trên Firebase chưa
            user = auth.get_user_by_email(email)
            print(f"   • Tìm thấy tài khoản hiện có (UID: {user.uid})")
        except auth.UserNotFoundError:
            # 2. Nếu chưa tồn tại, tự động tạo mới tài khoản với mật khẩu mặc định
            print(f"   • Tài khoản chưa tồn tại. Đang tiến hành khởi tạo tự động trên Firebase...")
            try:
                user = auth.create_user(
                    email=email,
                    email_verified=True,
                    password=DEFAULT_PASSWORD,
                    display_name=email.split("@")[0].capitalize()
                )
                print(f"   ✓ Đã tạo thành công tài khoản mới với mật khẩu: '{DEFAULT_PASSWORD}'")
            except Exception as ex:
                print(f"   ❌ Không thể tạo tài khoản {email}: {ex}")
                import traceback
                traceback.print_exc()
                continue
        except Exception as e:
            print(f"   ❌ Lỗi tra cứu tài khoản {email}: {e}")
            import traceback
            traceback.print_exc()
            continue

        # 3. Thiết lập Custom Claims (gán trường role cho ID Token)
        try:
            auth.set_custom_user_claims(user.uid, claims)
            print(f"   ✓ Đã thiết lập Custom Claims thành công: {claims} (role = '{role_name}')")
            success_count += 1
        except Exception as e:
            print(f"   ❌ Lỗi thiết lập Custom Claims cho {email}: {e}")
            import traceback
            traceback.print_exc()

    print("\n" + "=" * 70)
    print(f"  HOÀN THÀNH! Đã đồng bộ thành công {success_count}/{len(TEST_USERS)} tài khoản kiểm thử.")
    print("  Giờ đây các Token được cấp sẽ chứa đúng thuộc tính phân quyền thực tế.")
    print("=" * 70)

if __name__ == "__main__":
    run_setup()
