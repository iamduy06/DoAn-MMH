import requests
from config_owner import FIREBASE_API_KEY

def login(email: str, password: str) -> dict:
    resp = requests.post(
        "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
        params={"key": FIREBASE_API_KEY},
        json={"email": email, "password": password, "returnSecureToken": True}
    )
    data = resp.json()
    if "idToken" not in data:
        error_msg = data.get("error", {}).get("message", "Unknown error")
        raise Exception(f"Đăng nhập thất bại: {error_msg}")
    print(f"  Đăng nhập thành công! UserID: {data['localId']}")
    return {
        "idToken": data["idToken"],
        "userId": data["localId"],
        "email": email
    }
