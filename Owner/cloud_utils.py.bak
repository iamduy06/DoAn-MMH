import pyodbc
import base64

CONNECTION_STRING = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:cpabe-ehr-server.database.windows.net,1433;Database=cpabe-ehr-db;Uid=cpabeadmin;Pwd=linhquang206!;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"

def get_connection():
    try:
        conn = pyodbc.connect(CONNECTION_STRING)
        return conn
    except Exception as e:
        raise Exception(f"Kết nối Azure SQL thất bại: {e}")

def upload_encrypted_column(table: str, column: str, row_id: int, encrypted_value: str):
    conn = get_connection()
    cursor = conn.cursor()
    query = f"UPDATE [{table}] SET [{column}] = ? WHERE id = ?"
    cursor.execute(query, (encrypted_value, row_id))
    conn.commit()
    conn.close()
    print(f"  Uploaded [{table}].[{column}] row {row_id}")

def upload_encrypted_key(column_name: str, cpabe_ciphertext_b64: str, policy: str, public_key_b64: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='manage_key' AND xtype='U')
        CREATE TABLE manage_key (
            id INT IDENTITY(1,1) PRIMARY KEY,
            column_name NVARCHAR(100),
            cp_abe NVARCHAR(MAX),
            policy NVARCHAR(500),
            public_key NVARCHAR(MAX),
            created_at DATETIME DEFAULT GETDATE()
        )
    """)
    # Tự động nâng cấp bảng nếu thiếu cột public_key
    try:
        cursor.execute("ALTER TABLE manage_key ADD public_key NVARCHAR(MAX)")
    except Exception:
        pass

    cursor.execute("DELETE FROM manage_key WHERE column_name = ?", (column_name,))
    cursor.execute(
        "INSERT INTO manage_key (column_name, cp_abe, policy, public_key) VALUES (?, ?, ?, ?)",
        (column_name, cpabe_ciphertext_b64, policy, public_key_b64)
    )
    conn.commit()
    conn.close()
    print(f"  Uploaded encrypted key for [{column_name}] policy: {policy}")

def download_encrypted_keys() -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT column_name, cp_abe, policy FROM manage_key")
    rows = cursor.fetchall()
    conn.close()
    return [{"column_name": r[0], "cp_abe": r[1], "policy": r[2]} for r in rows]

def download_encrypted_data(table: str, columns: list) -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cols = ", ".join([f"[{c}]" for c in columns])
    cursor.execute(f"SELECT id, {cols} FROM [{table}]")
    rows = cursor.fetchall()
    conn.close()
    return rows

def upload_decrypted_column(table: str, column: str, row_id: int, plaintext_value: str):
    conn = get_connection()
    cursor = conn.cursor()
    query = f"UPDATE [{table}] SET [{column}] = ? WHERE id = ?"
    cursor.execute(query, (plaintext_value, row_id))
    conn.commit()
    conn.close()

def upload_mock_ehr_record(record_id: str, encrypted_data_b64: str, cpabe_ciphertext_b64: str, policy: str, pk_b64: str):
    """
    Giả lập việc upload file mã hoá lên Object Storage (S3/MinIO) 
    bằng cách lưu vào thư mục dùng chung (DataUser/data) để UserApp dễ dàng lấy về test.
    """
    import os
    import json
    
    # Giả định DataUser/data nằm cạnh thư mục Owner
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    data_dir = os.path.join(base_dir, "DataUser", "data")
    os.makedirs(data_dir, exist_ok=True)
    
    file_path = os.path.join(data_dir, f"cloud_record_{record_id}.json")
    
    payload = {
        "record_id": record_id,
        "policy": policy,
        "ciphertext": encrypted_data_b64,
        "encrypted_aes_key": cpabe_ciphertext_b64,
        "public_key": pk_b64,
        "timestamp": "2026-05-31T00:00:00Z"
    }
    
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4)
        
    print(f"  [MOCK CLOUD] Đã lưu mock record tại: {file_path}")
