import pyodbc
import base64

CONNECTION_STRING = "Driver={ODBC Driver 18 for SQL Server};Server=tcp:cpabe-ehr-server.database.windows.net,1433;Database=cpabe-ehr-db;Uid=cpabeadmin;Pwd=linhquang206!;Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"

def get_connection():
    try:
        conn = pyodbc.connect(CONNECTION_STRING)
        return conn
    except Exception as e:
        raise Exception(f"Kết nối Azure SQL thất bại: {e}")

def upload_ehr_record(record_id: str, encrypted_data_b64: str,
                      cpabe_ciphertext_b64: str, policy: str, pk_b64: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='ehr_records' AND xtype='U')
        CREATE TABLE ehr_records (
            id INT IDENTITY(1,1) PRIMARY KEY,
            record_id NVARCHAR(100) UNIQUE NOT NULL,
            policy NVARCHAR(500),
            ciphertext NVARCHAR(MAX),
            encrypted_aes_key NVARCHAR(MAX),
            public_key NVARCHAR(MAX),
            created_at DATETIME DEFAULT GETDATE()
        )
    """)
    cursor.execute("DELETE FROM ehr_records WHERE record_id = ?", (record_id,))
    cursor.execute("""
        INSERT INTO ehr_records (record_id, policy, ciphertext, encrypted_aes_key, public_key)
        VALUES (?, ?, ?, ?, ?)
    """, (record_id, policy, encrypted_data_b64, cpabe_ciphertext_b64, pk_b64))
    conn.commit()
    conn.close()
    print(f"  [AZURE] Đã upload record {record_id} lên Azure SQL.")

def download_ehr_record(record_id: str) -> dict:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT record_id, policy, ciphertext, encrypted_aes_key, public_key
        FROM ehr_records WHERE record_id = ?
    """, (record_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise Exception(f"Không tìm thấy record_id: {record_id}")
    return {
        "record_id": row[0],
        "policy": row[1],
        "ciphertext": row[2],
        "encrypted_aes_key": row[3],
        "public_key": row[4]
    }

def list_ehr_records() -> list:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT record_id, policy, created_at FROM ehr_records ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [{"record_id": r[0], "policy": r[1], "created_at": str(r[2])} for r in rows]

# Giữ lại các hàm cũ để không bị lỗi nếu còn chỗ nào dùng
def upload_encrypted_key(column_name, cpabe_ciphertext_b64, policy, public_key_b64):
    pass

def download_encrypted_keys():
    return []

def upload_mock_ehr_record(record_id, encrypted_data_b64, cpabe_ciphertext_b64, policy, pk_b64):
    upload_ehr_record(record_id, encrypted_data_b64, cpabe_ciphertext_b64, policy, pk_b64)
