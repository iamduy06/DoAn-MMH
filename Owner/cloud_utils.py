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

def upload_encrypted_key(column_name: str, cpabe_ciphertext_b64: str, policy: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='manage_key' AND xtype='U')
        CREATE TABLE manage_key (
            id INT IDENTITY(1,1) PRIMARY KEY,
            column_name NVARCHAR(100),
            cp_abe NVARCHAR(MAX),
            policy NVARCHAR(500),
            created_at DATETIME DEFAULT GETDATE()
        )
    """)
    cursor.execute("DELETE FROM manage_key WHERE column_name = ?", (column_name,))
    cursor.execute(
        "INSERT INTO manage_key (column_name, cp_abe, policy) VALUES (?, ?, ?)",
        (column_name, cpabe_ciphertext_b64, policy)
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
