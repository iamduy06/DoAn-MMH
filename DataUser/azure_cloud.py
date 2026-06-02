"""
azure_cloud.py — Kết nối đến Azure Cloud SQL.
Bao gồm hàm tải khoá AES (đã mã hoá) và dữ liệu (đã mã hoá).
"""
import os
import json
import logging
from config import Config

logger = logging.getLogger("UserApp")

class AzureCloud:
    """Quản lý tải dữ liệu từ Azure SQL với chế độ offline fallback"""
    
    @staticmethod
    def download_data(record_id: str, offline: bool = False) -> dict:
        """
        Tải xuống bản ghi bệnh án từ Azure SQL.
        Nếu offline=True hoặc kết nối lỗi, tự động fallback đọc file cục bộ data/cloud_record_{id}.json
        """
        if not offline:
            # 1. Thử kết nối sử dụng pyodbc (Nếu đã cấu hình ODBC Driver của Microsoft)
            try:
                import pyodbc
                logger.info(f"Đang kết nối Azure SQL Database dùng pyodbc: {Config.AZURE_SERVER}...")
                conn_str = (
                    f"DRIVER={Config.AZURE_DRIVER};"
                    f"SERVER={Config.AZURE_SERVER};"
                    f"DATABASE={Config.AZURE_DB};"
                    f"UID={Config.AZURE_UID};"
                    f"PWD={Config.AZURE_PWD};"
                    "Connection Timeout=5;"
                    "TrustServerCertificate=yes;"
                )

                conn = pyodbc.connect(conn_str)
                cursor = conn.cursor()
                
                table = "ehr_records"
                
                query = f"""
                    SELECT [ciphertext], [encrypted_aes_key], [public_key]
                    FROM [{table}]
                    WHERE [record_id] = ?
                """
                cursor.execute(query, (str(record_id),))
                row = cursor.fetchone()
                
                conn.close()
                
                if row:
                    logger.info("✓ Tải dữ liệu thành công từ Azure SQL Database thực tế (pyodbc).")
                    return {
                        "ciphertext": row[0],
                        "encrypted_aes_key": row[1],
                        "public_key": row[2]
                    }
                else:
                    logger.warning(f"Không tìm thấy bản ghi {record_id} trên Azure SQL.")
            except ImportError:
                # 2. Khắc phục thông minh: Fallback sang pymssql (Thư viện Python thuần không cần ODBC Driver)
                try:
                    import pymssql
                    logger.info(f"Đang kết nối Azure SQL Database dùng pymssql: {Config.AZURE_SERVER}...")
                    conn = pymssql.connect(
                        server=Config.AZURE_SERVER,
                        user=Config.AZURE_UID,
                        password=Config.AZURE_PWD,
                        database=Config.AZURE_DB,
                        timeout=5
                    )
                    cursor = conn.cursor()
                    
                    table = "ehr_records"
                    
                    # pymssql sử dụng %s làm placeholder thay cho ?
                    query = f"""
                        SELECT [ciphertext], [encrypted_aes_key], [public_key]
                        FROM [{table}]
                        WHERE [record_id] = %s
                    """
                    cursor.execute(query, (str(record_id),))
                    row = cursor.fetchone()
                    
                    conn.close()
                    
                    if row:
                        logger.info("✓ Tải dữ liệu thành công từ Azure SQL Database thực tế (pymssql).")
                        return {
                            "ciphertext": row[0],
                            "encrypted_aes_key": row[1],
                            "public_key": row[2]
                        }
                    else:
                        logger.warning(f"Không tìm thấy bản ghi {record_id} trên Azure SQL (pymssql).")
                except ImportError:
                    logger.warning("Cảnh báo: Không tìm thấy cả hai thư viện kết nối Database 'pyodbc' và 'pymssql'.")
                except Exception as e_mssql:
                    logger.warning(f"Lỗi kết nối Azure SQL qua pymssql: {e_mssql}")
            except Exception as e_odbc:
                logger.warning(f"Lỗi kết nối Azure SQL qua pyodbc: {e_odbc}")

        # Chế độ Fallback offline
        logger.info(f"Chạy chế độ offline: Đọc bản ghi ID={record_id} từ thư mục data cục bộ...")
        mock_file = os.path.join(Config.DATA_DIR, f"cloud_record_{record_id}.json")
        
        if not os.path.exists(mock_file):
            logger.error(f"Không tìm thấy bản ghi offline {record_id} tại {mock_file}!")
            logger.info(f"Vui lòng tạo file test: {mock_file} chứa 'encrypted_aes_key', 'ciphertext' và 'public_key' (base64).")
            return None
            
        with open(mock_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        logger.info(f"✓ Tải thành công dữ liệu mã hoá giả lập từ local.")
        return data

