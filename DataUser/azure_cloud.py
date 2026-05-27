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
            try:
                import pyodbc
                logger.info(f"Đang kết nối Azure SQL Database: {Config.AZURE_SERVER}...")
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
                
                # Lấy tên bảng và cột mặc định (phù hợp với cấu trúc Owner đã mã hoá)
                table = "records"
                column = "ciphertext"
                column_name = f"{table}.{column}"
                
                # Truy vấn thực tế tương thích 100% với schema của Owner
                query = f"""
                    SELECT r.[{column}], k.[cp_abe], k.[public_key]
                    FROM [{table}] r
                    CROSS JOIN [manage_key] k
                    WHERE r.[id] = ? AND k.[column_name] = ?
                """
                cursor.execute(query, (record_id, column_name))
                row = cursor.fetchone()
                
                if row:
                    logger.info("✓ Tải dữ liệu thành công từ Azure SQL Database thực tế.")
                    return {
                        "ciphertext": row[0],
                        "encrypted_aes_key": row[1],
                        "public_key": row[2]
                    }
                else:
                    logger.warning(f"Không tìm thấy bản ghi {record_id} trên Azure SQL.")
            except Exception as e:
                logger.warning(f"Lỗi kết nối Azure SQL ({e}). Tự động chuyển sang chế độ offline...")

        # Chế độ Fallback offline
        logger.info(f"Chạy chế độ offline: Đọc bản ghi ID={record_id} từ thư mục data cục bộ...")
        mock_file = os.path.join(Config.DATA_DIR, f"cloud_record_{record_id}.json")
        
        if not os.path.exists(mock_file):
            logger.error(f"Không tìm thấy bản ghi offline {record_id} tại {mock_file}!")
            logger.info(f"Vui lòng tạo file test: {mock_file} chứa 'encrypted_aes_key', 'ciphertext' và 'public_key' (base64).")
            return None
            
        with open(mock_file, "r") as f:
            data = json.load(f)
            
        logger.info(f"✓ Tải thành công dữ liệu mã hoá giả lập từ local.")
        return data

