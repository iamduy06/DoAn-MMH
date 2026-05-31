import sys
import os
import base64
import traceback
import json
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QMessageBox, QGroupBox, QFormLayout, QCheckBox)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

# Import backend logic
from config import Config
from user_app import firebase_login
from ta_client import TAClient
from azure_cloud import AzureCloud
from cpabe_user import CPABEUser
from aes_utils import AESCipher

class DataUserGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Data User - CP-ABE EHR System")
        self.resize(800, 700)
        
        self.token = None
        self.sk_b64 = None

        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # 1. Login Group
        login_group = QGroupBox("1. Đăng nhập hệ thống (Firebase)")
        login_layout = QFormLayout()
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Email đăng nhập")
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_btn = QPushButton("Đăng nhập")
        self.login_btn.clicked.connect(self.handle_login)

        login_layout.addRow("Email:", self.email_input)
        login_layout.addRow("Mật khẩu:", self.pass_input)
        login_layout.addRow("", self.login_btn)
        login_group.setLayout(login_layout)
        main_layout.addWidget(login_group)

        # 2. Key Request Group
        sk_group = QGroupBox("2. Xin Secret Key từ TA Server")
        sk_layout = QFormLayout()
        
        self.attr_input = QLineEdit()
        self.attr_input.setPlaceholderText("Ví dụ: DOCTOR, CARDIOLOGY (cách nhau bởi dấu phẩy)")
        
        self.break_glass_cb = QCheckBox("Yêu cầu quyền truy cập khẩn cấp (BREAK_GLASS)")
        
        self.get_sk_btn = QPushButton("Request Secret Key")
        self.get_sk_btn.setEnabled(False)
        self.get_sk_btn.clicked.connect(self.handle_get_sk)
        
        sk_layout.addRow("Thuộc tính của bạn:", self.attr_input)
        sk_layout.addRow("", self.break_glass_cb)
        sk_layout.addRow("", self.get_sk_btn)
        sk_group.setLayout(sk_layout)
        main_layout.addWidget(sk_group)

        # 3. Download & Decrypt Group
        dec_group = QGroupBox("3. Tải & Giải mã Hồ sơ")
        dec_layout = QFormLayout()
        
        self.record_id_input = QLineEdit()
        self.record_id_input.setPlaceholderText("Nhập ID Hồ sơ bệnh án cần tải (VD: 12345)")
        
        self.decrypt_btn = QPushButton("Download & Decrypt")
        self.decrypt_btn.setEnabled(False)
        self.decrypt_btn.clicked.connect(self.handle_decrypt)
        
        dec_layout.addRow("Record ID:", self.record_id_input)
        dec_layout.addRow("", self.decrypt_btn)
        dec_group.setLayout(dec_layout)
        main_layout.addWidget(dec_group)

        # 4. Result/Log Group
        res_group = QGroupBox("4. Kết quả giải mã / Logs")
        res_layout = QVBoxLayout()
        self.res_output = QTextEdit()
        self.res_output.setReadOnly(True)
        self.res_output.setFont(QFont("Consolas", 10))
        res_layout.addWidget(self.res_output)
        res_group.setLayout(res_layout)
        main_layout.addWidget(res_group)

    def log(self, message):
        self.res_output.append(message)
        # Scroll to bottom
        sb = self.res_output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def log_success(self, message):
        self.res_output.append(f"<span style='color:green;'>{message}</span>")
        sb = self.res_output.verticalScrollBar()
        sb.setValue(sb.maximum())
        
    def log_error(self, message):
        self.res_output.append(f"<span style='color:red;'><b>{message}</b></span>")
        sb = self.res_output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def handle_login(self):
        email = self.email_input.text().strip()
        password = self.pass_input.text().strip()

        if not email or not password:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập Email và Mật khẩu!")
            return

        self.log("Đang đăng nhập vào Firebase Auth...")
        QApplication.processEvents()

        try:
            self.token = firebase_login(email, password)
            self.log_success(f"✓ Đăng nhập thành công! Đã lấy Firebase Token.")
            self.get_sk_btn.setEnabled(True)
        except Exception as e:
            self.log_error(f"✗ Lỗi đăng nhập: {str(e)}")
            QMessageBox.critical(self, "Lỗi đăng nhập", "Kiểm tra lại tài khoản Firebase.")

    def handle_get_sk(self):
        raw_attrs = self.attr_input.text().strip()
        if not raw_attrs:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập ít nhất một thuộc tính!")
            return
            
        attrs = [a.strip() for a in raw_attrs.split(",") if a.strip()]
        
        if self.break_glass_cb.isChecked():
            if "BREAK_GLASS" not in [a.upper() for a in attrs]:
                attrs.append("BREAK_GLASS")
                
        self.log(f"Đang gửi yêu cầu xin SK tới TA Server với attributes: {attrs} ...")
        QApplication.processEvents()
        
        try:
            client = TAClient(host=Config.TA_HOST, port=Config.TA_PORT, ca_cert=Config.CERT_FILE)
            resp = client.get_sk(attrs, token=self.token)
            
            if resp.get("status") == "ok":
                self.sk_b64 = resp["data"]["sk"]
                with open(Config.SK_FILE, "w") as f:
                    f.write(self.sk_b64)
                self.log_success("✓ Nhận và lưu Secret Key thành công!")
                self.decrypt_btn.setEnabled(True)
            else:
                self.log_error(f"✗ TA Server từ chối: {resp.get('message')}")
                QMessageBox.critical(self, "Lỗi TA Server", resp.get('message', 'Không rõ lỗi'))
        except Exception as e:
            self.log_error(f"✗ Lỗi kết nối tới TA: {str(e)}")

    def handle_decrypt(self):
        record_id = self.record_id_input.text().strip()
        if not record_id:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập Record ID!")
            return
            
        if not self.sk_b64:
            # Try to load local key if it exists
            if os.path.exists(Config.SK_FILE):
                with open(Config.SK_FILE, "r") as f:
                    self.sk_b64 = f.read().strip()
                self.log("✓ Đã nạp lại Secret Key từ file local.")
            else:
                QMessageBox.warning(self, "Lỗi", "Bạn chưa có Secret Key! Hãy request trước.")
                return

        self.log(f"Đang tải hồ sơ {record_id} từ Cloud (Mock)...")
        QApplication.processEvents()
        
        cloud_data = AzureCloud.download_data(record_id, offline=True)
        if not cloud_data:
            self.log_error("✗ Không tìm thấy dữ liệu trên Cloud!")
            return
            
        pk_b64 = cloud_data.get("public_key")
        ct_b64 = cloud_data.get("encrypted_aes_key")
        enc_data_b64 = cloud_data.get("ciphertext")
        
        if not all([pk_b64, ct_b64, enc_data_b64]):
            self.log_error("✗ Dữ liệu từ Cloud bị thiếu trường (PK, CT, Data).")
            return

        self.log("Đang giải mã CP-ABE để khôi phục AES key...")
        QApplication.processEvents()
        
        try:
            cpabe = CPABEUser()
            aes_key_bytes = cpabe.decrypt(pk_b64, self.sk_b64, ct_b64)
            self.log_success("✓ Giải mã CP-ABE thành công!")
            
            self.log("Đang giải mã dữ liệu AES-256-CBC...")
            QApplication.processEvents()
            
            ciphertext_bytes = base64.b64decode(enc_data_b64)
            plaintext = AESCipher.decrypt(aes_key_bytes, ciphertext_bytes)
            
            self.log_success("✓ Giải mã Dữ liệu thành công!\n")
            
            # Format JSON for display if possible
            try:
                json_data = json.loads(plaintext.decode('utf-8'))
                formatted = json.dumps(json_data, indent=4, ensure_ascii=False)
                self.res_output.append("<hr>")
                self.res_output.append(f"<pre>{formatted}</pre>")
                self.res_output.append("<hr>")
            except:
                self.res_output.append("<hr>")
                self.res_output.append(plaintext.decode('utf-8'))
                self.res_output.append("<hr>")
                
            QMessageBox.information(self, "Thành công", "Đã giải mã thành công hồ sơ y tế!")
            
        except PermissionError:
            self.log_error("\nDECRYPTION FAILED: Bạn không đủ quyền (attributes) để giải mã hồ sơ này!\n")
        except Exception as e:
            self.log_error(f"✗ Lỗi giải mã: {str(e)}")
            self.log(traceback.format_exc())

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DataUserGUI()
    window.show()
    sys.exit(app.exec())
