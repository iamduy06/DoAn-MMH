import sys
import os
import base64
import traceback
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QFileDialog, QMessageBox, QGroupBox, QFormLayout)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

# Import backend logic
from charm.toolbox.pairinggroup import PairingGroup
from charm.core.engine.util import bytesToObject, objectToBytes
from owner import cpabe_encrypt_aes_key
from aes_utils import encrypt_aes, key_to_b64
from firebase_utils import login
from cloud_utils import upload_ehr_record
from ta_client import get_public_key

class DataOwnerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Data Owner - CP-ABE EHR System")
        self.resize(700, 600)
        self.group = PairingGroup('SS512')
        self.pk = None
        self.user_info = None

        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)

        # 1. Login Group
        login_group = QGroupBox("1. Đăng nhập hệ thống (Firebase)")
        login_layout = QFormLayout()
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("Bác sĩ / Data Owner Email")
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.login_btn = QPushButton("Đăng nhập & Kết nối TA Server")
        self.login_btn.clicked.connect(self.handle_login)

        login_layout.addRow("Email:", self.email_input)
        login_layout.addRow("Mật khẩu:", self.pass_input)
        login_layout.addRow("", self.login_btn)
        login_group.setLayout(login_layout)
        main_layout.addWidget(login_group)

        # 2. Encryption Group
        enc_group = QGroupBox("2. Mã hoá Hồ sơ bệnh án (EHR File)")
        enc_layout = QFormLayout()

        # Chọn file
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setReadOnly(True)
        self.browse_btn = QPushButton("Chọn File JSON")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(self.browse_btn)

        self.record_id_input = QLineEdit()
        self.record_id_input.setPlaceholderText("Ví dụ: 12345")

        self.policy_input = QLineEdit()
        self.policy_input.setPlaceholderText("Ví dụ: DOCTOR OR BREAK_GLASS")

        self.encrypt_btn = QPushButton("Mã hoá & Upload")
        self.encrypt_btn.setEnabled(False) # Bật sau khi login
        self.encrypt_btn.clicked.connect(self.handle_encrypt)

        enc_layout.addRow("File gốc:", file_layout)
        enc_layout.addRow("Record ID:", self.record_id_input)
        enc_layout.addRow("Access Policy:", self.policy_input)
        enc_layout.addRow("", self.encrypt_btn)
        enc_group.setLayout(enc_layout)
        main_layout.addWidget(enc_group)

        # 3. Log / Output Group
        log_group = QGroupBox("3. Log trạng thái")
        log_layout = QVBoxLayout()
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setFont(QFont("Consolas", 10))
        log_layout.addWidget(self.log_output)
        log_group.setLayout(log_layout)
        main_layout.addWidget(log_group)

    def log(self, message):
        self.log_output.append(message)
        # Scroll to bottom
        sb = self.log_output.verticalScrollBar()
        sb.setValue(sb.maximum())

    def handle_login(self):
        email = self.email_input.text().strip()
        password = self.pass_input.text().strip()

        if not email or not password:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập Email và Mật khẩu!")
            return

        self.log("Đang đăng nhập vào Firebase...")
        QApplication.processEvents() # Cập nhật UI

        try:
            self.user_info = login(email, password)
            self.log(f"✓ Đăng nhập thành công! User ID: {self.user_info.get('localId', 'unknown')}")
        except Exception as e:
            self.log(f"✗ Lỗi đăng nhập: {str(e)}")
            QMessageBox.critical(self, "Lỗi đăng nhập", str(e))
            return

        self.log("Đang kết nối TA Server để lấy Public Key...")
        QApplication.processEvents()

        try:
            self.pk = get_public_key(self.user_info["idToken"])
            self.log("✓ Lấy Public Key từ TA thành công!")
            self.encrypt_btn.setEnabled(True)
            self.login_btn.setEnabled(False)
        except Exception as e:
            self.log(f"✗ Không kết nối được TA: {str(e)}")
            QMessageBox.critical(self, "Lỗi kết nối TA", f"Kiểm tra lại TA Server. Lỗi: {str(e)}")

    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Chọn file EHR JSON", "", "JSON Files (*.json);;All Files (*)")
        if filename:
            self.file_input.setText(filename)

    def handle_encrypt(self):
        file_path = self.file_input.text()
        record_id = self.record_id_input.text().strip()
        policy = self.policy_input.text().strip().upper()

        if not file_path or not os.path.exists(file_path):
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn file hợp lệ!")
            return
        if not record_id:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập Record ID!")
            return
        if not policy:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập Access Policy!")
            return

        self.log(f"\n--- BẮT ĐẦU MÃ HOÁ BẢN GHI {record_id} ---")
        QApplication.processEvents()

        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            self.log(f"Đang sinh khóa và mã hóa AES Key với policy: {policy}...")
            QApplication.processEvents()

            # Gọi logic mã hoá từ owner.py
            ct_b64, aes_key = cpabe_encrypt_aes_key(self.pk, None, policy)
            self.log(f"✓ AES key derived: {key_to_b64(aes_key)[:20]}...")

            self.log("Đang mã hóa dữ liệu file bằng AES-256-CBC...")
            QApplication.processEvents()
            encrypted_data = encrypt_aes(plaintext, aes_key)
            encrypted_data_b64 = base64.b64encode(encrypted_data).decode('utf-8')

            self.log("Đang upload mock blob lên cloud storage...")
            pk_bytes = objectToBytes(self.pk, self.group)
            pk_b64 = base64.b64encode(pk_bytes).decode('utf-8')

            # Gọi cloud_utils lưu local
            upload_ehr_record(record_id, encrypted_data_b64, ct_b64, policy, pk_b64)

            self.log(f"✓ HOÀN THÀNH! File đã được mã hóa và lưu làm record {record_id}.")
            QMessageBox.information(self, "Thành công", f"Đã mã hoá và lưu record {record_id}!")

        except Exception as e:
            self.log(f"✗ Lỗi trong quá trình mã hoá: {str(e)}")
            self.log(traceback.format_exc())
            QMessageBox.critical(self, "Lỗi mã hoá", str(e))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = DataOwnerGUI()
    window.show()
    sys.exit(app.exec())
