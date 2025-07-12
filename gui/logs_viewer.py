from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit, QPushButton
from PyQt5.QtGui import QFont
import os

class LogsViewer(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Firewall Logs")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #B22222; padding: 10px;")
        layout.addWidget(title)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setStyleSheet("background-color: #2b2b2b; color: white; padding: 10px; border-radius: 6px;")
        layout.addWidget(self.log_display)

        refresh_btn = QPushButton("Refresh Logs")
        refresh_btn.clicked.connect(self.load_logs)
        refresh_btn.setStyleSheet("background-color: #B22222; color: white; padding: 10px; border-radius: 6px;")
        layout.addWidget(refresh_btn)

        self.load_logs()

    def load_logs(self):
        if os.path.exists("logs/firewall.log"):
            with open("logs/firewall.log", "r") as file:
                self.log_display.setText(file.read())
        else:
            self.log_display.setText("No logs found.")
