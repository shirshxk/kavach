from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QTimer
from src.utils.traffic_monitor import get_traffic_statistics
from src.utils.helpers import Helper
import time

class TrafficMonitor(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Live Traffic Monitor")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #B22222; padding: 10px;")
        layout.addWidget(title)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setStyleSheet("background-color: #2b2b2b; color: white; padding: 10px; border-radius: 6px;")
        layout.addWidget(self.output)

        self.monitor_btn = QPushButton("Start Monitoring")
        self.monitor_btn.clicked.connect(self.start_monitoring)
        self.monitor_btn.setStyleSheet("background-color: #B22222; color: white; padding: 10px; border-radius: 6px;")
        layout.addWidget(self.monitor_btn)

    def start_monitoring(self):
        interface = Helper.detect_interface()
        duration = 10
        self.output.append(f"📡 Monitoring {interface} for {duration} seconds...")

        for i in range(duration):
            time.sleep(1)

        stats = get_traffic_statistics(interface, duration)
        self.output.append(f"\n✅ Monitoring complete.")
        self.output.append(f"📦 Packets: {stats['packets']}\n📊 Data: {stats['data']:,} bytes")
