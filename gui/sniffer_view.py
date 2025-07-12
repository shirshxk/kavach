from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTextEdit
from PyQt5.QtGui import QFont
from src.core.packet_sniffer import PacketSniffer
from src.core.packet_filter import PacketFilter
from src.core.rule_engine import RuleEngine
from src.core.logger import Logger
from src.utils.helpers import Helper
import threading

class SnifferView(QWidget):
    def __init__(self):
        super().__init__()
        self.rule_engine = RuleEngine()
        self.logger = Logger("logs/firewall.log")
        self.packet_filter = PacketFilter(self.rule_engine, mode="view")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Live Traffic View")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #B22222; padding: 10px;")
        layout.addWidget(title)

        self.sniffer_output = QTextEdit()
        self.sniffer_output.setReadOnly(True)
        self.sniffer_output.setStyleSheet("background-color: #2b2b2b; color: white; padding: 10px; border-radius: 6px;")
        layout.addWidget(self.sniffer_output)

        start_btn = QPushButton("Start Sniffing")
        start_btn.clicked.connect(self.start_sniffer)
        start_btn.setStyleSheet("""
            QPushButton {
                background-color: #B22222;
                color: white;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #A52A2A;
            }
        """)
        layout.addWidget(start_btn)

    def start_sniffer(self):
        def run_sniffer():
            sniffer = PacketSniffer(Helper.detect_interface(), self.packet_filter, self.logger)
            sniffer.packet_handler = lambda pkt: self.sniffer_output.append(pkt.summary())
            sniffer.start()

        threading.Thread(target=run_sniffer, daemon=True).start()
