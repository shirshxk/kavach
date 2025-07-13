from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QHBoxLayout
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import pyqtSignal, pyqtSlot, QObject
from src.core.packet_sniffer import PacketSniffer
from src.core.packet_filter import PacketFilter
from src.core.rule_engine import RuleEngine
from src.core.logger import Logger
from src.utils.helpers import Helper
from gui.state import firewall_active
from gui.verdict_log import verdict_emitter
import threading
from scapy.all import IP, TCP, UDP, ARP
from datetime import datetime

class SignalEmitter(QObject):
    log_signal = pyqtSignal(dict)

class SnifferView(QWidget):
    def __init__(self):
        super().__init__()
        self.rule_engine = RuleEngine()
        self.logger = Logger("logs/firewall.log")
        self.packet_filter = PacketFilter(self.rule_engine, mode="view")
        self.signals = SignalEmitter()
        self.signals.log_signal.connect(self.append_packet)
        verdict_emitter.verdict_signal.connect(self.append_packet)  # Listen to real firewall verdicts
        self.sniffer_thread = None
        self.sniffer_instance = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Live Traffic View")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #B22222; padding: 10px;")
        layout.addWidget(title)

        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Protocol", "Source", "Destination", "Action"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setStyleSheet("background-color: #2b2b2b; color: white;")
        layout.addWidget(self.packet_table)

        btn_row = QHBoxLayout()
        self.start_btn = QPushButton("Start Sniffing")
        self.start_btn.clicked.connect(self.start_sniffer)

        self.stop_btn = QPushButton("Stop Sniffing")
        self.stop_btn.clicked.connect(self.stop_sniffer)
        self.stop_btn.setEnabled(False)

        self.clear_btn = QPushButton("Clear Table")
        self.clear_btn.clicked.connect(self.clear_table)

        for btn in [self.start_btn, self.stop_btn]:
            btn.setStyleSheet("""
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
            btn_row.addWidget(btn)

        self.clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #444444;
                color: white;
                padding: 10px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #5A5A5A;
            }
        """)
        btn_row.addWidget(self.clear_btn)

        layout.addLayout(btn_row)

    def start_sniffer(self):
        def run_sniffer():
            self.sniffer_instance = PacketSniffer(Helper.detect_interface(), self.packet_filter, self.logger)

            def handler(pkt):
                parsed = self.parse_packet(pkt)
                if parsed:
                    self.signals.log_signal.emit(parsed)

            self.sniffer_instance.packet_handler = handler
            self.sniffer_instance.start()

        self.sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        self.sniffer_thread.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_sniffer(self):
        if self.sniffer_instance:
            self.sniffer_instance.stop_sniffing = True
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def clear_table(self):
        self.packet_table.setRowCount(0)

    def parse_packet(self, packet):
        if not (IP in packet or ARP in packet):
            return None

        timestamp = datetime.now().strftime("%H:%M:%S")
        proto = "ARP" if ARP in packet else ("TCP" if TCP in packet else "UDP" if UDP in packet else "IP")
        src = dst = "N/A"

        if IP in packet:
            sport = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else ""
            dport = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else ""
            src = f"{packet[IP].src}:{sport}"
            dst = f"{packet[IP].dst}:{dport}"
        elif ARP in packet:
            src = packet[ARP].psrc
            dst = packet[ARP].pdst

        action = "ALLOW"
        if firewall_active:
            action = self.rule_engine.check_packet(packet)

        return {
            "time": timestamp,
            "proto": proto,
            "src": src,
            "dst": dst,
            "action": action
        }

    @pyqtSlot(dict)
    def append_packet(self, data):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        self.packet_table.setItem(row, 0, QTableWidgetItem(data["time"]))
        self.packet_table.setItem(row, 1, QTableWidgetItem(data["proto"]))
        self.packet_table.setItem(row, 2, QTableWidgetItem(data["src"]))
        self.packet_table.setItem(row, 3, QTableWidgetItem(data["dst"]))
        self.packet_table.setItem(row, 4, QTableWidgetItem(data["action"]))

        color = QColor("#B22222") if data["action"] == "BLOCK" else QColor("#228B22")
        for col in range(5):
            self.packet_table.item(row, col).setForeground(color)

        self.packet_table.scrollToBottom()
