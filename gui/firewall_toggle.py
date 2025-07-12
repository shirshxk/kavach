
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox
from PyQt5.QtGui import QFont
from src.core.packet_filter import PacketFilter
from src.core.rule_engine import RuleEngine
from src.core.logger import Logger
from src.utils.helpers import Helper
import subprocess
import threading

class FirewallToggle(QWidget):
    def __init__(self):
        super().__init__()
        self.rule_engine = RuleEngine()
        self.logger = Logger("logs/firewall.log")
        self.packet_filter = PacketFilter(self.rule_engine, mode="block")
        self.nfqueue = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Firewall Block Mode")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #B22222; padding: 10px;")
        layout.addWidget(title)

        self.status_label = QLabel("Status: Inactive")
        self.status_label.setStyleSheet("color: white;")
        layout.addWidget(self.status_label)

        self.start_btn = QPushButton("Start Firewall")
        self.start_btn.clicked.connect(self.start_firewall)

        self.stop_btn = QPushButton("Stop Firewall")
        self.stop_btn.clicked.connect(self.stop_firewall)
        self.stop_btn.setEnabled(False)

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
            layout.addWidget(btn)

    def start_firewall(self):
        try:
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"], check=True)
            self.status_label.setText("Status: Running")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)

            threading.Thread(target=self.run_nfqueue, daemon=True).start()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def run_nfqueue(self):
        from netfilterqueue import NetfilterQueue
        from scapy.all import IP
        self.nfqueue = NetfilterQueue()

        def process_packet(pkt):
            scapy_pkt = IP(pkt.get_payload())
            allowed = self.packet_filter.filter_packet(scapy_pkt)
            pkt.accept() if allowed else pkt.drop()

        self.nfqueue.bind(1, process_packet)
        try:
            self.nfqueue.run()
        except:
            self.nfqueue.unbind()

    def stop_firewall(self):
        try:
            subprocess.call(["sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"])
            if self.nfqueue:
                self.nfqueue.unbind()

            self.status_label.setText("Status: Inactive")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))