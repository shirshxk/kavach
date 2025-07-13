# gui/firewall_toggle.py
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox, QHBoxLayout, QSizePolicy, QSpacerItem, QFrame
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from src.core.packet_filter import PacketFilter
from src.core.rule_engine import RuleEngine
from src.core.logger import Logger
from src.utils.helpers import Helper
from gui.state import firewall_active
from gui.verdict_log import verdict_emitter
import subprocess
import threading
from datetime import datetime

class FirewallToggle(QWidget):
    def __init__(self):
        super().__init__()
        self.rule_engine = RuleEngine()
        self.logger = Logger("logs/firewall.log")
        self.packet_filter = PacketFilter(self.rule_engine, mode="block")
        self.nfqueue = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setAlignment(Qt.AlignCenter)
        self.setLayout(main_layout)

        container = QFrame()
        container.setStyleSheet("""
            QFrame {
                background-color: #2e2e2e;
                border-radius: 16px;
                padding: 30px;
            }
        """)
        container_layout = QVBoxLayout()
        container_layout.setAlignment(Qt.AlignCenter)
        container_layout.setSpacing(25)
        container.setLayout(container_layout)

        title = QLabel("Firewall Block Mode")
        title.setFont(QFont("Arial", 22, QFont.Bold))
        title.setStyleSheet("color: #FF4C4C;")
        container_layout.addWidget(title, alignment=Qt.AlignCenter)

        self.status_label = QLabel("🛑 Firewall is INACTIVE")
        self.status_label.setFont(QFont("Arial", 16, QFont.Bold))
        self.status_label.setStyleSheet("color: #FFB6B6;")
        container_layout.addWidget(self.status_label, alignment=Qt.AlignCenter)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(40)

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
                    padding: 14px 28px;
                    font-size: 15px;
                    border-radius: 10px;
                }
                QPushButton:hover {
                    background-color: #cc3333;
                }
            """)
            btn.setMinimumWidth(180)
            btn.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            btn_row.addWidget(btn)

        container_layout.addLayout(btn_row)
        main_layout.addWidget(container)

    def start_firewall(self):
        global firewall_active
        try:
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"], check=True)
            self.status_label.setText("🟢 Firewall is ACTIVE")
            self.status_label.setStyleSheet("color: #98FB98;")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            firewall_active = True
            threading.Thread(target=self.run_nfqueue, daemon=True).start()

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def run_nfqueue(self):
        from netfilterqueue import NetfilterQueue
        from scapy.all import IP, TCP, UDP, ARP

        def process_packet(pkt):
            scapy_pkt = IP(pkt.get_payload())
            allowed = self.packet_filter.filter_packet(scapy_pkt)
            pkt.accept() if allowed else pkt.drop()

            proto = "TCP" if TCP in scapy_pkt else "UDP" if UDP in scapy_pkt else "IP"
            sport = scapy_pkt[TCP].sport if TCP in scapy_pkt else scapy_pkt[UDP].sport if UDP in scapy_pkt else ""
            dport = scapy_pkt[TCP].dport if TCP in scapy_pkt else scapy_pkt[UDP].dport if UDP in scapy_pkt else ""

            verdict_emitter.verdict_signal.emit({
                "time": datetime.now().strftime("%H:%M:%S"),
                "proto": proto,
                "src": f"{scapy_pkt.src}:{sport}",
                "dst": f"{scapy_pkt.dst}:{dport}",
                "action": "ALLOW" if allowed else "BLOCK"
            })

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(1, process_packet)
        try:
            self.nfqueue.run()
        except:
            self.nfqueue.unbind()

    def stop_firewall(self):
        global firewall_active
        try:
            subprocess.call(["sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"])
            if self.nfqueue:
                self.nfqueue.unbind()

            self.status_label.setText("🛑 Firewall is INACTIVE")
            self.status_label.setStyleSheet("color: #FFB6B6;")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            firewall_active = False

        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
