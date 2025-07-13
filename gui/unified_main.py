import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame
)
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtCore import Qt, pyqtSlot
from verdict_log import verdict_emitter
from state import firewall_active
from src.core.packet_sniffer import PacketSniffer
from src.core.packet_filter import PacketFilter
from src.core.rule_engine import RuleEngine
from src.core.logger import Logger
from src.utils.helpers import Helper
import threading
from scapy.all import IP, TCP, UDP, ARP
from datetime import datetime
from PyQt5.QtGui import QPixmap
from PyQt5.QtGui import QFontDatabase

class UnifiedMain(QWidget):
    def __init__(self):
        super().__init__()
        self.setStyleSheet("background-color: #1e1e1e; color: white;")
        self.rule_engine = RuleEngine()
        self.packet_filter = PacketFilter(self.rule_engine, mode="block")
        self.sniffer_instance = None
        self.sniffer_thread = None
        self.interface = Helper.detect_interface()
        font_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../assets/fonts/BricolageGrotesque.ttf"))
        QFontDatabase.addApplicationFont(font_path)

        self.init_ui()
        verdict_emitter.verdict_signal.connect(self.append_traffic_row)

    def init_ui(self):
        layout = QVBoxLayout(self)

        # ---- Top Logo ----
        from PyQt5.QtGui import QPixmap
        logo = QLabel()
        pixmap = QPixmap(os.path.abspath(os.path.join(os.path.dirname(__file__), "../logo.png")))
        logo.setPixmap(pixmap.scaledToHeight(80, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo)

        # ---- Rule Controls ----
        rule_bar = QHBoxLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Source IP")
        self.action_dropdown = QComboBox()
        self.action_dropdown.addItems(["ALLOW", "BLOCK"])
        add_btn = QPushButton("Add Rule")
        remove_btn = QPushButton("Remove Rule")
        list_btn = QPushButton("List Rules")

        for btn in [add_btn, remove_btn, list_btn]:
            btn.setFont(QFont("Bricolage Grotesque", 10, QFont.Medium))
            btn.setStyleSheet("background-color: #B22222; color: white; padding: 8px; border-radius: 6px;")

        add_btn.clicked.connect(self.add_rule)
        remove_btn.clicked.connect(self.remove_rule)
        list_btn.clicked.connect(self.list_rules)

        rule_bar.addWidget(self.ip_input)
        rule_bar.addWidget(self.action_dropdown)
        rule_bar.addWidget(add_btn)
        rule_bar.addWidget(remove_btn)
        rule_bar.addWidget(list_btn)
        layout.addLayout(rule_bar)

        # ---- Main Section (Traffic Table + Output Panel) ----
        bottom_section = QHBoxLayout()

        # --- Live Traffic Table ---
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(5)
        self.packet_table.setHorizontalHeaderLabels(["Time", "Proto", "Source", "Destination", "Action"])
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.packet_table.setStyleSheet("background-color: #2b2b2b; color: white; border-radius: 6px;")
        self.packet_table.setMinimumWidth(800)
        bottom_section.addWidget(self.packet_table, 3)

        # --- Right Panel: Output Box + Buttons ---
        right_panel = QVBoxLayout()

        # --- Panel Switch Buttons ---
        switch_bar = QHBoxLayout()
        self.monitor_btn = QPushButton("Traffic Monitor")
        self.logs_btn = QPushButton("View Logs")
        self.clear_btn = QPushButton("Clear Logs")

        for btn in [self.monitor_btn, self.logs_btn, self.clear_btn]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #555;
                    color: white;
                    padding: 6px;
                    border-radius: 5px;
                }
                QPushButton:hover {
                    background-color: #777;
                }
            """)
            btn.setMinimumWidth(110)

        self.monitor_btn.clicked.connect(self.show_monitor)
        self.logs_btn.clicked.connect(self.show_logs)
        self.clear_btn.clicked.connect(self.clear_output)

        switch_bar.addWidget(self.monitor_btn)
        switch_bar.addWidget(self.logs_btn)
        switch_bar.addWidget(self.clear_btn)
        right_panel.addLayout(switch_bar)

        # --- Output Text Box ---
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
        self.output_box.setFont(QFont("Bricolage Grotesque", 9, QFont.Light))
        self.output_box.setStyleSheet("background-color: #1c1c1c; color: #EEEEEE; border-radius: 8px;")
        right_panel.addWidget(self.output_box)

        bottom_section.addLayout(right_panel, 2)
        layout.addLayout(bottom_section)

        # ---- Horizontal Line ----
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet("color: #333; background-color: #333; max-height: 1px;")
        layout.addWidget(line)

        # ---- Firewall Buttons + Status at Bottom ----
        self.start_btn = QPushButton("Start Firewall")
        self.stop_btn = QPushButton("Stop Firewall")
        self.stop_btn.setEnabled(False)
        self.status_label = QLabel("Status: 🔴 INACTIVE")
        self.status_label.setFont(QFont("Bricolage Grotesque", 12, QFont.Bold))

        self.start_btn.clicked.connect(self.start_firewall)
        self.stop_btn.clicked.connect(self.stop_firewall)

        for btn in [self.start_btn, self.stop_btn]:
            btn.setStyleSheet("background-color: #cc3333; color: white; padding: 8px; border-radius: 6px;")

        fw_bar = QHBoxLayout()
        fw_bar.addWidget(self.start_btn)
        fw_bar.addWidget(self.stop_btn)
        fw_bar.addWidget(self.status_label)

        layout.addLayout(fw_bar)


    def add_rule(self):
        ip = self.ip_input.text().strip()
        action = self.action_dropdown.currentText()
        if ip:
            rule = {"src": ip, "action": action}
            self.rule_engine.add_rule(rule)
            self.output_box.append(f"✅ Rule added: {rule}")

    def remove_rule(self):
        ip = self.ip_input.text().strip()
        action = self.action_dropdown.currentText()
        rule = {"src": ip, "action": action}
        self.rule_engine.remove_rule(rule)
        self.output_box.append(f"❌ Rule removed: {rule}")

    def list_rules(self):
        self.output_box.clear()
        if not self.rule_engine.rules:
            self.output_box.append("No rules currently defined.")
        for rule in self.rule_engine.rules:
            self.output_box.append(f"{rule}")

    def start_firewall(self):
        from netfilterqueue import NetfilterQueue
        from scapy.all import IP
        import subprocess
        global firewall_active

        try:
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"], check=True)
            self.status_label.setText("Status: 🟢 ACTIVE")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            firewall_active = True

            def process(pkt):
                scapy_pkt = IP(pkt.get_payload())
                allowed = self.packet_filter.filter_packet(scapy_pkt)
                pkt.accept() if allowed else pkt.drop()
                verdict_emitter.verdict_signal.emit(self._format_packet_data(scapy_pkt, allowed))

            self.nfqueue = NetfilterQueue()
            self.nfqueue.bind(1, process)
            threading.Thread(target=self.nfqueue.run, daemon=True).start()

        except Exception as e:
            self.output_box.append(f"[Error] Could not start firewall: {str(e)}")

    def stop_firewall(self):
        import subprocess
        global firewall_active

        try:
            subprocess.call(["sudo", "iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"])
            if hasattr(self, 'nfqueue'):
                self.nfqueue.unbind()
            self.status_label.setText("Status: 🔴 INACTIVE")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)
            firewall_active = False
            self.output_box.append("🛑 Firewall stopped and unbound.")
        except Exception as e:
            self.output_box.append(f"[Error] Could not stop firewall: {str(e)}")

    def _format_packet_data(self, packet, allowed=True):
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "IP"
        sport = packet[TCP].sport if TCP in packet else packet[UDP].sport if UDP in packet else ""
        dport = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else ""
        src = packet[IP].src
        dst = packet[IP].dst
        return {
            "time": datetime.now().strftime("%H:%M:%S"),
            "proto": proto,
            "src": f"{src}:{sport}",
            "dst": f"{dst}:{dport}",
            "action": "ALLOW" if allowed else "BLOCK"
        }
    def show_logs(self):
        try:
            with open("/home/shirshxk/softwarica/prog/firewall/logs/firewall.log", "r") as f:
                content = f.read()
            self.output_box.setPlainText(content or "No logs found.")
        except Exception as e:
            self.output_box.setPlainText(f"Error reading logs: {str(e)}")

    def show_monitor(self):
        # You can replace this with live stats later
        self.output_box.setPlainText("📊 Monitor Placeholder:\n- Packets: 0\n- Blocked: 0\n- Allowed: 0")

    def clear_output(self):
        self.output_box.clear()

    @pyqtSlot(dict)
    def append_traffic_row(self, data):
        row = self.packet_table.rowCount()
        header_font = QFont("Bricolage Grotesque", 10, QFont.DemiBold)
        self.packet_table.horizontalHeader().setFont(header_font)

        self.packet_table.insertRow(row)

        color = QColor("#B22222") if data["action"] == "BLOCK" else QColor("#228B22")
        action_weight = QFont.Bold if data["action"] == "BLOCK" else QFont.Normal

        columns = ["time", "proto", "src", "dst", "action"]
        for col, key in enumerate(columns):
            item = QTableWidgetItem(data[key])

            # Apply font weights
            if key == "action":
                item.setFont(QFont("Bricolage Grotesque", 9, action_weight))
            else:
                item.setFont(QFont("Bricolage Grotesque", 9, QFont.Medium))

            item.setForeground(color)
            self.packet_table.setItem(row, col, item)

        self.packet_table.scrollToBottom()

