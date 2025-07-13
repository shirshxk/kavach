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
from netfilterqueue import NetfilterQueue
import subprocess

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

        self.total_packets = 0
        self.total_allowed = 0
        self.total_blocked = 0

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
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Source Port")
        self.action_dropdown = QComboBox()
        self.action_dropdown.addItems(["ALLOW", "BLOCK"])
        add_btn = QPushButton("Add Rule")
        remove_btn = QPushButton("Remove Rule")
        list_btn = QPushButton("List Rules")
        

        add_btn.clicked.connect(self.add_rule)
        remove_btn.clicked.connect(self.remove_rule)
        list_btn.clicked.connect(self.list_rules)

        rule_bar.addWidget(self.ip_input)
        rule_bar.addWidget(self.port_input)
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
        self.logs_btn = QPushButton("View Logs")
        self.clear_btn = QPushButton("Clear Logs")

        for btn in [self.logs_btn, self.clear_btn]:
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

        # --- Styled Traffic Monitor Labels ---
        self.packet_count_label = self._create_monitor_box("Total Packets", "0", "#5A5A5A")
        self.blocked_count_label = self._create_monitor_box("Total Blocked", "0", "#D22222")
        self.allowed_count_label = self._create_monitor_box("Total Allowed", "0", "#43A047")
        self.monitor_container = QHBoxLayout()
        self.monitor_container.addWidget(self.packet_count_label)
        self.monitor_container.addWidget(self.blocked_count_label)
        self.monitor_container.addWidget(self.allowed_count_label)

        right_panel.addLayout(self.monitor_container)

        self.logs_btn.clicked.connect(self.show_logs)
        self.clear_btn.clicked.connect(self.clear_output)
        switch_bar.addWidget(self.logs_btn)
        switch_bar.addWidget(self.clear_btn)
        right_panel.addLayout(switch_bar)

        # --- Output Text Box ---
        self.output_box = QTextEdit()
        self.output_box.setReadOnly(True)
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
        red_button_style = """
            QPushButton {
                background-color: #B22222;
                color: white;
                padding: 8px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #e53935;
            }
        """
        for btn in [add_btn, remove_btn, list_btn, self.start_btn, self.stop_btn]:
            btn.setStyleSheet(red_button_style)

        self.start_btn.clicked.connect(self.start_firewall)
        self.stop_btn.clicked.connect(self.stop_firewall)

        fw_bar = QHBoxLayout()
        fw_bar.addWidget(self.start_btn)
        fw_bar.addWidget(self.stop_btn)
        fw_bar.addStretch(1)
        status_container = QHBoxLayout()
        status_container.addStretch()
        status_container.addWidget(self.status_label)
        status_container.addStretch()

        fw_bar.addLayout(status_container)
        layout.addLayout(fw_bar)


    def add_rule(self):
        ip = self.ip_input.text().strip()
        port = self.port_input.text().strip()
        action = self.action_dropdown.currentText()

        # Allow both fields to be optional, but at least one must be provided
        if not ip and not port:
            self.output_box.append("❌ Please enter at least an IP or Port.")
            return

        # Validate IP if given
        if ip and not Helper.validate_ip_or_subnet_with_optional_port(ip):
            self.output_box.append("❌ Invalid IP or subnet format.")
            return

        # Validate port if given
        if port:
            try:
                Helper.parse_ports(port)
            except Exception:
                self.output_box.append("❌ Invalid port number.")
                return

        # Build rule
        rule = {"action": action}
        if ip:
            rule["src"] = ip
        if port:
            rule["sport"] = int(port)

        self.rule_engine.add_rule(rule)
        self.output_box.append(f"✅ Rule added: {rule}")


    def remove_rule(self):
        ip = self.ip_input.text().strip()
        port = self.port_input.text().strip()
        action = self.action_dropdown.currentText()

        rule = {"action": action}
        if ip:
            rule["src"] = ip
        if port:
            rule["sport"] = int(port)

        self.rule_engine.remove_rule(rule)
        self.output_box.append(f"❌ Rule removed: {rule}")

    def list_rules(self):
        self.output_box.clear()
        if not self.rule_engine.rules:
            self.output_box.append("No rules currently defined.")
        for rule in self.rule_engine.rules:
            self.output_box.append(f"{rule}")


    def start_firewall(self):
        global firewall_active

        try:
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "1"], check=True)
            self.status_label.setText("Status: 🟢🔴 ACTIVE")
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

    def _create_monitor_box(self, title, count, color):
        box = QWidget()
        layout = QVBoxLayout()
        layout.setAlignment(Qt.AlignCenter)

        title_label = QLabel(title)
        title_label.setFont(QFont("Bricolage Grotesque", 10, QFont.Bold))
        title_label.setStyleSheet("color: white;")

        count_label = QLabel(count)
        count_label.setFont(QFont("Bricolage Grotesque", 20, QFont.Bold))
        count_label.setStyleSheet(f"background-color: {color}; color: white; padding: 10px; border-radius: 10px;")
        count_label.setAlignment(Qt.AlignCenter)

        layout.addWidget(title_label)
        layout.addWidget(count_label)
        box.setLayout(layout)
        box.count_label = count_label  
        return box
    
    def clear_output(self):
        self.output_box.clear()

    @pyqtSlot(dict)
    def append_traffic_row(self, data):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)

        self.total_packets += 1
        if data["action"] == "BLOCK":
            self.total_blocked += 1
        else:
            self.total_allowed += 1

        self.packet_count_label.count_label.setText(str(self.total_packets))
        self.blocked_count_label.count_label.setText(str(self.total_blocked))
        self.allowed_count_label.count_label.setText(str(self.total_allowed))

        self.packet_table.setItem(row, 0, QTableWidgetItem(data["time"]))
        self.packet_table.setItem(row, 1, QTableWidgetItem(data["proto"]))
        self.packet_table.setItem(row, 2, QTableWidgetItem(data["src"]))
        self.packet_table.setItem(row, 3, QTableWidgetItem(data["dst"]))
        self.packet_table.setItem(row, 4, QTableWidgetItem(data["action"]))

        # Apply color
        color = QColor("#B22222") if data["action"] == "BLOCK" else QColor("#228B22")
        for col in range(5):
            self.packet_table.item(row, col).setForeground(color)

        self.packet_table.scrollToBottom()
