from PyQt5.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QComboBox, QPushButton, QTextEdit, QHBoxLayout
from PyQt5.QtGui import QFont
from src.core.rule_engine import RuleEngine

class RuleManager(QWidget):
    def __init__(self):
        super().__init__()
        self.rule_engine = RuleEngine()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        self.setLayout(layout)

        title = QLabel("Advanced Rule Manager")
        title.setFont(QFont("Arial", 18, QFont.Bold))
        title.setStyleSheet("color: #B22222; padding: 10px;")
        layout.addWidget(title)

        # Rule input fields
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Enter IP Address")

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Enter Port (optional)")

        self.protocol_dropdown = QComboBox()
        self.protocol_dropdown.addItems(["", "TCP", "UDP", "IP"])

        self.direction_dropdown = QComboBox()
        self.direction_dropdown.addItems(["SRC", "DST"])

        self.action_dropdown = QComboBox()
        self.action_dropdown.addItems(["ALLOW", "BLOCK"])

        input_row_1 = QHBoxLayout()
        input_row_1.addWidget(self.ip_input)
        input_row_1.addWidget(self.port_input)

        input_row_2 = QHBoxLayout()
        input_row_2.addWidget(self.protocol_dropdown)
        input_row_2.addWidget(self.direction_dropdown)
        input_row_2.addWidget(self.action_dropdown)

        layout.addLayout(input_row_1)
        layout.addLayout(input_row_2)

        # Buttons
        button_layout = QHBoxLayout()
        add_btn = QPushButton("Add Rule")
        add_btn.clicked.connect(self.add_rule)
        remove_btn = QPushButton("Remove Rule")
        remove_btn.clicked.connect(self.remove_rule)
        refresh_btn = QPushButton("List Rules")
        refresh_btn.clicked.connect(self.display_rules)

        for btn in [add_btn, remove_btn, refresh_btn]:
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
            button_layout.addWidget(btn)

        layout.addLayout(button_layout)

        # Rule display
        self.rules_display = QTextEdit()
        self.rules_display.setReadOnly(True)
        self.rules_display.setStyleSheet("background-color: #2b2b2b; color: white; padding: 10px; border-radius: 6px;")
        layout.addWidget(self.rules_display)

        self.display_rules()

    def build_rule(self):
        rule = {}
        ip = self.ip_input.text().strip()
        port = self.port_input.text().strip()
        protocol = self.protocol_dropdown.currentText().strip().lower()
        direction = self.direction_dropdown.currentText().strip().lower()
        action = self.action_dropdown.currentText().strip().upper()

        if ip:
            rule[direction] = ip
        if port:
            try:
                rule["port"] = int(port)
            except ValueError:
                pass
        if protocol:
            rule["protocol"] = protocol

        rule["action"] = action
        return rule

    def add_rule(self):
        rule = self.build_rule()
        if rule:
            self.rule_engine.add_rule(rule)
            self.display_rules()

    def remove_rule(self):
        rule = self.build_rule()
        if rule:
            self.rule_engine.remove_rule(rule)
            self.display_rules()

    def display_rules(self):
        self.rules_display.clear()
        rules = self.rule_engine.rules
        if not rules:
            self.rules_display.setText("No rules defined.")
        else:
            for rule in rules:
                self.rules_display.append(str(rule))