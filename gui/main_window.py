# gui/main_window.py
from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QLabel, QHBoxLayout, QStackedLayout, QPushButton
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from gui.rule_manager import RuleManager
from gui.sniffer_view import SnifferView
from gui.logs_viewer import LogsViewer

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Kavach Firewall GUI")
        self.setGeometry(200, 100, 1200, 700)
        self.setStyleSheet("background-color: #1e1e1e; color: white;")

        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QHBoxLayout()
        central_widget.setLayout(layout)

        # Sidebar
        self.sidebar = self.create_sidebar()
        layout.addWidget(self.sidebar, 1)

        # Main display panel
        self.stack = QStackedLayout()
        main_panel = QWidget()
        main_panel.setLayout(self.stack)
        layout.addWidget(main_panel, 4)

        # Panels from external files
        self.rule_manager_panel = RuleManager()
        self.sniffer_panel = SnifferView()
        self.logs_panel = LogsViewer()

        self.stack.addWidget(self.rule_manager_panel)
        self.stack.addWidget(self.sniffer_panel)
        self.stack.addWidget(self.logs_panel)

    def create_sidebar(self):
        sidebar = QWidget()
        layout = QVBoxLayout()
        sidebar.setLayout(layout)
        sidebar.setStyleSheet("background-color: #B22222;")

        title = QLabel("Kavach")
        title.setAlignment(Qt.AlignCenter)
        title.setFont(QFont("Arial", 22, QFont.Bold))
        title.setStyleSheet("color: white; padding: 20px;")
        layout.addWidget(title)

        btn_rule_manager = QPushButton("Manage Rules")
        btn_rule_manager.clicked.connect(lambda: self.stack.setCurrentWidget(self.rule_manager_panel))

        btn_sniffer = QPushButton("Live Traffic")
        btn_sniffer.clicked.connect(lambda: self.stack.setCurrentWidget(self.sniffer_panel))

        btn_logs = QPushButton("View Logs")
        btn_logs.clicked.connect(lambda: self.stack.setCurrentWidget(self.logs_panel))

        for btn in [btn_rule_manager, btn_sniffer, btn_logs]:
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #8B1A1A;
                    color: white;
                    font-size: 16px;
                    padding: 12px;
                    border-radius: 8px;
                    margin: 8px;
                }
                QPushButton:hover {
                    background-color: #A52A2A;
                }
            """)
            layout.addWidget(btn)

        layout.addStretch()
        return sidebar