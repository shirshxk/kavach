from PyQt5.QtWidgets import QApplication
from unified_main import UnifiedMain
import sys
from PyQt5.QtGui import QFont

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Bricolage Grotesque", 10))
    window = UnifiedMain()
    window.setWindowTitle("KAVACH")
    window.resize(1200, 800)
    window.show()
    sys.exit(app.exec_())
