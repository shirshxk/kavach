#!/usr/bin/env -S PYTHONWARNINGS=ignore python3
from PyQt5.QtWidgets import QApplication
from unified_main import UnifiedMain
import sys
from PyQt5.QtGui import QFont
import os
if "XDG_RUNTIME_DIR" not in os.environ:
    os.environ["XDG_RUNTIME_DIR"] = f"/tmp/runtime-{os.getuid()}"

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setFont(QFont("Bricolage Grotesque", 10))
    window = UnifiedMain()
    window.setWindowTitle("KAVACH")
    window.resize(1200, 800)
    window.show()
    sys.exit(app.exec_())
