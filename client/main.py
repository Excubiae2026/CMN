import sys
from PyQt6.QtWidgets import QApplication
from gui import NodeGUI

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = NodeGUI()
    window.show()
    sys.exit(app.exec())
