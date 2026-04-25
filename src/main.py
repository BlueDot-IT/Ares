import sys
from pathlib import Path
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QMainWindow

from ui.config import ConfigLayout
from ui.layout_switcher import LayoutSwitcher
from ui.scan import ScanLayout

from lib.orchestrator import Orchestrator

class PentestAgent(QApplication):
    def __init__(self, sys_argv):
        super().__init__(sys_argv)
        self.window = QMainWindow()
        self.window.setWindowTitle("Ares")
        self.window.setFixedSize(900, 600)
        self.switcher = LayoutSwitcher()
        self.options = {}
        self.orchestrator = Orchestrator()
        self._setup_ui()
        self.aboutToQuit.connect(self._on_about_to_quit)

    def _setup_ui(self):
        config_layout = ConfigLayout(set_options=self.save_config)
        self.scan_layout = ScanLayout(
            options_getter=self.get_options,
            run_scan=self.orchestrator.run_scan,
        )

        self.switcher.add_layout("config", config_layout)
        self.switcher.add_layout("scan", self.scan_layout)
        self.switcher.set_active("config")

        self.window.setCentralWidget(self.switcher)
        self.window.show()
    
    def set_option(self, key, value):
        self.options[key] = value
    def set_options(self, options_dict):
        self.options.update(options_dict)
    def get_options(self):
        return self.options
    def get_option(self, key):
        return self.options.get(key)
    
    def save_config(self, config):
        self.set_options(config)
        self.scan_layout.refresh_options()
        self.switcher.set_active("scan")
        QTimer.singleShot(0, self.scan_layout.start_scan)

    def _on_about_to_quit(self):
        self.scan_layout.stop_scan()



if __name__ == "__main__":
    app = PentestAgent(sys.argv)
    sys.exit(app.exec())
