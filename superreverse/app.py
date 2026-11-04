"""SuperReverse application entry point and lifecycle manager."""
from __future__ import annotations

import os
import sys
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont, QIcon
from PySide6.QtWidgets import QApplication

from superreverse.ui.window import MainWindow


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    # Enable High DPI scaling
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    os.environ["QT_ENABLE_HIGHDPI_SCALING"] = "1"

    app = QApplication(sys.argv[:1])
    app.setApplicationName("SuperReverse")
    app.setOrganizationName("SuperReverse")

    window = MainWindow()

    # If file passed on command line, analyze it immediately
    if argv and len(argv) >= 1:
        target_candidate = argv[0]
        if Path(target_candidate).exists():
            window.start_analysis(target_candidate)

    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
