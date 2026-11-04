"""Main Frameless Liquid-Glass Window with Drop Zone and Integrated AI Map Viewer."""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QPoint, QRectF, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QDragEnterEvent, QDropEvent, QPainter, QPainterPath
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QSizeGrip,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from superreverse.core.cli import analyze_target
from superreverse.ui import glass
from superreverse.ui.radial import RadialDialWidget
from superreverse.ui.viewer import MapViewerWidget


class AnalysisWorker(QThread):
    progress = Signal(str, int)
    finished = Signal(str, str)  # markdown_path, content
    error = Signal(str)

    def __init__(self, target_path: str):
        super().__init__()
        self.target_path = target_path

    def run(self):
        try:
            self.progress.emit("Classifying target artifact...", 20)
            self.msleep(60)

            self.progress.emit("Extracting strings, APIs and indicators...", 45)
            self.msleep(60)

            self.progress.emit("Running deep reverse engineering engines...", 70)
            self.msleep(60)

            self.progress.emit("Synthesizing AI Software Architecture Blueprint...", 90)
            out_file, content = analyze_target(self.target_path)

            self.progress.emit("Analysis Complete!", 100)
            self.finished.emit(str(out_file), content)
        except Exception as e:
            self.error.emit(str(e))


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SuperReverse — AI Software Architecture Mapper")
        self.setWindowFlags(Qt.Window | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setStyleSheet(glass.QSS)
        self.resize(1120, 720)

        self._drag_pos: Optional[QPoint] = None
        self.radius = 18
        self.active_target: Optional[Path] = None
        self.worker: Optional[AnalysisWorker] = None

        self.setAcceptDrops(True)
        self._init_ui()

    def _init_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(14, 10, 14, 12)
        outer.setSpacing(10)

        # 1. Custom Title Bar
        title_bar = QHBoxLayout()
        title_bar.setSpacing(8)

        icon_label = QLabel("⚡")
        icon_label.setStyleSheet("font-size: 14pt;")
        title_bar.addWidget(icon_label)

        title_lbl = QLabel("SuperReverse")
        title_lbl.setObjectName("title")
        title_bar.addWidget(title_lbl)

        author_lbl = QLabel("by Manish (@officialgodgoku)")
        author_lbl.setObjectName("badge")
        title_bar.addWidget(author_lbl)

        sub_lbl = QLabel("Autonomous Binary & Software AI Blueprint Mapper")
        sub_lbl.setObjectName("subtitle")
        title_bar.addWidget(sub_lbl)

        title_bar.addStretch(1)

        # Buy Me a Coffee button
        btn_coffee = QPushButton("☕ Buy Me a Coffee")
        btn_coffee.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ffdd00, stop:1 #ffb700);
                color: #000000;
                font-weight: 700;
                border-radius: 10px;
                padding: 4px 12px;
                border: 1px solid rgba(255, 255, 255, 0.4);
            }
            QPushButton:hover {
                background: #ffe642;
            }
        """)
        btn_coffee.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://buymeacoffee.com/officialgodgoku")))
        title_bar.addWidget(btn_coffee)

        # GitHub button
        btn_gh = QPushButton("🐙 GitHub")
        btn_gh.clicked.connect(lambda: QDesktopServices.openUrl(QUrl("https://github.com/officialgodgoku/SuperReverse")))
        title_bar.addWidget(btn_gh)

        btn_min = QPushButton("🗕")
        btn_min.setObjectName("chrome")
        btn_min.setToolTip("Minimize")
        btn_min.clicked.connect(self.showMinimized)
        title_bar.addWidget(btn_min)

        btn_close = QPushButton("✕")
        btn_close.setObjectName("chrome")
        btn_close.setToolTip("Close")
        btn_close.clicked.connect(self.close)
        title_bar.addWidget(btn_close)

        outer.addLayout(title_bar)

        # 2. Main Content Splitter
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.setStyleSheet("QSplitter::handle { background: rgba(255,255,255,0.08); width: 2px; }")

        # Left Panel: Drop Zone & Radial Menu
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(4, 4, 8, 4)
        left_layout.setSpacing(12)

        # Drop Zone Frame
        self.drop_frame = QFrame()
        self.drop_frame.setObjectName("dropZone")
        drop_layout = QVBoxLayout(self.drop_frame)
        drop_layout.setContentsMargins(16, 20, 16, 20)
        drop_layout.setAlignment(Qt.AlignCenter)

        self.drop_icon = QLabel("📥")
        self.drop_icon.setStyleSheet("font-size: 38pt;")
        self.drop_icon.setAlignment(Qt.AlignCenter)
        drop_layout.addWidget(self.drop_icon)

        self.drop_label = QLabel("Drag & Drop Any Software Here")
        self.drop_label.setStyleSheet("font-size: 12pt; font-weight: 600; color: #ffffff;")
        self.drop_label.setAlignment(Qt.AlignCenter)
        drop_layout.addWidget(self.drop_label)

        self.drop_hint = QLabel("Supports APK, EXE, DLL, ELF, ASAR, WASM, JAR, or Web URLs")
        self.drop_hint.setObjectName("subtitle")
        self.drop_hint.setAlignment(Qt.AlignCenter)
        drop_layout.addWidget(self.drop_hint)

        # URL Input Bar
        url_row = QHBoxLayout()
        url_row.setSpacing(6)
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("🌐 Enter or paste Website URL...")
        self.url_input.returnPressed.connect(self._on_url_submitted)
        url_row.addWidget(self.url_input, 1)

        btn_url = QPushButton("Analyze URL")
        btn_url.clicked.connect(self._on_url_submitted)
        url_row.addWidget(btn_url)
        drop_layout.addLayout(url_row)

        btn_browse = QPushButton("📂 Browse File...")
        btn_browse.clicked.connect(self._browse_file)
        drop_layout.addWidget(btn_browse, alignment=Qt.AlignCenter)

        left_layout.addWidget(self.drop_frame, 1)

        # Radial Dial Action Hub
        self.radial_dial = RadialDialWidget(self, size=320)
        self.radial_dial.action_selected.connect(self._on_radial_action)
        left_layout.addWidget(self.radial_dial, alignment=Qt.AlignCenter)

        # Progress Section
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.hide()
        left_layout.addWidget(self.progress_bar)

        self.status_lbl = QLabel("")
        self.status_lbl.setObjectName("subtitle")
        self.status_lbl.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(self.status_lbl)

        self.splitter.addWidget(left_panel)

        # Right Panel: Interactive Map Viewer
        self.viewer = MapViewerWidget()
        self.splitter.addWidget(self.viewer)

        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 6)

        outer.addWidget(self.splitter, 1)

        # Bottom Bar with SizeGrip and Credits
        bot_bar = QHBoxLayout()
        credit_lbl = QLabel("Created with 💖 by <b>Manish</b> (<a href='https://github.com/officialgodgoku' style='color:#5ac8ff;'>@officialgodgoku</a>) • Free & Open Source")
        credit_lbl.setOpenExternalLinks(True)
        credit_lbl.setObjectName("subtitle")
        bot_bar.addWidget(credit_lbl)

        bot_bar.addStretch(1)
        grip = QSizeGrip(self)
        grip.setFixedSize(14, 14)
        bot_bar.addWidget(grip)
        outer.addLayout(bot_bar)

    def _on_url_submitted(self):
        url = self.url_input.text().strip()
        if url:
            self.start_analysis(url)

    def _browse_file(self):
        target, _ = QFileDialog.getOpenFileName(
            self,
            "Select Software to Analyze",
            "",
            "All Supported (*.apk *.aab *.exe *.dll *.so *.asar *.jar *.wasm *.elf *.url);;Android APK (*.apk *.aab);;Windows Executable (*.exe *.dll);;Electron ASAR (*.asar);;Internet Shortcut (*.url);;All Files (*.*)",
        )
        if target:
            self.start_analysis(target)

    def start_analysis(self, target_str: str):
        target_str = target_str.strip()
        if not target_str:
            return

        is_url = target_str.startswith(("http://", "https://", "www.")) or (
            "." in target_str and "/" not in target_str and "\\" not in target_str
        )

        if not is_url:
            p = Path(target_str).resolve()
            if not p.exists():
                return
            display_name = p.name
            self.active_target = p
        else:
            display_name = target_str
            self.active_target = target_str

        self.drop_label.setText(display_name)
        self.radial_dial.set_target(display_name)

        self.progress_bar.show()
        self.progress_bar.setValue(10)
        self.status_lbl.setText("Starting Autonomous Analysis Pipeline...")

        self.worker = AnalysisWorker(str(target_str))
        self.worker.progress.connect(self._on_progress)
        self.worker.finished.connect(self._on_finished)
        self.worker.error.connect(self._on_error)
        self.worker.start()

    def _on_progress(self, msg: str, val: int):
        self.status_lbl.setText(msg)
        self.progress_bar.setValue(val)

    def _on_finished(self, out_file: str, content: str):
        self.status_lbl.setText(f"✅ Generated: {Path(out_file).name}")
        self.progress_bar.setValue(100)
        self.viewer.load_markdown(out_file, content)

    def _on_error(self, err_msg: str):
        self.status_lbl.setText(f"❌ Error: {err_msg}")
        self.progress_bar.hide()

    def _on_radial_action(self, action_id: str):
        if not self.active_target:
            self._browse_file()
            return

        if action_id == "ai_map":
            self.start_analysis(str(self.active_target))
        elif action_id == "copy_prompt":
            self.viewer._copy_for_ai()
        elif action_id == "security":
            self.viewer.tabs.setCurrentIndex(0)
        elif action_id == "strings":
            self.viewer.tabs.setCurrentIndex(0)
        elif action_id in ("unpack", "decompile"):
            # Trigger JADX / APKTool if APK
            from superreverse.analyzers.rea_bridge import REABridge
            bridge = REABridge()
            if self.active_target.suffix.lower() == ".apk":
                out_dir = self.active_target.parent / f"{self.active_target.stem}_decompiled"
                self.status_lbl.setText("Running decompilation...")
                if action_id == "decompile":
                    bridge.run_jadx_decompile(self.active_target, out_dir)
                else:
                    bridge.run_apktool_decode(self.active_target, out_dir)
                self.status_lbl.setText(f"Decompiled to {out_dir.name}")

    # Drag and Drop handlers
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls() or event.mimeData().hasText():
            event.acceptProposedAction()
            self.drop_frame.setProperty("active", True)
            self.drop_frame.setStyle(self.drop_frame.style())
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.drop_frame.setProperty("active", False)
        self.drop_frame.setStyle(self.drop_frame.style())

    def dropEvent(self, event: QDropEvent):
        self.drop_frame.setProperty("active", False)
        self.drop_frame.setStyle(self.drop_frame.style())

        if event.mimeData().hasUrls():
            urls = event.mimeData().urls()
            if urls:
                path = urls[0].toLocalFile()
                if path:
                    self.start_analysis(path)
                    event.acceptProposedAction()
                    return
                elif urls[0].toString():
                    self.start_analysis(urls[0].toString())
                    event.acceptProposedAction()
                    return

        if event.mimeData().hasText():
            text = event.mimeData().text().strip()
            if text:
                self.start_analysis(text)
                event.acceptProposedAction()

    # Frameless window dragging
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton and event.position().y() < 50:
            self._drag_pos = event.globalPosition().toPoint() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if self._drag_pos and event.buttons() & Qt.LeftButton:
            self.move(event.globalPosition().toPoint() - self._drag_pos)
            event.accept()

    def mouseReleaseEvent(self, event):
        self._drag_pos = None

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        path = QPainterPath()
        path.addRoundedRect(QRectF(1, 1, self.width() - 2, self.height() - 2), self.radius, self.radius)
        glass.paint_liquid_glass(p, path, tint=QColor(16, 14, 24, 235), rim=True, rainbow_alpha=200)
