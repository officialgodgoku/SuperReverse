"""Interactive Markdown and AI Architecture Map Viewer.

Renders rich HTML styling for markdown blueprints, tables, code blocks,
and provides one-click AI prompt export and Explorer reveal.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Optional

import markdown
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QClipboard, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from superreverse.analyzers.rea_bridge import REABridge

HTML_STYLE = """
<style>
body {
    background-color: transparent;
    color: #e0e0e0;
    font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    line-height: 1.6;
    padding: 10px 18px;
}
h1, h2, h3, h4 {
    color: #ffffff;
    font-weight: 600;
}
h1 {
    font-size: 19pt;
    border-bottom: 2px solid rgba(0, 240, 255, 0.4);
    padding-bottom: 6px;
    margin-top: 5px;
}
h2 {
    font-size: 14pt;
    border-bottom: 1px solid rgba(255, 255, 255, 0.15);
    padding-bottom: 4px;
    margin-top: 22px;
    color: #5ac8ff;
}
h3 {
    font-size: 11pt;
    color: #ff9cfb;
    margin-top: 14px;
}
blockquote {
    border-left: 4px solid #00f0ff;
    margin: 8px 0;
    padding: 6px 12px;
    background: rgba(0, 240, 255, 0.08);
    border-radius: 4px;
    color: #d0f0ff;
}
table {
    border-collapse: collapse;
    width: 100%;
    margin: 12px 0;
    background: rgba(255, 255, 255, 0.03);
    border-radius: 8px;
    overflow: hidden;
}
th, td {
    padding: 8px 12px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    text-align: left;
}
th {
    background: rgba(255, 255, 255, 0.08);
    color: #ffffff;
    font-weight: 600;
}
code {
    font-family: "Consolas", "Cascadia Code", monospace;
    background: rgba(255, 255, 255, 0.1);
    padding: 2px 5px;
    border-radius: 4px;
    color: #00f0ff;
}
pre {
    background: rgba(10, 8, 16, 0.85);
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-radius: 8px;
    padding: 10px;
    overflow-x: auto;
}
pre code {
    background: transparent;
    padding: 0;
    color: #7df5ff;
}
hr {
    border: none;
    border-top: 1px solid rgba(255, 255, 255, 0.12);
    margin: 20px 0;
}
ul, ol {
    padding-left: 20px;
}
li {
    margin-bottom: 4px;
}
</style>
"""


class MapViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.markdown_path: Optional[Path] = None
        self.raw_content: str = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # Action Bar
        action_bar = QHBoxLayout()
        action_bar.setSpacing(8)

        self.btn_copy_prompt = QPushButton("📋 Copy for AI Prompt")
        self.btn_copy_prompt.setObjectName("primary")
        self.btn_copy_prompt.clicked.connect(self._copy_for_ai)
        action_bar.addWidget(self.btn_copy_prompt)

        self.btn_reveal = QPushButton("📁 Reveal in Explorer")
        self.btn_reveal.clicked.connect(self._reveal_in_explorer)
        action_bar.addWidget(self.btn_reveal)

        self.btn_save_as = QPushButton("💾 Save As...")
        self.btn_save_as.clicked.connect(self._save_as)
        action_bar.addWidget(self.btn_save_as)

        action_bar.addStretch(1)

        self.status_pill = QLabel("Ready")
        self.status_pill.setObjectName("badge")
        action_bar.addWidget(self.status_pill)

        layout.addLayout(action_bar)

        # Tab Widget
        self.tabs = QTabWidget()

        # Tab 1: Rendered HTML Map
        self.browser = QTextBrowser()
        self.browser.setOpenExternalLinks(True)
        self.tabs.addTab(self.browser, "🗺️ Visual Blueprint")

        # Tab 2: Raw Markdown Editor
        self.editor = QPlainTextEdit()
        self.tabs.addTab(self.editor, "📝 Raw Markdown")

        # Tab 3: Tool Readiness
        self.tools_panel = QTextBrowser()
        self.tabs.addTab(self.tools_panel, "🛠️ REA Environment")

        layout.addWidget(self.tabs, 1)

        self._refresh_tools_panel()

    def load_markdown(self, file_path: Path | str, content: str):
        self.markdown_path = Path(file_path)
        self.raw_content = content

        self.editor.setPlainText(content)

        # Convert markdown to HTML
        html_body = markdown.markdown(content, extensions=["tables", "fenced_code"])
        full_html = f"<!DOCTYPE html><html><head>{HTML_STYLE}</head><body>{html_body}</body></html>"
        self.browser.setHtml(full_html)

        self.status_pill.setText(f"Generated: {self.markdown_path.name}")

    def _copy_for_ai(self):
        clipboard = QGuiApplication.clipboard()
        # Find AI Prompt section if possible, else copy whole file
        if "## 7. AI Agent Navigation & Prompt Context" in self.raw_content:
            parts = self.raw_content.split("## 7. AI Agent Navigation & Prompt Context")
            text_to_copy = "## 7. AI Agent Navigation & Prompt Context" + parts[1].split("---")[0]
        else:
            text_to_copy = self.raw_content

        clipboard.setText(text_to_copy)
        self.status_pill.setText("✅ AI Prompt Copied to Clipboard!")

    def _reveal_in_explorer(self):
        if not self.markdown_path or not self.markdown_path.exists():
            return
        if sys.platform == "win32":
            subprocess.run(["explorer", f"/select,{str(self.markdown_path)}"])
        elif sys.platform == "darwin":
            subprocess.run(["open", "-R", str(self.markdown_path)])
        else:
            subprocess.run(["xdg-open", str(self.markdown_path.parent)])

    def _save_as(self):
        if not self.raw_content:
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Save AI Map", str(self.markdown_path or "AI_MAP.md"), "Markdown (*.md)")
        if dest:
            with open(dest, "w", encoding="utf-8") as f:
                f.write(self.raw_content)
            self.status_pill.setText(f"Saved: {Path(dest).name}")

    def _refresh_tools_panel(self):
        readiness = REABridge.check_readiness()
        lines = [
            "# REA & Reverse Engineering Environment Status\n",
            "| Tool | Status | Version | Capabilities |",
            "| :--- | :---: | :--- | :--- |",
            f"| **REA CLI** | {'🟢 Available' if readiness.rea_available else '⚪ Not Found'} | `{readiness.rea_version or 'N/A'}` | Go/Rust audit, Native disasm, JS AST |",
            f"| **JADX Decompiler** | {'🟢 Available' if readiness.jadx_available else '⚪ Not Found'} | `{readiness.jadx_version or 'N/A'}` | Java decompilation from DEX/APK |",
            f"| **APKTool** | {'🟢 Available' if readiness.apktool_available else '⚪ Not Found'} | `{readiness.apktool_version or 'N/A'}` | Resource decoding, smali disassembly |",
            f"| **Frida Dynamic CLI** | {'🟢 Available' if readiness.frida_available else '⚪ Not Found'} | `{readiness.frida_version or 'N/A'}` | Dynamic hooking, SSL unpinning, trace |",
            f"| **Python Host** | 🟢 Available | `{sys.version.split()[0]}` | PySide6 GUI, pefile, AXML parser |",
        ]
        html_body = markdown.markdown("\n".join(lines), extensions=["tables"])
        self.tools_panel.setHtml(f"<!DOCTYPE html><html><head>{HTML_STYLE}</head><body>{html_body}</body></html>")
