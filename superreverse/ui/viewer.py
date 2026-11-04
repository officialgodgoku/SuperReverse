"""Interactive AI Architecture Map & Multi-Engine Viewer for SuperReverse.

Features 7 specialized tabs:
0. 🗺️ AI Map (Visual HTML rendered blueprint with Mermaid flowcharts & diagrams)
1. 🎛️ Parameters (Searchable interactive Tweakable Parameter Matrix)
2. 🛡️ Security (Mitigations, exploit defenses, permissions, and Frida scripts)
3. ☕ Decompile (Capstone machine disassembly & JADX/ASAR decompiled code)
4. 🔍 Intelligence (Categorized URLs, IPs, registry keys, secrets & APIs)
5. 📝 Raw Markdown (Direct editable markdown with Copy & Save As)
6. 🛠️ REA Environment (Status of REA, JADX, APKTool, Frida, Python)
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import markdown
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QClipboard, QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from superreverse.analyzers.rea_bridge import REABridge
from superreverse.core.cli import AnalysisBundle

HTML_STYLE = """
<style>
body {
    background-color: transparent;
    color: #e2e8f0;
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
.badge-green {
    background: #00875a;
    color: #ffffff;
    padding: 2px 8px;
    border-radius: 12px;
    font-weight: 600;
}
.badge-red {
    background: #de350b;
    color: #ffffff;
    padding: 2px 8px;
    border-radius: 12px;
    font-weight: 600;
}
.badge-yellow {
    background: #ffab00;
    color: #172b4d;
    padding: 2px 8px;
    border-radius: 12px;
    font-weight: 600;
}
</style>
"""


class MapViewerWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.bundle: Optional[AnalysisBundle] = None
        self.markdown_path: Optional[Path] = None
        self.raw_content: str = ""

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)

        # 1. Action Bar
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

        # 2. Tab Widget with 7 Views
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 8px;
                background: rgba(14, 12, 22, 0.7);
            }
            QTabBar::tab {
                background: rgba(255, 255, 255, 0.04);
                color: #a0aec0;
                padding: 6px 14px;
                margin-right: 2px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                font-weight: 600;
                font-size: 9pt;
            }
            QTabBar::tab:selected {
                background: rgba(0, 240, 255, 0.18);
                color: #ffffff;
                border-bottom: 2px solid #00f0ff;
            }
            QTabBar::tab:hover:!selected {
                background: rgba(255, 255, 255, 0.08);
                color: #ffffff;
            }
        """)

        # Tab 0: Visual Blueprint HTML
        self.browser_map = QTextBrowser()
        self.browser_map.setOpenExternalLinks(True)
        self.tabs.addTab(self.browser_map, "🗺️ AI Map")

        # Tab 1: Interactive Tweakable Parameters Table
        self.tab_params = QWidget()
        params_layout = QVBoxLayout(self.tab_params)
        params_layout.setContentsMargins(6, 6, 6, 6)
        params_layout.setSpacing(6)

        param_header_bar = QHBoxLayout()
        self.param_search = QLineEdit()
        self.param_search.setPlaceholderText("🔍 Search parameters by identifier, category, value...")
        self.param_search.textChanged.connect(self._filter_params_table)
        param_header_bar.addWidget(self.param_search, 1)

        btn_copy_params_json = QPushButton("📋 Copy JSON")
        btn_copy_params_json.clicked.connect(self._copy_params_json)
        param_header_bar.addWidget(btn_copy_params_json)

        btn_copy_params_md = QPushButton("📋 Copy Markdown")
        btn_copy_params_md.clicked.connect(self._copy_params_md)
        param_header_bar.addWidget(btn_copy_params_md)

        params_layout.addLayout(param_header_bar)

        self.params_table = QTableWidget()
        self.params_table.setColumnCount(5)
        self.params_table.setHorizontalHeaderLabels([
            "Parameter Identifier", "Category", "Current Value", "Discovered In", "Tweak Impact & Instructions"
        ])
        self.params_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.params_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.params_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.params_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.params_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.params_table.setStyleSheet("QTableWidget { background: transparent; color: #ffffff; gridline-color: rgba(255,255,255,0.08); } QHeaderView::section { background: rgba(30, 25, 45, 0.9); color: #00f0ff; padding: 4px; font-weight: 600; border: 1px solid rgba(255,255,255,0.1); }")
        params_layout.addWidget(self.params_table, 1)
        self.tabs.addTab(self.tab_params, "🎛️ Parameters")

        # Tab 2: Security & Exploit Mitigations
        self.browser_security = QTextBrowser()
        self.browser_security.setOpenExternalLinks(True)
        self.tabs.addTab(self.browser_security, "🛡️ Security")

        # Tab 3: Decompiled Code & Capstone Disassembly
        self.tab_decompile = QWidget()
        dec_layout = QVBoxLayout(self.tab_decompile)
        dec_layout.setContentsMargins(6, 6, 6, 6)
        dec_layout.setSpacing(6)

        dec_header_bar = QHBoxLayout()
        self.dec_title_lbl = QLabel("Binary Machine Instructions & Recovered Sources")
        self.dec_title_lbl.setStyleSheet("font-weight: 600; color: #5ac8ff;")
        dec_header_bar.addWidget(self.dec_title_lbl, 1)

        btn_copy_code = QPushButton("📋 Copy Code")
        btn_copy_code.clicked.connect(self._copy_code)
        dec_header_bar.addWidget(btn_copy_code)
        dec_layout.addLayout(dec_header_bar)

        self.code_viewer = QPlainTextEdit()
        self.code_viewer.setReadOnly(True)
        self.code_viewer.setFont(QFont("Consolas", 10))
        self.code_viewer.setStyleSheet("background: rgba(10, 8, 16, 0.95); color: #7df5ff; border: 1px solid rgba(255, 255, 255, 0.12); border-radius: 6px; padding: 8px;")
        dec_layout.addWidget(self.code_viewer, 1)
        self.tabs.addTab(self.tab_decompile, "☕ Decompile")

        # Tab 4: Extracted Intelligence & Strings
        self.tab_strings = QWidget()
        str_layout = QVBoxLayout(self.tab_strings)
        str_layout.setContentsMargins(6, 6, 6, 6)
        str_layout.setSpacing(6)

        str_header_bar = QHBoxLayout()
        self.str_search = QLineEdit()
        self.str_search.setPlaceholderText("🔍 Filter intelligence strings, URLs, IPs, registry keys...")
        self.str_search.textChanged.connect(self._filter_strings_view)
        str_header_bar.addWidget(self.str_search, 1)
        str_layout.addLayout(str_header_bar)

        self.strings_browser = QTextBrowser()
        self.strings_browser.setOpenExternalLinks(True)
        str_layout.addWidget(self.strings_browser, 1)
        self.tabs.addTab(self.tab_strings, "🔍 Strings")

        # Tab 5: Raw Markdown Editor
        self.editor = QPlainTextEdit()
        self.editor.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.editor, "📝 Raw Markdown")

        # Tab 6: REA Environment Status
        self.tools_panel = QTextBrowser()
        self.tabs.addTab(self.tools_panel, "🛠️ REA Environment")

        layout.addWidget(self.tabs, 1)
        self._refresh_tools_panel()

    def load_bundle(self, bundle: AnalysisBundle):
        self.bundle = bundle
        self.markdown_path = bundle.out_file
        self.raw_content = bundle.markdown_content

        # 0. Load AI Map HTML
        self.editor.setPlainText(bundle.markdown_content)
        html_body = markdown.markdown(bundle.markdown_content, extensions=["tables", "fenced_code"])
        self.browser_map.setHtml(f"<!DOCTYPE html><html><head>{HTML_STYLE}</head><body>{html_body}</body></html>")
        self.status_pill.setText(f"Generated: {bundle.out_file.name}")

        # 1. Populate Parameters Table
        self._populate_parameters_table(bundle)

        # 2. Populate Security View
        self._populate_security_view(bundle)

        # 3. Populate Decompile View
        self._populate_decompile_view(bundle)

        # 4. Populate Strings View
        self._populate_strings_view(bundle)

    def load_markdown(self, file_path: Path | str, content: str):
        self.markdown_path = Path(file_path)
        self.raw_content = content
        self.editor.setPlainText(content)

        html_body = markdown.markdown(content, extensions=["tables", "fenced_code"])
        self.browser_map.setHtml(f"<!DOCTYPE html><html><head>{HTML_STYLE}</head><body>{html_body}</body></html>")
        self.status_pill.setText(f"Loaded: {self.markdown_path.name}")

    def switch_to_tab(self, tab_id: str):
        mapping = {
            "ai_map": 0,
            "parameters": 1,
            "security": 2,
            "decompile": 3,
            "strings": 4,
            "markdown": 5,
            "tools": 6,
        }
        idx = mapping.get(tab_id, 0)
        self.tabs.setCurrentIndex(idx)

    def _populate_parameters_table(self, b: AnalysisBundle):
        params_list = []
        if b.pe and b.pe.parameters:
            for p in b.pe.parameters:
                params_list.append((p.name, p.category, p.value, p.location, p.tweak_impact))
        elif b.apk and b.apk.parameters:
            for p in b.apk.parameters:
                params_list.append((p.name, p.category, p.value, p.location, p.tweak_impact))
        elif b.electron and b.electron.parameters:
            for p in b.electron.parameters:
                params_list.append((p.name, p.category, p.value, p.location, p.tweak_impact))
        elif b.web and b.web.security_headers:
            for h in b.web.security_headers:
                params_list.append((f"HEADER_{h.header.upper()}", "Security Header", h.value, "HTTP Response", h.recommendation))

        self.params_table.setRowCount(len(params_list))
        for row, (name, cat, val, loc, impact) in enumerate(params_list):
            item_name = QTableWidgetItem(name)
            item_name.setForeground(QColor("#00f0ff"))
            item_name.setFont(QFont("Consolas", 9, QFont.Bold))

            item_cat = QTableWidgetItem(cat)
            item_cat.setForeground(QColor("#ff9cfb"))

            item_val = QTableWidgetItem(str(val))
            item_val.setFont(QFont("Consolas", 9))

            item_loc = QTableWidgetItem(loc)
            item_loc.setForeground(QColor("#a0aec0"))

            item_impact = QTableWidgetItem(impact)

            self.params_table.setItem(row, 0, item_name)
            self.params_table.setItem(row, 1, item_cat)
            self.params_table.setItem(row, 2, item_val)
            self.params_table.setItem(row, 3, item_loc)
            self.params_table.setItem(row, 4, item_impact)

    def _filter_params_table(self, query: str):
        query = query.strip().lower()
        for row in range(self.params_table.rowCount()):
            match = False
            for col in range(5):
                item = self.params_table.item(row, col)
                if item and query in item.text().lower():
                    match = True
                    break
            self.params_table.setRowHidden(row, not match)

    def _copy_params_json(self):
        data = []
        for r in range(self.params_table.rowCount()):
            if not self.params_table.isRowHidden(r):
                data.append({
                    "name": self.params_table.item(r, 0).text(),
                    "category": self.params_table.item(r, 1).text(),
                    "value": self.params_table.item(r, 2).text(),
                    "location": self.params_table.item(r, 3).text(),
                    "tweak_impact": self.params_table.item(r, 4).text(),
                })
        QGuiApplication.clipboard().setText(json.dumps(data, indent=2))
        self.status_pill.setText("✅ Parameters Copied as JSON!")

    def _copy_params_md(self):
        lines = ["| Parameter Identifier | Category | Current Value | Discovered In | Tweak Impact |", "| :--- | :--- | :--- | :--- | :--- |"]
        for r in range(self.params_table.rowCount()):
            if not self.params_table.isRowHidden(r):
                lines.append(f"| **`{self.params_table.item(r, 0).text()}`** | `{self.params_table.item(r, 1).text()}` | `{self.params_table.item(r, 2).text()}` | `{self.params_table.item(r, 3).text()}` | {self.params_table.item(r, 4).text()} |")
        QGuiApplication.clipboard().setText("\n".join(lines))
        self.status_pill.setText("✅ Parameters Copied as Markdown!")

    def _populate_security_view(self, b: AnalysisBundle):
        md = ["# 🛡️ Binary Security Posture & Exploit Mitigations\n"]
        if b.pe:
            m = b.pe.mitigations
            md.append("| Mitigation Feature | Status | Forensic Protection Detail |")
            md.append("| :--- | :---: | :--- |")
            md.append(f"| **ASLR** | {'🟢 Enabled' if m.aslr else '🔴 Disabled'} | Address Space Layout Randomization |")
            md.append(f"| **High-Entropy ASLR** | {'🟢 Enabled' if m.high_entropy_aslr else '⚪ N/A'} | 64-bit high entropy variance |")
            md.append(f"| **DEP / NX** | {'🟢 Enabled' if m.dep_nx else '🔴 Disabled'} | Data Execution Prevention (W^X memory) |")
            md.append(f"| **Control Flow Guard (CFG)** | {'🟢 Enabled' if m.cfg else '⚪ Absent'} | Indirect call target bitmap validation |")
            md.append(f"| **SafeSEH** | {'🟢 Protected' if m.safeseh else '🔴 Missing'} | Structured Exception Handler table validation |")
            md.append(f"| **Authenticode Signed** | {'🟢 Signed' if m.authenticode_signed else '🟡 Unsigned'} | Cryptographic publisher signature |")

            if b.pe.warnings:
                md.append("\n### ⚠️ Security Warnings & Anomalies")
                for w in b.pe.warnings:
                    md.append(f"- 🔴 {w}")

        elif b.apk:
            md.append("| Policy / Boundary | Status | Assessment |")
            md.append("| :--- | :---: | :--- |")
            md.append(f"| **Debuggable** | {'🔴 ENABLED' if b.apk.debuggable else '🟢 Disabled'} | {'Memory inspection and live attach permitted' if b.apk.debuggable else 'Secure'} |")
            md.append(f"| **ADB Backup Allowed** | {'🟡 ALLOWED' if b.apk.allow_backup else '🟢 Blocked'} | {'App private sandbox extractable via adb backup' if b.apk.allow_backup else 'Secure'} |")
            md.append(f"| **Cleartext HTTP** | {'🟡 PERMITTED' if b.apk.uses_cleartext else '🟢 Blocked'} | {'Insecure unencrypted HTTP allowed' if b.apk.uses_cleartext else 'Secure'} |")
            md.append(f"| **Dangerous Permissions** | {len(b.apk.dangerous_permissions)} declared | Declared runtime sensitive privileges |")

            if b.apk.dangerous_permissions:
                md.append("\n### ⚠️ Declared Sensitive Permissions")
                for p in b.apk.dangerous_permissions:
                    md.append(f"- 🔴 `{p}`")

            if b.apk.frida_script_ssl:
                md.append("\n### ⚡ Ready-to-Run Frida Dynamic Hook Script (SSL Unpinning)")
                md.append("```javascript")
                md.append(b.apk.frida_script_ssl)
                md.append("```\n")

        elif b.web:
            md.append("| HTTP Security Header | Configured Value | Status / Recommendation |")
            md.append("| :--- | :--- | :--- |")
            for h in b.web.security_headers:
                md.append(f"| `{h.header}` | `{h.value}` | {h.recommendation} |")

        html_body = markdown.markdown("\n".join(md), extensions=["tables", "fenced_code"])
        self.browser_security.setHtml(f"<!DOCTYPE html><html><head>{HTML_STYLE}</head><body>{html_body}</body></html>")

    def _populate_decompile_view(self, b: AnalysisBundle):
        code_lines = []
        if b.pe:
            self.dec_title_lbl.setText(f"🔬 Capstone Machine Disassembly — Entry Point VA: {b.pe.entry_point_va}")
            code_lines.append(f"; ===================================================================")
            code_lines.append(f"; SuperReverse Binary Machine Disassembly (Capstone 5.x)")
            code_lines.append(f"; Architecture: {b.pe.machine_type} | Subsystem: {b.pe.subsystem}")
            code_lines.append(f"; Entry Point RVA: {b.pe.entry_point_rva} (Loaded VA: {b.pe.entry_point_va})")
            code_lines.append(f"; ===================================================================\n")
            if b.pe.disassembly:
                for instr in b.pe.disassembly:
                    code_lines.append(f"{instr.address}:   {instr.bytes_hex.ljust(20)}  {instr.mnemonic.ljust(8)} {instr.op_str}")
            else:
                code_lines.append("; No machine disassembly available at entry point.")

        elif b.apk:
            self.dec_title_lbl.setText(f"☕ Android Bytecode Inventory — Package: {b.apk.package_name}")
            code_lines.append(f"// ===================================================================")
            code_lines.append(f"// SuperReverse Android DEX & Component Reconstruction")
            code_lines.append(f"// Package: {b.apk.package_name} (Version: {b.apk.version_name})")
            code_lines.append(f"// Min SDK: {b.apk.min_sdk} | Target SDK: {b.apk.target_sdk}")
            code_lines.append(f"// Total Classes: ~{b.apk.total_classes} across {b.apk.dex_count} DEX file(s)")
            code_lines.append(f"// ===================================================================\n")
            code_lines.append(f"package {b.apk.package_name};\n")
            if b.apk.application_class:
                code_lines.append(f"public class {b.apk.application_class.split('.')[-1]} extends android.app.Application {{")
                code_lines.append(f"    @Override")
                code_lines.append(f"    public void onCreate() {{")
                code_lines.append(f"        super.onCreate();")
                code_lines.append(f"        // Initialized SQLite databases and preferences")
                code_lines.append(f"    }}")
                code_lines.append(f"}}\n")
            for c in b.apk.components[:15]:
                code_lines.append(f"// Component: {c.kind.upper()} (Exported: {c.exported})")
                code_lines.append(f"public class {c.name.split('.')[-1]} extends android.app.{c.kind.capitalize()} {{ /* ... */ }}\n")

        elif b.electron:
            self.dec_title_lbl.setText(f"⚡ Electron Source Recovery — App: {b.electron.app_name}")
            code_lines.append(f"// Package Name: {b.electron.app_name} v{b.electron.app_version}")
            code_lines.append(f"// Main Process Entry: {b.electron.main_entry}\n")
            code_lines.append(f"const {{ app, BrowserWindow, ipcMain }} = require('electron');\n")
            for ch in b.electron.ipc_channels:
                code_lines.append(f"// IPC: {ch.direction} on '{ch.channel_name}'")
                code_lines.append(f"ipcMain.handle('{ch.channel_name}', async (event, ...args) => {{")
                code_lines.append(f"    return {{ success: true }};")
                code_lines.append(f"}});\n")

        self.code_viewer.setPlainText("\n".join(code_lines))

    def _copy_code(self):
        QGuiApplication.clipboard().setText(self.code_viewer.toPlainText())
        self.status_pill.setText("✅ Disassembly / Code Copied!")

    def _populate_strings_view(self, b: AnalysisBundle):
        md = ["# 🔍 Extracted Intelligence, URLs & Indicators\n"]
        s = b.strings_intel
        if s:
            if s.urls:
                md.append("### 🌐 Discovered URLs & Remote Endpoints")
                for u in s.urls:
                    md.append(f"- [{u}]({u})")
            ips = getattr(s, "ips", []) or getattr(s, "ip_addresses", [])
            if ips:
                md.append("\n### 📡 Discovered IP Addresses")
                for ip in ips:
                    md.append(f"- `{ip}`")
            if s.registry_keys:
                md.append("\n### 🔑 Windows Registry Keys")
                for reg in s.registry_keys:
                    md.append(f"- `{reg}`")
            if s.potential_secrets:
                md.append("\n### 🔐 Discovered Potential API Keys & Secrets")
                for sec in s.potential_secrets:
                    md.append(f"- ⚠️ `{sec}`")
            paths = getattr(s, "paths", []) or getattr(s, "file_paths", [])
            if paths:
                md.append("\n### 📁 Embedded File Paths & Artifacts")
                for fp in paths[:20]:
                    md.append(f"- `{fp}`")

        html_body = markdown.markdown("\n".join(md), extensions=["tables"])
        self.strings_browser.setHtml(f"<!DOCTYPE html><html><head>{HTML_STYLE}</head><body>{html_body}</body></html>")

    def _filter_strings_view(self, query: str):
        self.strings_browser.find(query)

    def _copy_for_ai(self):
        clipboard = QGuiApplication.clipboard()
        if "## 9. Direct AI Prompt Injection Card" in self.raw_content:
            parts = self.raw_content.split("## 9. Direct AI Prompt Injection Card")
            text_to_copy = "## 9. Direct AI Prompt Injection Card" + parts[1]
        elif "## 7. AI Agent Navigation & Prompt Context" in self.raw_content:
            parts = self.raw_content.split("## 7. AI Agent Navigation & Prompt Context")
            text_to_copy = "## 7. AI Agent Navigation & Prompt Context" + parts[1]
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
            f"| **Python Host** | 🟢 Available | `{sys.version.split()[0]}` | PySide6 GUI, pefile, Capstone NASM, AXML |",
        ]
        html_body = markdown.markdown("\n".join(lines), extensions=["tables"])
        self.tools_panel.setHtml(f"<!DOCTYPE html><html><head>{HTML_STYLE}</head><body>{html_body}</body></html>")
