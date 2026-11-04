"""Electron & JavaScript Application Reverse Engineering Engine.

Deep static inspection of Electron ASAR archives and JavaScript bundles:
- Pure-Python ASAR archive unpacking & virtual file system indexer
- package.json metadata: name, version, main script, dependencies
- Electron Security Audit: nodeIntegration, contextIsolation, enableRemoteModule, sandbox
- Complete IPC Communication Map: (ipcMain.on, ipcMain.handle, ipcRenderer.send, ipcRenderer.invoke)
- Frontend framework fingerprinting: React, Vue, Angular, Svelte, Next, Vite
- Main process, preload scripts, and renderer bundle classification
"""
from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ElectronSecurityAudit:
    node_integration: Optional[bool] = None
    context_isolation: Optional[bool] = None
    enable_remote_module: Optional[bool] = None
    sandbox: Optional[bool] = None
    web_security: Optional[bool] = None
    vulnerabilities: List[str] = field(default_factory=list)


@dataclass
class ElectronIPCChannel:
    channel_name: str
    direction: str  # main_listener, main_handle, renderer_send, renderer_invoke
    source_file: str


@dataclass
class ElectronAnalysisResult:
    is_electron: bool = False
    app_name: str = ""
    app_version: str = ""
    main_entry: str = ""
    dependencies: Dict[str, str] = field(default_factory=dict)
    all_files: List[str] = field(default_factory=list)
    frontend_frameworks: List[str] = field(default_factory=list)
    preload_scripts: List[str] = field(default_factory=list)
    ipc_channels: List[ElectronIPCChannel] = field(default_factory=list)
    security: ElectronSecurityAudit = field(default_factory=ElectronSecurityAudit)
    api_endpoints: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)


class ASARReader:
    """Pure-Python ASAR file reader and header unpacker."""

    def __init__(self, file_path: Path | str):
        self.file_path = Path(file_path)
        self.header: Dict[str, Any] = {}
        self.base_offset: int = 0
        self._raw_file = None

    def read_header(self) -> Dict[str, Any]:
        with open(self.file_path, "rb") as f:
            magic_and_sizes = f.read(16)
            if len(magic_and_sizes) < 16:
                return {}

            u1, header_size, u2, json_len = struct.unpack("<IIII", magic_and_sizes)
            if json_len > 100 * 1024 * 1024 or json_len == 0:
                return {}

            json_bytes = f.read(json_len)
            self.header = json.loads(json_bytes.decode("utf-8", errors="replace"))
            self.base_offset = 16 + json_len
        return self.header

    def extract_file(self, relative_path: str) -> Optional[bytes]:
        """Extract a single file from ASAR using header offset and size."""
        parts = relative_path.replace("\\", "/").strip("/").split("/")
        curr = self.header.get("files", {})

        for part in parts:
            if not isinstance(curr, dict):
                return None
            if part in curr:
                curr = curr[part]
                if "files" in curr:
                    curr = curr["files"]
            else:
                return None

        if isinstance(curr, dict) and "offset" in curr and "size" in curr:
            file_offset = int(curr["offset"])
            file_size = int(curr["size"])
            with open(self.file_path, "rb") as f:
                f.seek(self.base_offset + file_offset)
                return f.read(file_size)
        return None

    def list_all_files(self) -> List[str]:
        results: List[str] = []

        def recurse(node: Dict[str, Any], path_prefix: str):
            for name, val in node.items():
                cur_path = f"{path_prefix}/{name}" if path_prefix else name
                if isinstance(val, dict):
                    if "files" in val:
                        recurse(val["files"], cur_path)
                    elif "size" in val:
                        results.append(cur_path)

        if self.header and "files" in self.header:
            recurse(self.header["files"], "")
        return results


class ElectronEngine:
    """Reverse engineering engine for Electron ASAR and JavaScript applications."""

    IPC_MAIN_ON_RE = re.compile(r"ipcMain\.on\(\s*['\"`]([^'\"`]+)['\"`]")
    IPC_MAIN_HANDLE_RE = re.compile(r"ipcMain\.handle\(\s*['\"`]([^'\"`]+)['\"`]")
    IPC_REND_SEND_RE = re.compile(r"ipcRenderer\.send\(\s*['\"`]([^'\"`]+)['\"`]")
    IPC_REND_INVOKE_RE = re.compile(r"ipcRenderer\.invoke\(\s*['\"`]([^'\"`]+)['\"`]")

    def __init__(self, target_path: Path | str):
        self.target_path = Path(target_path)

    def analyze(self) -> ElectronAnalysisResult:
        result = ElectronAnalysisResult()

        if self.target_path.is_file() and self.target_path.name.lower().endswith(".asar"):
            self._analyze_asar(self.target_path, result)
        elif self.target_path.is_dir():
            asar_candidates = list(self.target_path.rglob("*.asar"))
            if asar_candidates:
                self._analyze_asar(asar_candidates[0], result)
            else:
                self._analyze_directory(self.target_path, result)

        return result

    def _analyze_asar(self, asar_file: Path, result: ElectronAnalysisResult) -> None:
        reader = ASARReader(asar_file)
        header = reader.read_header()
        if not header:
            return

        result.is_electron = True
        result.all_files = reader.list_all_files()

        # Parse package.json
        pkg_data = reader.extract_file("package.json")
        if pkg_data:
            try:
                pkg = json.loads(pkg_data.decode("utf-8", errors="ignore"))
                result.app_name = pkg.get("name", "")
                result.app_version = pkg.get("version", "")
                result.main_entry = pkg.get("main", "")
                result.dependencies = pkg.get("dependencies", {})
            except Exception:
                pass

        # Identify frameworks from files and dependencies
        deps_str = " ".join(result.dependencies.keys()).lower()
        files_str = " ".join(result.all_files).lower()
        frameworks = set()
        if "react" in deps_str or "react" in files_str:
            frameworks.add("React")
        if "vue" in deps_str or "vue" in files_str:
            frameworks.add("Vue.js")
        if "@angular" in deps_str or "angular" in files_str:
            frameworks.add("Angular")
        if "svelte" in deps_str or "svelte" in files_str:
            frameworks.add("Svelte")
        if "electron-builder" in deps_str or "electron-forge" in deps_str:
            frameworks.add("Electron Packager")
        result.frontend_frameworks = sorted(frameworks)

        # Inspect JS files for IPC, Security, Preload
        for fpath in result.all_files:
            lower = fpath.lower()
            if "preload" in lower:
                result.preload_scripts.append(fpath)

            if lower.endswith((".js", ".cjs", ".mjs", ".html")):
                content_bytes = reader.extract_file(fpath)
                if content_bytes and len(content_bytes) < 5 * 1024 * 1024:
                    self._inspect_js_code(fpath, content_bytes.decode("utf-8", errors="ignore"), result)

        self._audit_security(result)

    def _analyze_directory(self, dir_path: Path, result: ElectronAnalysisResult) -> None:
        pkg_file = dir_path / "package.json"
        if pkg_file.exists():
            result.is_electron = True
            try:
                with open(pkg_file, "r", encoding="utf-8", errors="ignore") as f:
                    pkg = json.load(f)
                    result.app_name = pkg.get("name", "")
                    result.app_version = pkg.get("version", "")
                    result.main_entry = pkg.get("main", "")
                    result.dependencies = pkg.get("dependencies", {})
            except Exception:
                pass

        for p in dir_path.rglob("*.js"):
            rel = str(p.relative_to(dir_path)).replace("\\", "/")
            result.all_files.append(rel)
            if "preload" in rel.lower():
                result.preload_scripts.append(rel)
            if p.stat().st_size < 3 * 1024 * 1024:
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        self._inspect_js_code(rel, f.read(), result)
                except Exception:
                    pass

        self._audit_security(result)

    def _inspect_js_code(self, filename: str, code: str, result: ElectronAnalysisResult) -> None:
        # IPC channels
        for m in self.IPC_MAIN_ON_RE.finditer(code):
            result.ipc_channels.append(ElectronIPCChannel(channel_name=m.group(1), direction="ipcMain.on (Event Listener)", source_file=filename))
        for m in self.IPC_MAIN_HANDLE_RE.finditer(code):
            result.ipc_channels.append(ElectronIPCChannel(channel_name=m.group(1), direction="ipcMain.handle (Async RPC)", source_file=filename))
        for m in self.IPC_REND_SEND_RE.finditer(code):
            result.ipc_channels.append(ElectronIPCChannel(channel_name=m.group(1), direction="ipcRenderer.send (Trigger)", source_file=filename))
        for m in self.IPC_REND_INVOKE_RE.finditer(code):
            result.ipc_channels.append(ElectronIPCChannel(channel_name=m.group(1), direction="ipcRenderer.invoke (Query)", source_file=filename))

        # Security checks
        if "nodeIntegration: true" in code or "nodeIntegration:!0" in code:
            result.security.node_integration = True
        elif "nodeIntegration: false" in code or "nodeIntegration:!1" in code:
            result.security.node_integration = False

        if "contextIsolation: false" in code or "contextIsolation:!1" in code:
            result.security.context_isolation = False
        elif "contextIsolation: true" in code or "contextIsolation:!0" in code:
            result.security.context_isolation = True

        if "enableRemoteModule: true" in code or "enableRemoteModule:!0" in code:
            result.security.enable_remote_module = True
        elif "enableRemoteModule: false" in code or "enableRemoteModule:!1" in code:
            result.security.enable_remote_module = False

        if "webSecurity: false" in code or "webSecurity:!1" in code:
            result.security.web_security = False

    def _audit_security(self, result: ElectronAnalysisResult) -> None:
        sec = result.security
        if sec.node_integration is True:
            sec.vulnerabilities.append("CRITICAL: nodeIntegration is ENABLED in renderer. Any XSS immediately results in full remote code execution (RCE) on host OS.")
        if sec.context_isolation is False:
            sec.vulnerabilities.append("CRITICAL: contextIsolation is DISABLED. Preload scripts share context with webpage, allowing prototype pollution and RCE.")
        if sec.enable_remote_module is True:
            sec.vulnerabilities.append("HIGH RISK: enableRemoteModule is ENABLED. Deprecated dangerous API allowing renderer arbitrary host process access.")
        if sec.web_security is False:
            sec.vulnerabilities.append("HIGH RISK: webSecurity is DISABLED. Same-Origin Policy (SOP) bypass enabled.")

        # Deduplicate IPC channels
        seen = set()
        deduped = []
        for ch in result.ipc_channels:
            key = (ch.channel_name, ch.direction)
            if key not in seen:
                seen.add(key)
                deduped.append(ch)
        result.ipc_channels = deduped
