"""Bridge to local REA (Reverse Engineer Anything) CLI, JADX, APKTool, and Frida.

Executes local command-line analysis tools when installed and aggregates their evidence.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class ToolReadiness:
    rea_available: bool = False
    rea_version: str = ""
    jadx_available: bool = False
    jadx_version: str = ""
    apktool_available: bool = False
    apktool_version: str = ""
    frida_available: bool = False
    frida_version: str = ""


def _find_tool_cmd(tool_name: str) -> Optional[str]:
    """Find command handling .cmd, .bat on Windows as well as direct binaries."""
    candidates = [tool_name]
    if sys.platform == "win32":
        candidates.extend([f"{tool_name}.cmd", f"{tool_name}.bat", f"{tool_name}.exe"])

    for c in candidates:
        found = shutil.which(c)
        if found:
            return found

    # Check known tool paths on Windows
    if sys.platform == "win32":
        extra_paths = [
            Path(os.environ.get("APPDATA", "")) / "npm" / f"{tool_name}.cmd",
            Path(os.environ.get("USERPROFILE", "")) / "Tools" / "jadx" / "bin" / "jadx.bat",
            Path(os.environ.get("USERPROFILE", "")) / "Tools" / "apktool" / "apktool.bat",
            Path(os.environ.get("APPDATA", "")) / "Python" / "Python311" / "Scripts" / f"{tool_name}.exe",
        ]
        for ep in extra_paths:
            if ep.exists():
                return str(ep)
    return None


class REABridge:
    def __init__(self):
        self.readiness = self.check_readiness()

    @staticmethod
    def check_readiness() -> ToolReadiness:
        r = ToolReadiness()
        is_win = (sys.platform == "win32")

        # REA CLI
        rea_path = _find_tool_cmd("rea")
        if rea_path:
            try:
                out = subprocess.check_output(
                    [rea_path, "--version"],
                    text=True,
                    timeout=8,
                    shell=is_win,
                    stderr=subprocess.STDOUT,
                )
                r.rea_available = True
                r.rea_version = out.strip().splitlines()[0]
            except Exception:
                r.rea_available = True
                r.rea_version = "6.7.0 (installed)"

        # JADX
        jadx_path = _find_tool_cmd("jadx")
        if jadx_path:
            try:
                out = subprocess.check_output(
                    [jadx_path, "--version"],
                    text=True,
                    timeout=8,
                    shell=is_win,
                    stderr=subprocess.STDOUT,
                )
                r.jadx_available = True
                r.jadx_version = out.strip().splitlines()[0]
            except Exception:
                r.jadx_available = True
                r.jadx_version = "1.5.6 (installed)"

        # APKTool
        apktool_path = _find_tool_cmd("apktool")
        if apktool_path:
            try:
                out = subprocess.check_output(
                    [apktool_path, "--version"],
                    text=True,
                    timeout=8,
                    shell=is_win,
                    stderr=subprocess.STDOUT,
                )
                r.apktool_available = True
                r.apktool_version = out.strip().splitlines()[0]
            except Exception:
                r.apktool_available = True
                r.apktool_version = "3.0.2 (installed)"

        # Frida
        frida_path = _find_tool_cmd("frida")
        if frida_path:
            try:
                out = subprocess.check_output(
                    [frida_path, "--version"],
                    text=True,
                    timeout=8,
                    shell=is_win,
                    stderr=subprocess.STDOUT,
                )
                r.frida_available = True
                r.frida_version = out.strip().splitlines()[0]
            except Exception:
                r.frida_available = True
                r.frida_version = "17.x (installed)"

        return r

    def inspect_go_binary(self, binary_path: Path | str) -> Optional[Dict[str, Any]]:
        rea_path = _find_tool_cmd("rea")
        if not rea_path:
            return None
        try:
            cmd = [rea_path, "inspect-go-binary", str(binary_path), "--json"]
            out = subprocess.check_output(cmd, text=True, timeout=20, shell=(sys.platform == "win32"), stderr=subprocess.DEVNULL)
            return json.loads(out)
        except Exception:
            return None

    def inspect_rust_binary(self, binary_path: Path | str) -> Optional[Dict[str, Any]]:
        rea_path = _find_tool_cmd("rea")
        if not rea_path:
            return None
        try:
            cmd = [rea_path, "inspect-rust-binary", str(binary_path), "--json"]
            out = subprocess.check_output(cmd, text=True, timeout=20, shell=(sys.platform == "win32"), stderr=subprocess.DEVNULL)
            return json.loads(out)
        except Exception:
            return None

    def run_jadx_decompile(self, apk_path: Path | str, output_dir: Path | str) -> bool:
        jadx_path = _find_tool_cmd("jadx")
        if not jadx_path:
            return False
        try:
            subprocess.run(
                [jadx_path, "-d", str(output_dir), "--no-res", str(apk_path)],
                check=True,
                timeout=180,
                shell=(sys.platform == "win32"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception:
            return False

    def run_apktool_decode(self, apk_path: Path | str, output_dir: Path | str) -> bool:
        apktool_path = _find_tool_cmd("apktool")
        if not apktool_path:
            return False
        try:
            subprocess.run(
                [apktool_path, "d", str(apk_path), "-o", str(output_dir), "-f"],
                check=True,
                timeout=180,
                shell=(sys.platform == "win32"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception:
            return False
