"""Universal Software & Target Classifier.

Inspects magic bytes, file extensions, URLs, and internal structures to accurately
identify binary target types and web applications for specialized reverse engineering routing.
"""
from __future__ import annotations

import configparser
import re
import zipfile
from enum import Enum
from pathlib import Path
from typing import Optional, Tuple


class TargetKind(Enum):
    WEB_URL = "Live Web Application & URL"
    ANDROID_APK = "Android APK / AAB Package"
    WINDOWS_PE = "Windows PE (Native / .NET Executable)"
    LINUX_ELF = "Linux ELF Binary / Shared Object"
    MACOS_MACHO = "macOS / iOS Mach-O Binary"
    ELECTRON_ASAR = "Electron Application ASAR"
    JAVA_JAR = "Java Bytecode Archive (JAR / WAR)"
    WASM_BINARY = "WebAssembly (WASM) Binary"
    SQLITE_DB = "SQLite Database Snapshot"
    SOURCE_DIRECTORY = "Application Source / Project Tree"
    GENERIC_ARCHIVE = "Compressed Archive (ZIP / TAR / 7Z)"
    GENERIC_BINARY = "Unknown Native / Firmware Binary"


class TargetClassifier:
    URL_PATTERN = re.compile(r"^(?:https?://|www\.)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:/[^\s]*)?$")

    @classmethod
    def classify(cls, target: Path | str) -> Tuple[TargetKind, str]:
        target_str = str(target).strip()

        # 1. Direct Web URL check
        if target_str.startswith(("http://", "https://")) or cls.URL_PATTERN.match(target_str):
            return TargetKind.WEB_URL, f"Live Web URL ({target_str})"

        p = Path(target_str)
        if not p.exists():
            # If string contains domain or url format
            if "." in target_str and "/" not in target_str and "\\" not in target_str:
                return TargetKind.WEB_URL, f"Domain URL ({target_str})"
            return TargetKind.GENERIC_BINARY, "Path does not exist"

        # 2. Windows .url Internet Shortcut File
        if p.is_file() and p.suffix.lower() == ".url":
            try:
                cp = configparser.ConfigParser()
                cp.read(p)
                actual_url = cp.get("InternetShortcut", "URL", fallback="")
                if actual_url:
                    return TargetKind.WEB_URL, f"Internet Shortcut URL ({actual_url})"
            except Exception:
                pass

        if p.is_dir():
            if (p / "package.json").exists():
                return TargetKind.ELECTRON_ASAR, "JavaScript / Electron application tree"
            if (p / "AndroidManifest.xml").exists():
                return TargetKind.ANDROID_APK, "Unpacked Android application directory"
            return TargetKind.SOURCE_DIRECTORY, "Software directory or source tree"

        # Check by extension first for fast path
        ext = p.suffix.lower()
        if ext in (".apk", ".aab", ".xapk"):
            return TargetKind.ANDROID_APK, "Android Package file"
        if ext == ".asar":
            return TargetKind.ELECTRON_ASAR, "Electron ASAR application bundle"

        # Read magic bytes
        try:
            with open(p, "rb") as f:
                magic = f.read(64)
        except Exception:
            return TargetKind.GENERIC_BINARY, "Unable to read file header"

        if len(magic) < 4:
            return TargetKind.GENERIC_BINARY, "File too small"

        # Windows PE: MZ
        if magic.startswith(b"MZ"):
            return TargetKind.WINDOWS_PE, "Windows Portable Executable (EXE / DLL / SYS)"

        # Linux ELF: \x7fELF
        if magic.startswith(b"\x7fELF"):
            return TargetKind.LINUX_ELF, "Linux ELF executable or shared library"

        # macOS Mach-O
        if magic.startswith((b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")):
            return TargetKind.MACOS_MACHO, "macOS / iOS Mach-O executable or dylib"

        # WebAssembly: \x00asm
        if magic.startswith(b"\x00asm"):
            return TargetKind.WASM_BINARY, "WebAssembly binary artifact"

        # SQLite
        if magic.startswith(b"SQLite format 3"):
            return TargetKind.SQLITE_DB, "SQLite Database snapshot"

        # ZIP Container (APK, JAR, standard ZIP)
        if magic.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(p, "r") as zf:
                    names = set(zf.namelist())
                    if "AndroidManifest.xml" in names or any(n.endswith(".dex") for n in names):
                        return TargetKind.ANDROID_APK, "Android APK / DEX container"
                    if "META-INF/MANIFEST.MF" in names:
                        return TargetKind.JAVA_JAR, "Java Bytecode Archive (JAR / WAR)"
                    return TargetKind.GENERIC_ARCHIVE, "Standard ZIP archive"
            except Exception:
                return TargetKind.GENERIC_ARCHIVE, "ZIP-formatted archive container"

        # ASAR header check
        if len(magic) >= 16:
            import struct
            try:
                u1, h_size, u2, json_size = struct.unpack("<IIII", magic[:16])
                if u1 == 4 and json_size < 100 * 1024 * 1024 and json_size > 0:
                    return TargetKind.ELECTRON_ASAR, "Electron ASAR application archive"
            except Exception:
                pass

        return TargetKind.GENERIC_BINARY, "Raw binary or unknown format"
