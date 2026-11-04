"""Universal string and semantic indicator extraction engine.

Extracts ASCII, UTF-16LE strings, calculates Shannon entropy,
and semantically categorizes URLs, IPs, paths, registry keys,
potential secrets, and command patterns.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set


@dataclass
class StringIntelligence:
    total_strings: int = 0
    urls: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    paths: List[str] = field(default_factory=list)
    registry_keys: List[str] = field(default_factory=list)
    suspicious_commands: List[str] = field(default_factory=list)
    potential_secrets: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    common_tokens: List[str] = field(default_factory=list)
    raw_sample: List[str] = field(default_factory=list)

    @property
    def ip_addresses(self) -> List[str]:
        return self.ips

    @property
    def file_paths(self) -> List[str]:
        return self.paths


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0 - 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)
    return round(entropy, 4)


class StringsEngine:
    URL_REGEX = re.compile(r"https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?::\d+)?(?:/[^\s\"'<>]*)?")
    IPV4_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
    WIN_PATH_REGEX = re.compile(r"[A-Za-z]:\\(?:[\w\.\-]+\\)*[\w\.\-]+")
    UNIX_PATH_REGEX = re.compile(r"/(?:usr|bin|etc|lib|var|opt|tmp|home|app)/[\w\.\-/]+")
    REG_REGEX = re.compile(r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|HKCR|SYSTEM\\CurrentControlSet|Software\\Microsoft\\[\w\\]+)", re.IGNORECASE)
    CMD_REGEX = re.compile(r"\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|wscript|cscript|bash|sh|curl|wget|certutil|rundll32|regsvr32|bitsadmin)\b", re.IGNORECASE)
    JWT_REGEX = re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")
    AWS_REGEX = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

    def __init__(self, min_length: int = 4, max_strings: int = 15000):
        self.min_length = min_length
        self.max_strings = max_strings

    def extract_from_bytes(self, data: bytes) -> List[str]:
        """Extract ASCII and UTF-16LE strings from byte stream."""
        strings: Set[str] = set()

        # ASCII strings: printable chars 0x20..0x7e
        ascii_pattern = re.compile(rb"[\x20-\x7e]{" + str(self.min_length).encode() + rb",}")
        for match in ascii_pattern.finditer(data):
            try:
                s = match.group().decode("ascii", errors="ignore").strip()
                if len(s) >= self.min_length:
                    strings.add(s)
                    if len(strings) >= self.max_strings:
                        break
            except Exception:
                pass

        # UTF-16LE strings (typical in Windows binaries)
        if len(strings) < self.max_strings:
            utf16_pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(self.min_length).encode() + rb",}")
            for match in utf16_pattern.finditer(data):
                try:
                    s = match.group().decode("utf-16le", errors="ignore").strip()
                    if len(s) >= self.min_length:
                        strings.add(s)
                        if len(strings) >= self.max_strings:
                            break
                except Exception:
                    pass

        return list(strings)

    def analyze(self, file_path_or_bytes: Path | str | bytes) -> StringIntelligence:
        """Analyze strings in a file or bytes and extract semantic categories."""
        if isinstance(file_path_or_bytes, (str, Path)):
            path = Path(file_path_or_bytes)
            # Read at most 32MB for strings scan to remain responsive
            with open(path, "rb") as f:
                data = f.read(32 * 1024 * 1024)
        else:
            data = file_path_or_bytes[: 32 * 1024 * 1024]

        raw_strings = self.extract_from_bytes(data)
        intel = StringIntelligence(total_strings=len(raw_strings))

        urls: Set[str] = set()
        ips: Set[str] = set()
        paths: Set[str] = set()
        regs: Set[str] = set()
        cmds: Set[str] = set()
        secrets: Set[str] = set()
        emails: Set[str] = set()

        for s in raw_strings:
            # URLs
            for u in self.URL_REGEX.findall(s):
                urls.add(u)
            # IPs
            for ip in self.IPV4_REGEX.findall(s):
                if not ip.startswith("0.0.") and not ip.startswith("127.0."):
                    ips.add(ip)
            # Windows Paths
            for p in self.WIN_PATH_REGEX.findall(s):
                paths.add(p)
            # Unix Paths
            for p in self.UNIX_PATH_REGEX.findall(s):
                paths.add(p)
            # Registry
            for r in self.REG_REGEX.findall(s):
                regs.add(r)
            # Suspicious CLI commands
            if self.CMD_REGEX.search(s):
                cmds.add(s)
            # Tokens / Secrets
            for jwt in self.JWT_REGEX.findall(s):
                secrets.add(f"JWT: {jwt[:20]}...{jwt[-8:]}")
            for aws in self.AWS_REGEX.findall(s):
                secrets.add(f"AWS Key: {aws}")
            # Emails
            for em in self.EMAIL_REGEX.findall(s):
                emails.add(em)

        intel.urls = sorted(urls)[:100]
        intel.ips = sorted(ips)[:50]
        intel.paths = sorted(paths)[:80]
        intel.registry_keys = sorted(regs)[:50]
        intel.suspicious_commands = sorted(cmds)[:40]
        intel.potential_secrets = sorted(secrets)[:30]
        intel.emails = sorted(emails)[:40]
        intel.raw_sample = sorted(raw_strings[:100])

        return intel
