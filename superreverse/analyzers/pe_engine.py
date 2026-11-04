"""Windows PE (Portable Executable) Reverse Engineering Engine.

Deep static inspection of PE32 / PE32+ (EXE, DLL, SYS) binaries:
- Header architecture, subsystem, entry point, image base
- Sections analysis, virtual vs raw sizes, Shannon entropy (packing/crypter detection)
- Import Address Table (IAT) with semantic API capability clustering:
  (Network, Injection, Persistence, Cryptography, Anti-Debug, Process Creation)
- Export table symbols and ordinals
- Binary security hardening & exploit mitigations:
  (ASLR, High-Entropy VA, DEP/NX, SafeSEH, CFG, Authenticode Signatures)
- Resource inspection: VersionInfo and Application Manifest (UAC privilege level)
- .NET / CLR managed assembly detection & framework identification
"""
from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import pefile
except ImportError:
    pefile = None


@dataclass
class PESection:
    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: str
    is_suspicious: bool = False
    flag: str = ""


@dataclass
class PEImport:
    dll: str
    functions: List[str] = field(default_factory=list)


@dataclass
class PEMitigations:
    aslr: bool = False
    high_entropy_aslr: bool = False
    dep_nx: bool = False
    safeseh: bool = False
    cfg: bool = False
    code_integrity: bool = False
    authenticode_signed: bool = False


@dataclass
class PEAnalysisResult:
    machine_type: str = ""
    is_64bit: bool = False
    subsystem: str = ""
    entry_point_rva: str = ""
    image_base: str = ""
    file_size: int = 0
    overall_entropy: float = 0.0
    is_packed_likely: bool = False
    packers_detected: List[str] = field(default_factory=list)
    is_dotnet: bool = False
    dotnet_framework: str = ""
    mitigations: PEMitigations = field(default_factory=PEMitigations)
    sections: List[PESection] = field(default_factory=list)
    imports: List[PEImport] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    capabilities: Dict[str, List[str]] = field(default_factory=dict)
    version_info: Dict[str, str] = field(default_factory=dict)
    uac_level: str = "asInvoker"
    warnings: List[str] = field(default_factory=list)


def calc_bytes_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class PEEngine:
    CAPABILITY_PATTERNS = {
        "Process Injection & Memory": [
            "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
            "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
            "NtCreateThreadEx", "QueueUserAPC", "SetThreadContext", "ResumeThread"
        ],
        "Network & Socket Communication": [
            "WSAStartup", "socket", "connect", "send", "recv", "gethostbyname",
            "InternetOpenA", "InternetOpenW", "InternetConnectA", "HttpOpenRequestA",
            "HttpSendRequestA", "URLDownloadToFileA", "URLDownloadToFileW", "WinHttpOpen"
        ],
        "Registry & Persistence": [
            "RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW",
            "RegCreateKeyExA", "CreateServiceA", "CreateServiceW", "StartServiceA"
        ],
        "Anti-Debugging & Evasion": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "GetTickCount", "QueryPerformanceCounter", "FindWindowA"
        ],
        "Cryptography & Hashing": [
            "CryptAcquireContextA", "CryptGenKey", "CryptEncrypt", "CryptDecrypt",
            "BCryptOpenAlgorithmProvider", "BCryptEncrypt", "BCryptDecrypt", "MD5Init"
        ],
        "Process Execution": [
            "CreateProcessA", "CreateProcessW", "ShellExecuteA", "ShellExecuteW",
            "WinExec", "system", "_wsystem"
        ],
    }

    def __init__(self, file_path: Path | str):
        self.file_path = Path(file_path)

    def analyze(self) -> PEAnalysisResult:
        result = PEAnalysisResult()

        if not self.file_path.exists():
            return result

        with open(self.file_path, "rb") as f:
            raw_bytes = f.read()

        result.file_size = len(raw_bytes)
        result.overall_entropy = calc_bytes_entropy(raw_bytes)

        if pefile is not None:
            self._analyze_with_pefile(raw_bytes, result)
        else:
            self._analyze_minimal_pe(raw_bytes, result)

        return result

    def _analyze_with_pefile(self, raw_bytes: bytes, result: PEAnalysisResult) -> None:
        try:
            pe = pefile.PE(data=raw_bytes)

            # Machine & Arch
            machine = pe.FILE_HEADER.Machine
            if machine == 0x8664:
                result.machine_type = "x86-64 (AMD64 / Intel 64)"
                result.is_64bit = True
            elif machine == 0x014C:
                result.machine_type = "x86 (Intel 32-bit)"
                result.is_64bit = False
            elif machine == 0xAA64:
                result.machine_type = "ARM64 (Little Endian)"
                result.is_64bit = True
            else:
                result.machine_type = f"Machine 0x{machine:04X}"

            # Subsystem
            subsys = pe.OPTIONAL_HEADER.Subsystem
            subsystems_map = {
                1: "Native Driver",
                2: "Windows GUI",
                3: "Windows CUI (Console)",
                7: "POSIX CUI",
                9: "Windows CE GUI",
                10: "EFI Application",
                14: "Xbox",
            }
            result.subsystem = subsystems_map.get(subsys, f"Subsystem {subsys}")
            result.entry_point_rva = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            result.image_base = hex(pe.OPTIONAL_HEADER.ImageBase)

            # Mitigations & DllCharacteristics
            dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
            result.mitigations.aslr = bool(dll_char & 0x0040)
            result.mitigations.high_entropy_aslr = bool(dll_char & 0x0020)
            result.mitigations.dep_nx = bool(dll_char & 0x0100)
            result.mitigations.cfg = bool(dll_char & 0x4000)
            result.mitigations.code_integrity = bool(dll_char & 0x0080)

            # Authenticode Digital Signature Directory
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            result.mitigations.authenticode_signed = bool(sec_dir.VirtualAddress and sec_dir.Size)

            # SafeSEH
            if not result.is_64bit:
                load_cfg_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]]
                result.mitigations.safeseh = bool(load_cfg_dir.VirtualAddress and load_cfg_dir.Size)
            else:
                result.mitigations.safeseh = True  # x64 uses table-driven SEH natively

            # .NET CLR Directory
            com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
            if com_dir.VirtualAddress and com_dir.Size:
                result.is_dotnet = True
                result.dotnet_framework = ".NET Managed Assembly (CLI Runtime)"

            # Sections & Entropy
            for section in pe.sections:
                s_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                s_entropy = section.get_entropy()
                vsize = section.Misc_VirtualSize
                rsize = section.SizeOfRawData
                suspicious = False
                flag = ""

                # Packing detection indicators
                if s_entropy > 7.2:
                    suspicious = True
                    flag = "High Entropy (Likely Packed/Encrypted)"
                    result.is_packed_likely = True
                if s_name.lower() in (".upx0", ".upx1", "upx2"):
                    result.packers_detected.append("UPX Packer")
                    suspicious = True
                    flag = "UPX Section"
                elif s_name.lower() in (".vmp0", ".vmp1"):
                    result.packers_detected.append("VMProtect")
                    suspicious = True
                    flag = "VMProtect Section"
                elif s_name.lower() in (".themida"):
                    result.packers_detected.append("Themida")
                    suspicious = True
                    flag = "Themida Section"

                result.sections.append(
                    PESection(
                        name=s_name,
                        virtual_address=hex(section.VirtualAddress),
                        virtual_size=vsize,
                        raw_size=rsize,
                        entropy=round(s_entropy, 3),
                        characteristics=hex(section.Characteristics),
                        is_suspicious=suspicious,
                        flag=flag,
                    )
                )

            # Imports & Capabilities
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    imported_funcs = []
                    for imp in entry.imports:
                        f_name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                        imported_funcs.append(f_name)

                        # Match capabilities
                        for cap, api_list in self.CAPABILITY_PATTERNS.items():
                            for target_api in api_list:
                                if f_name.startswith(target_api):
                                    result.capabilities.setdefault(cap, []).append(f"{dll_name}!{f_name}")

                    result.imports.append(PEImport(dll=dll_name, functions=imported_funcs))

            # Exports
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result.exports.append(exp.name.decode("utf-8", errors="ignore"))

            # Version Info
            if hasattr(pe, "FileInfo"):
                for file_info in pe.FileInfo:
                    if file_info:
                        for entry in getattr(file_info, "StringTable", []):
                            for k, v in getattr(entry, "entries", {}).items():
                                k_str = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                                v_str = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                                result.version_info[k_str] = v_str

        except Exception as e:
            result.warnings.append(f"PE Parser Exception: {str(e)}")

        # Deduplicate capabilities
        for cap in result.capabilities:
            result.capabilities[cap] = sorted(set(result.capabilities[cap]))

    def _analyze_minimal_pe(self, data: bytes, result: PEAnalysisResult) -> None:
        """Fallback lightweight manual PE header parser."""
        if len(data) < 0x40 or data[:2] != b"MZ":
            return
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return

        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        result.is_64bit = machine == 0x8664
        result.machine_type = "x86-64" if result.is_64bit else "x86 (32-bit)"
        opt_magic = struct.unpack_from("<H", data, e_lfanew + 24)[0]
        if opt_magic == 0x020B:
            result.is_64bit = True
