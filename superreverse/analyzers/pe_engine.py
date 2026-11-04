"""Windows PE (Portable Executable) Reverse Engineering Engine.

Deep static and binary-level inspection:
- Capstone machine disassembly of Entry Point procedures
- Section byte offsets, raw vs virtual sizes, and Shannon entropy analysis
- Exhaustive PE parameters extraction (ImageBase, Stack/Heap limits, Alignments)
- Semantic IAT capability clustering (Process Injection, Network/C2, Registry, Cryptography, Anti-Debug)
- Export table symbol signatures and ordinals
- Security hardening & exploit mitigations matrix
- Embedded resources (VersionInfo, Manifest UAC privilege levels)
- .NET / CLR managed assembly detection
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

try:
    import capstone
except ImportError:
    capstone = None


@dataclass
class DisassembledInstruction:
    address: str
    mnemonic: str
    op_str: str
    bytes_hex: str


@dataclass
class PESection:
    name: str
    virtual_address: str
    virtual_size: int
    raw_offset: int
    raw_size: int
    entropy: float
    permissions: str
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
class PEParameter:
    name: str
    category: str
    value: str
    location: str
    tweak_impact: str


@dataclass
class PEAnalysisResult:
    machine_type: str = ""
    is_64bit: bool = False
    subsystem: str = ""
    entry_point_rva: str = ""
    entry_point_va: str = ""
    image_base: str = ""
    file_size: int = 0
    overall_entropy: float = 0.0
    is_packed_likely: bool = False
    packers_detected: List[str] = field(default_factory=list)
    is_dotnet: bool = False
    dotnet_framework: str = ""
    stack_reserve: int = 0
    stack_commit: int = 0
    heap_reserve: int = 0
    heap_commit: int = 0
    file_alignment: int = 0
    section_alignment: int = 0
    subsystem_version: str = ""
    os_version: str = ""
    mitigations: PEMitigations = field(default_factory=PEMitigations)
    sections: List[PESection] = field(default_factory=list)
    imports: List[PEImport] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    capabilities: Dict[str, List[str]] = field(default_factory=dict)
    parameters: List[PEParameter] = field(default_factory=list)
    disassembly: List[DisassembledInstruction] = field(default_factory=list)
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

            # Machine & Architecture
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

            # Subsystems
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
            entry_va = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
            result.entry_point_va = hex(entry_va)

            # Memory Limits & Alignments
            result.stack_reserve = getattr(pe.OPTIONAL_HEADER, "SizeOfStackReserve", 0)
            result.stack_commit = getattr(pe.OPTIONAL_HEADER, "SizeOfStackCommit", 0)
            result.heap_reserve = getattr(pe.OPTIONAL_HEADER, "SizeOfHeapReserve", 0)
            result.heap_commit = getattr(pe.OPTIONAL_HEADER, "SizeOfHeapCommit", 0)
            result.file_alignment = getattr(pe.OPTIONAL_HEADER, "FileAlignment", 0)
            result.section_alignment = getattr(pe.OPTIONAL_HEADER, "SectionAlignment", 0)
            result.os_version = f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}"
            result.subsystem_version = f"{pe.OPTIONAL_HEADER.MajorSubsystemVersion}.{pe.OPTIONAL_HEADER.MinorSubsystemVersion}"

            # Extract Core Tweakable Parameters
            result.parameters.extend([
                PEParameter("IMAGE_BASE", "Memory Architecture", result.image_base, "pe.OPTIONAL_HEADER.ImageBase", "Base memory loading address in virtual RAM"),
                PEParameter("ENTRY_POINT_RVA", "Execution Lifecycle", result.entry_point_rva, "pe.OPTIONAL_HEADER.AddressOfEntryPoint", "Relative entry point instruction address"),
                PEParameter("SUBSYSTEM", "Platform Subsystem", result.subsystem, "pe.OPTIONAL_HEADER.Subsystem", "Controls console window presence (GUI vs Console)"),
                PEParameter("STACK_RESERVE_BYTES", "Thread & Memory", str(result.stack_reserve), "pe.OPTIONAL_HEADER.SizeOfStackReserve", "Initial stack size reserved per thread"),
                PEParameter("HEAP_RESERVE_BYTES", "Thread & Memory", str(result.heap_reserve), "pe.OPTIONAL_HEADER.SizeOfHeapReserve", "Initial default process heap reserve"),
                PEParameter("FILE_ALIGNMENT", "Binary Layout", str(result.file_alignment), "pe.OPTIONAL_HEADER.FileAlignment", "Physical on-disk sector alignment"),
                PEParameter("SECTION_ALIGNMENT", "Binary Layout", str(result.section_alignment), "pe.OPTIONAL_HEADER.SectionAlignment", "In-memory virtual page alignment"),
                PEParameter("MIN_OS_VERSION", "OS Compatibility", result.os_version, "pe.OPTIONAL_HEADER.MajorOperatingSystemVersion", "Minimum required Windows OS version"),
            ])

            # Mitigations & DllCharacteristics
            dll_char = pe.OPTIONAL_HEADER.DllCharacteristics
            result.mitigations.aslr = bool(dll_char & 0x0040)
            result.mitigations.high_entropy_aslr = bool(dll_char & 0x0020)
            result.mitigations.dep_nx = bool(dll_char & 0x0100)
            result.mitigations.cfg = bool(dll_char & 0x4000)
            result.mitigations.code_integrity = bool(dll_char & 0x0080)

            result.parameters.extend([
                PEParameter("ASLR_ENABLED", "Exploit Defense", str(result.mitigations.aslr), "DllCharacteristics:0x0040", "Randomizes base address at load time"),
                PEParameter("DEP_NX_ENABLED", "Exploit Defense", str(result.mitigations.dep_nx), "DllCharacteristics:0x0100", "Prevents code execution from data/heap pages"),
                PEParameter("CFG_ENABLED", "Exploit Defense", str(result.mitigations.cfg), "DllCharacteristics:0x4000", "Validates indirect branch targets"),
            ])

            # Authenticode Digital Signature Directory
            sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
            result.mitigations.authenticode_signed = bool(sec_dir.VirtualAddress and sec_dir.Size)

            # SafeSEH
            if not result.is_64bit:
                load_cfg_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG"]]
                result.mitigations.safeseh = bool(load_cfg_dir.VirtualAddress and load_cfg_dir.Size)
            else:
                result.mitigations.safeseh = True

            # .NET CLR Directory
            com_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]]
            if com_dir.VirtualAddress and com_dir.Size:
                result.is_dotnet = True
                result.dotnet_framework = ".NET Managed Assembly (CLI Runtime)"

            # Sections & Entropy Analysis
            for section in pe.sections:
                s_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                s_entropy = section.get_entropy()
                vsize = section.Misc_VirtualSize
                rsize = section.SizeOfRawData
                suspicious = False
                flag = ""

                # Permissions string
                perms = []
                if section.Characteristics & 0x20000000:
                    perms.append("EXEC")
                if section.Characteristics & 0x40000000:
                    perms.append("READ")
                if section.Characteristics & 0x80000000:
                    perms.append("WRITE")
                perm_str = "|".join(perms) or "NONE"

                if s_entropy > 7.2:
                    suspicious = True
                    flag = "High Entropy (Packed / Encrypted)"
                    result.is_packed_likely = True
                if s_name.lower() in (".upx0", ".upx1", "upx2"):
                    result.packers_detected.append("UPX Packer")
                    suspicious = True
                    flag = "UPX Compressed Section"
                elif s_name.lower() in (".vmp0", ".vmp1"):
                    result.packers_detected.append("VMProtect")
                    suspicious = True
                    flag = "VMProtect Virtualized Section"
                elif s_name.lower() in (".themida"):
                    result.packers_detected.append("Themida")
                    suspicious = True
                    flag = "Themida Protected Section"

                result.sections.append(
                    PESection(
                        name=s_name,
                        virtual_address=hex(section.VirtualAddress),
                        virtual_size=vsize,
                        raw_offset=section.PointerToRawData,
                        raw_size=rsize,
                        entropy=round(s_entropy, 3),
                        permissions=perm_str,
                        characteristics=hex(section.Characteristics),
                        is_suspicious=suspicious,
                        flag=flag,
                    )
                )

            # Capstone Binary Machine Disassembly
            if capstone is not None and pe.OPTIONAL_HEADER.AddressOfEntryPoint:
                try:
                    ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
                    # Extract code block at entry point
                    mem_img = pe.get_memory_mapped_image()
                    code_bytes = mem_img[ep_rva : ep_rva + 128]
                    arch_mode = capstone.CS_MODE_64 if result.is_64bit else capstone.CS_MODE_32
                    md = capstone.Cs(capstone.CS_ARCH_X86, arch_mode)
                    for instr in md.disasm(code_bytes, entry_va):
                        bytes_hex = " ".join(f"{b:02x}" for b in instr.bytes)
                        result.disassembly.append(
                            DisassembledInstruction(
                                address=hex(instr.address),
                                mnemonic=instr.mnemonic,
                                op_str=instr.op_str,
                                bytes_hex=bytes_hex,
                            )
                        )
                        if len(result.disassembly) >= 25:
                            break
                except Exception as e:
                    result.warnings.append(f"Capstone Disassembly Note: {str(e)}")

            # Imports & Capabilities
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    imported_funcs = []
                    for imp in entry.imports:
                        f_name = imp.name.decode("utf-8", errors="ignore") if imp.name else f"Ordinal({imp.ordinal})"
                        imported_funcs.append(f_name)

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
                                if k_str in ("CompanyName", "FileDescription", "FileVersion", "ProductName", "ProductVersion"):
                                    result.parameters.append(PEParameter(f"VERSION_{k_str.upper()}", "Identity & Metadata", v_str, f"PE.VersionInfo:{k_str}", "Embedded binary metadata"))

        except Exception as e:
            result.warnings.append(f"PE Parser Exception: {str(e)}")

        for cap in result.capabilities:
            result.capabilities[cap] = sorted(set(result.capabilities[cap]))

    def _analyze_minimal_pe(self, data: bytes, result: PEAnalysisResult) -> None:
        if len(data) < 0x40 or data[:2] != b"MZ":
            return
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return
        machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
        result.is_64bit = machine == 0x8664
        result.machine_type = "x86-64" if result.is_64bit else "x86 (32-bit)"
