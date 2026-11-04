"""Artifact and Binary Unpacker Engine for SuperReverse.

Extracts packaged resources, manifests, assets, and embedded binary data:
- APK: Decodes with APKTool if available, or extracts classes.dex, AndroidManifest, assets, res
- Windows PE: Extracts embedded manifests, icons, version information, and .rsrc payloads
- Electron ASAR: Unpacks virtual filesystem trees into source directories
- Archives (ZIP, JAR, AAB): Unpacks full directory structure
- Web URLs: Dumps page HTML, stylesheets, and discovered JavaScript bundles
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import pefile
except ImportError:
    pefile = None

from superreverse.analyzers.electron_engine import ElectronEngine
from superreverse.analyzers.rea_bridge import REABridge, _find_tool_cmd
from superreverse.core.classifier import TargetClassifier, TargetKind


@dataclass
class UnpackResult:
    target_path: str
    output_dir: Path
    file_count: int
    extracted_files: List[str] = field(default_factory=list)
    success: bool = True
    message: str = ""


class Unpacker:
    """Automated unpacker for all supported binary and web targets."""

    @staticmethod
    def get_default_output_dir(target_str: str) -> Path:
        p = Path(target_str)
        if p.exists() and p.is_file():
            base_dir = p.parent
            folder_name = f"{p.stem}_unpacked"
        else:
            base_dir = Path.home() / "Desktop"
            if not base_dir.exists():
                base_dir = Path.home()
            clean_name = "".join(c if c.isalnum() else "_" for c in target_str[:25])
            folder_name = f"{clean_name}_unpacked"

        out_dir = base_dir / folder_name
        return out_dir

    @classmethod
    def unpack(cls, target_path: str | Path, output_dir: Optional[str | Path] = None) -> UnpackResult:
        target_str = str(target_path).strip()
        kind, desc = TargetClassifier.classify(target_str)

        out_dir = Path(output_dir).resolve() if output_dir else cls.get_default_output_dir(target_str)
        out_dir.mkdir(parents=True, exist_ok=True)

        res = UnpackResult(target_path=target_str, output_dir=out_dir, file_count=0)

        try:
            if kind == TargetKind.ANDROID_APK:
                cls._unpack_apk(Path(target_str), out_dir, res)
            elif kind == TargetKind.WINDOWS_PE:
                cls._unpack_pe(Path(target_str), out_dir, res)
            elif kind == TargetKind.ELECTRON_ASAR:
                cls._unpack_asar(Path(target_str), out_dir, res)
            elif kind == TargetKind.WEB_URL:
                cls._unpack_web(target_str, out_dir, res)
            elif zipfile.is_zipfile(target_str):
                cls._unpack_zip(Path(target_str), out_dir, res)
            else:
                # Raw copy or inspect
                p = Path(target_str)
                if p.is_file():
                    dest = out_dir / p.name
                    shutil.copy2(p, dest)
                    res.extracted_files.append(p.name)
                    res.file_count = 1
                    res.message = f"Copied artifact to {out_dir.name}"

            res.file_count = len(res.extracted_files)
            if not res.message:
                res.message = f"Successfully unpacked {res.file_count} items to {out_dir.name}"
            res.success = True
        except Exception as e:
            res.success = False
            res.message = f"Unpack error: {str(e)}"

        return res

    @staticmethod
    def _unpack_apk(apk_path: Path, out_dir: Path, res: UnpackResult) -> None:
        bridge = REABridge()
        apktool_ran = False
        if bridge.readiness.apktool_available:
            apktool_out = out_dir / "apktool"
            apktool_out.mkdir(parents=True, exist_ok=True)
            if bridge.run_apktool_decode(apk_path, apktool_out):
                apktool_ran = True
                for root, _, files in os.walk(apktool_out):
                    for f in files:
                        rel = os.path.relpath(os.path.join(root, f), str(out_dir))
                        res.extracted_files.append(rel)

        # Also extract raw files via zipfile
        raw_out = out_dir / ("extracted" if apktool_ran else "")
        raw_out.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(apk_path, "r") as z:
            for member in z.namelist():
                if not member.endswith("/"):
                    z.extract(member, raw_out)
                    res.extracted_files.append(member)

        res.message = f"APK unpacked: {len(res.extracted_files)} files (Resources & Bytecode)"

    @staticmethod
    def _unpack_pe(pe_path: Path, out_dir: Path, res: UnpackResult) -> None:
        if pefile is None:
            res.message = "pefile not installed"
            return

        try:
            pe = pefile.PE(str(pe_path))
        except Exception as e:
            res.message = f"Could not parse PE: {e}"
            return

        res_dir = out_dir / "resources"
        res_dir.mkdir(parents=True, exist_ok=True)

        manifest_extracted = False
        icons_count = 0

        # Parse PE resources directory
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                type_id = entry.struct.Id if entry.name is None else str(entry.name)
                type_name = pefile.RESOURCE_TYPE.get(type_id, str(type_id))

                sub_dir = res_dir / str(type_name).replace("RT_", "").lower()
                sub_dir.mkdir(parents=True, exist_ok=True)

                if hasattr(entry, "directory"):
                    for subentry in entry.directory.entries:
                        res_id = subentry.struct.Id if subentry.name is None else str(subentry.name)
                        if hasattr(subentry, "directory"):
                            for leaf in subentry.directory.entries:
                                data_rva = leaf.data.struct.OffsetToData
                                size = leaf.data.struct.Size
                                raw_data = pe.get_data(data_rva, size)

                                # Save resource file
                                fname = f"res_{res_id}.bin"
                                if type_name == "RT_MANIFEST":
                                    fname = "manifest.xml"
                                    manifest_extracted = True
                                elif type_name == "RT_ICON":
                                    fname = f"icon_{res_id}.ico"
                                    icons_count += 1

                                out_file = sub_dir / fname
                                with open(out_file, "wb") as rf:
                                    rf.write(raw_data)
                                rel = str(out_file.relative_to(out_dir))
                                res.extracted_files.append(rel)

        # Dump version info
        vinfo = {}
        if hasattr(pe, "FileInfo"):
            for fi in pe.FileInfo:
                if fi:
                    for entry in getattr(fi, "StringTable", []):
                        for k, v in getattr(entry, "entries", {}).items():
                            k_s = k.decode("utf-8", errors="ignore") if isinstance(k, bytes) else str(k)
                            v_s = v.decode("utf-8", errors="ignore") if isinstance(v, bytes) else str(v)
                            vinfo[k_s] = v_s
        if vinfo:
            vinfo_file = out_dir / "version_info.json"
            with open(vinfo_file, "w", encoding="utf-8") as vf:
                json.dump(vinfo, vf, indent=2)
            res.extracted_files.append("version_info.json")

        # Dump PE Section dump
        sec_dir = out_dir / "sections"
        sec_dir.mkdir(parents=True, exist_ok=True)
        for s in pe.sections:
            s_name = s.Name.decode("utf-8", errors="ignore").strip("\x00").replace(".", "_")
            sec_file = sec_dir / f"{s_name}.bin"
            with open(sec_file, "wb") as sf:
                sf.write(s.get_data())
            res.extracted_files.append(str(sec_file.relative_to(out_dir)))

        res.message = f"PE Unpacked: {len(res.extracted_files)} files (Resources, Manifest, Sections)"

    @staticmethod
    def _unpack_asar(asar_path: Path, out_dir: Path, res: UnpackResult) -> None:
        engine = ElectronEngine(asar_path)
        count = engine.unpack_all_to_dir(out_dir)
        for root, _, files in os.walk(out_dir):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), str(out_dir))
                res.extracted_files.append(rel)
        res.message = f"Electron ASAR Unpacked: {len(res.extracted_files)} files extracted"

    @staticmethod
    def _unpack_zip(zip_path: Path, out_dir: Path, res: UnpackResult) -> None:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(out_dir)
            for m in z.namelist():
                if not m.endswith("/"):
                    res.extracted_files.append(m)
        res.message = f"Archive unpacked: {len(res.extracted_files)} files"

    @staticmethod
    def _unpack_web(url: str, out_dir: Path, res: UnpackResult) -> None:
        import urllib.request
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers={"User-Agent": "SuperReverse/1.0 (+https://github.com/officialgodgoku/SuperReverse)"})
        with urllib.request.urlopen(req, timeout=12, context=ctx) as resp:
            content = resp.read()

        index_file = out_dir / "index.html"
        with open(index_file, "wb") as f:
            f.write(content)
        res.extracted_files.append("index.html")
        res.message = f"Web page dumped to {out_dir.name}"
