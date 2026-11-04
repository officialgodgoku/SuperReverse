"""Command-line and headless core analysis pipeline for SuperReverse."""
from __future__ import annotations

import argparse
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple

from superreverse.analyzers.apk_engine import APKEngine
from superreverse.analyzers.electron_engine import ElectronEngine
from superreverse.analyzers.native_engine import NativeEngine
from superreverse.analyzers.pe_engine import PEEngine
from superreverse.analyzers.rea_bridge import REABridge
from superreverse.analyzers.strings_engine import StringsEngine
from superreverse.analyzers.web_engine import WebEngine
from superreverse.core.classifier import TargetClassifier, TargetKind
from superreverse.core.generator import AIMapGenerator


def analyze_target(target_path: Path | str, output_path: Optional[Path | str] = None) -> Tuple[Path, str]:
    """Analyze target artifact or Web URL and write AI Software Architecture Map."""
    target_str = str(target_path).strip()
    kind, description = TargetClassifier.classify(target_path)

    strings_engine = StringsEngine()
    strings_intel = None
    apk_data = None
    pe_data = None
    electron_data = None
    native_data = None
    web_data = None

    if kind == TargetKind.WEB_URL:
        # If it was a .url file, extract url
        p = Path(target_str)
        actual_url = target_str
        if p.exists() and p.is_file() and p.suffix.lower() == ".url":
            import configparser
            try:
                cp = configparser.ConfigParser()
                cp.read(p)
                actual_url = cp.get("InternetShortcut", "URL", fallback=target_str)
            except Exception:
                pass

        web_engine = WebEngine(actual_url)
        web_data = web_engine.analyze()
        domain_clean = re.sub(r"[^\w\.-]", "_", web_data.domain or "website")
        default_filename = f"{domain_clean}_AI_MAP.md"

        # Determine output location
        desktop = Path.home() / "Desktop"
        if output_path is not None:
            out_file = Path(output_path).resolve()
        else:
            out_file = desktop / default_filename
    else:
        p = Path(target_str).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Target path does not exist: {p}")

        strings_intel = strings_engine.analyze(p)

        if kind == TargetKind.ANDROID_APK:
            apk_engine = APKEngine(p)
            apk_data = apk_engine.analyze()
        elif kind == TargetKind.WINDOWS_PE:
            pe_engine = PEEngine(p)
            pe_data = pe_engine.analyze()
        elif kind == TargetKind.ELECTRON_ASAR:
            electron_engine = ElectronEngine(p)
            electron_data = electron_engine.analyze()
        elif kind in (TargetKind.LINUX_ELF, TargetKind.MACOS_MACHO, TargetKind.WASM_BINARY):
            native_engine = NativeEngine(p)
            native_data = native_engine.analyze()

        # Determine output path with permission fallback
        if output_path is not None:
            candidate_file = Path(output_path).resolve()
        else:
            if p.is_dir():
                candidate_file = p / f"{p.name}_AI_MAP.md"
            else:
                candidate_file = p.parent / f"{p.stem}_AI_MAP.md"

        out_file = candidate_file

    generator = AIMapGenerator(
        target_path=target_str,
        kind=kind,
        strings_intel=strings_intel,
        apk_data=apk_data,
        pe_data=pe_data,
        electron_data=electron_data,
        native_data=native_data,
        web_data=web_data,
    )

    markdown_content = generator.generate_markdown()

    try:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(markdown_content)
    except (PermissionError, OSError):
        desktop = Path.home() / "Desktop"
        if not desktop.exists():
            desktop = Path.home()
        fallback_file = desktop / out_file.name
        with open(fallback_file, "w", encoding="utf-8") as f:
            f.write(markdown_content)
        out_file = fallback_file

    return out_file, markdown_content


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="superreverse",
        description="SuperReverse — Drag-and-Drop Software & Website AI Architecture Mapper",
    )
    parser.add_argument("target", help="Path to software executable, APK, ASAR, directory, or Website URL")
    parser.add_argument("-o", "--output", help="Optional output markdown file path")
    parser.add_argument("--json", action="store_true", help="Print result summary in JSON")

    args = parser.parse_args(argv)

    try:
        out_file, _ = analyze_target(args.target, args.output)
        print(f"[+] Successfully generated AI Software Map: {out_file}")
    except Exception as e:
        print(f"[-] Error analyzing target: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
