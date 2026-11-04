"""Smoke tests for SuperReverse core engines, generator, and unpacker."""
import sys
from pathlib import Path

# Add project root
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from superreverse.analyzers.rea_bridge import REABridge
from superreverse.core.classifier import TargetClassifier, TargetKind
from superreverse.core.cli import analyze_target, analyze_target_bundle
from superreverse.core.unpacker import Unpacker


def test_rea_bridge():
    bridge = REABridge()
    r = bridge.readiness
    print(f"[+] REA Readiness: REA={r.rea_available} ({r.rea_version}), JADX={r.jadx_available} ({r.jadx_version}), APKTool={r.apktool_available} ({r.apktool_version})")


def test_real_pe():
    pe_path = Path(sys.executable)
    kind, desc = TargetClassifier.classify(pe_path)
    print(f"[+] PE Classification for python.exe: {kind} ({desc})")
    assert kind == TargetKind.WINDOWS_PE

    bundle = analyze_target_bundle(pe_path)
    print(f"[+] Generated PE AI Map: {bundle.out_file}")
    assert bundle.out_file.exists()
    content = bundle.markdown_content
    assert "Executive Software Identity" in content
    assert "System Architecture Flowchart" in content
    assert "End-to-End Execution Sequence Diagram" in content
    assert "Complete Tweakable Parameter & Configuration Matrix" in content
    assert "ASLR" in content
    assert "Reconstruction Obligation Ledger" in content
    assert len(bundle.pe_data.parameters) > 0
    print(f"[+] PE Test Passed! Discovered {len(bundle.pe_data.parameters)} parameters.")


def test_real_apk():
    apk_path = Path(r"C:\Users\Admin\.gemini\antigravity\scratch\superdrag-mobile\SuperDrag.apk")
    if not apk_path.exists():
        print("[!] Warning: SuperDrag.apk not found, skipping apk test.")
        return

    kind, desc = TargetClassifier.classify(apk_path)
    print(f"[+] APK Classification: {kind} ({desc})")
    assert kind == TargetKind.ANDROID_APK

    bundle = analyze_target_bundle(apk_path)
    print(f"[+] Generated APK AI Map: {bundle.out_file}")
    assert bundle.out_file.exists()
    content = bundle.markdown_content
    assert "Executive Software Identity" in content
    assert "Complete Tweakable Parameter & Configuration Matrix" in content
    assert "Reconstruction Obligation Ledger" in content
    print("[+] APK Test Passed!")


def test_web_url():
    url = "https://example.com"
    kind, desc = TargetClassifier.classify(url)
    print(f"[+] Web Classification: {kind} ({desc})")
    assert kind == TargetKind.WEB_URL

    bundle = analyze_target_bundle(url)
    print(f"[+] Generated Web AI Map: {bundle.out_file}")
    assert bundle.out_file.exists()
    content = bundle.markdown_content
    assert "Executive Software Identity" in content
    assert "Direct AI Prompt Injection Card" in content
    print("[+] Web Test Passed!")


def test_unpacker():
    pe_path = Path(sys.executable)
    import tempfile
    td = Path(tempfile.mkdtemp())
    res = Unpacker.unpack(pe_path, td)
    assert res.success
    assert res.file_count > 0
    print(f"[+] Unpacker Test Passed! Unpacked {res.file_count} files into {td}")


if __name__ == "__main__":
    test_rea_bridge()
    test_real_pe()
    test_real_apk()
    test_web_url()
    test_unpacker()
    print("\n[SUCCESS] ALL SMOKE TESTS PASSED COMPLETELY!")
