"""Smoke tests for SuperReverse core engines and generators."""
import sys
from pathlib import Path

# Add project root
root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from superreverse.core.classifier import TargetClassifier, TargetKind
from superreverse.core.cli import analyze_target
from superreverse.analyzers.rea_bridge import REABridge


def test_real_apk():
    apk_path = Path(r"C:\Users\Admin\.gemini\antigravity\scratch\superdrag-mobile\SuperDrag.apk")
    if not apk_path.exists():
        print("[!] Warning: SuperDrag.apk not found, skipping apk test.")
        return

    kind, desc = TargetClassifier.classify(apk_path)
    print(f"[+] APK Classification: {kind} ({desc})")
    assert kind == TargetKind.ANDROID_APK

    out_file, content = analyze_target(apk_path)
    print(f"[+] Generated APK AI Map: {out_file}")
    assert out_file.exists()
    assert "## 1. Executive Summary & Machine Signature" in content
    assert "## 2. Security Posture" in content
    assert "## 3. High-Level Architecture" in content
    assert "## 8. Reconstruction Obligation Ledger" in content
    print("[+] APK Test Passed!")


def test_real_pe():
    # Use python.exe or DragShift-Setup.exe
    pe_path = Path(sys.executable)
    kind, desc = TargetClassifier.classify(pe_path)
    print(f"[+] PE Classification for python.exe: {kind} ({desc})")
    assert kind == TargetKind.WINDOWS_PE

    out_file, content = analyze_target(pe_path)
    print(f"[+] Generated PE AI Map: {out_file}")
    assert out_file.exists()
    assert "Windows PE Mitigations & Hardening Matrix" in content
    assert "ASLR" in content
    assert "Reconstruction Obligation Ledger" in content
    print("[+] PE Test Passed!")


def test_rea_bridge():
    bridge = REABridge()
    r = bridge.readiness
    print(f"[+] REA Readiness: REA={r.rea_available} ({r.rea_version}), JADX={r.jadx_available} ({r.jadx_version}), APKTool={r.apktool_available} ({r.apktool_version})")


def test_web_url():
    url = "https://example.com"
    kind, desc = TargetClassifier.classify(url)
    print(f"[+] Web Classification: {kind} ({desc})")
    assert kind == TargetKind.WEB_URL

    out_file, content = analyze_target(url)
    print(f"[+] Generated Web AI Map: {out_file}")
    assert out_file.exists()
    assert "Live Web Application & URL" in content
    assert "Web Application Security Headers Audit" in content
    assert "Discovered Assets" in content
    print("[+] Web Test Passed!")


if __name__ == "__main__":
    test_rea_bridge()
    test_real_pe()
    test_real_apk()
    test_web_url()
    print("\n[SUCCESS] ALL SMOKE TESTS PASSED COMPLETELY!")
