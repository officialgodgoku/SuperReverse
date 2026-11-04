"""Generates sleek preview mockups and animated GIFs for SuperReverse README documentation."""
import math
import os
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

docs_dir = Path(__file__).resolve().parent.parent / "docs"
assets_dir = Path(__file__).resolve().parent.parent / "superreverse" / "assets"
docs_dir.mkdir(parents=True, exist_ok=True)
assets_dir.mkdir(parents=True, exist_ok=True)


def create_banner():
    width, height = 1200, 360
    img = Image.new("RGBA", (width, height), (16, 14, 24, 255))
    draw = ImageDraw.Draw(img)

    # Draw gradient mesh lines
    for x in range(0, width, 40):
        draw.line([(x, 0), (x, height)], fill=(255, 255, 255, 8), width=1)
    for y in range(0, height, 40):
        draw.line([(0, y), (width, y)], fill=(255, 255, 255, 8), width=1)

    # Glowing radial accent circles
    for r in range(160, 0, -2):
        alpha = int(35 * (1 - r / 160))
        draw.ellipse([width // 2 - r, height // 2 - r, width // 2 + r, height // 2 + r], fill=(0, 240, 255, alpha))

    # Iridescent border
    draw.rounded_rectangle([10, 10, width - 10, height - 10], radius=24, outline=(0, 240, 255, 120), width=2)

    # Title & Subtitle text
    try:
        font_large = ImageFont.truetype("arialbd.ttf", 64)
        font_sub = ImageFont.truetype("arial.ttf", 24)
        font_small = ImageFont.truetype("arial.ttf", 18)
    except Exception:
        font_large = font_sub = font_small = ImageFont.load_default()

    draw.text((width // 2, 90), "⚡ SuperReverse", fill=(255, 255, 255), anchor="mm", font=font_large)
    draw.text((width // 2, 175), "Autonomous AI Software & Web Architecture Mapper", fill=(0, 240, 255), anchor="mm", font=font_sub)
    draw.text((width // 2, 225), "REA (Reverse Engineer Anything) + APK-Reverse + Web Engine in Liquid Glass", fill=(200, 200, 220), anchor="mm", font=font_small)
    draw.text((width // 2, 285), "Created by Manish (@officialgodgoku)", fill=(255, 221, 0), anchor="mm", font=font_sub)

    banner_path = docs_dir / "banner.png"
    img.save(banner_path, "PNG")
    print(f"[+] Created {banner_path}")


def create_preview_mockup():
    width, height = 1120, 680
    img = Image.new("RGBA", (width, height), (14, 12, 22, 255))
    draw = ImageDraw.Draw(img)

    # Glass Window Frame
    draw.rounded_rectangle([15, 15, width - 15, height - 15], radius=20, fill=(20, 18, 30, 240), outline=(0, 240, 255, 160), width=2)

    # Title Bar
    draw.line([(15, 65), (width - 15, 65)], fill=(255, 255, 255, 30), width=1)
    try:
        font_title = ImageFont.truetype("arialbd.ttf", 20)
        font_body = ImageFont.truetype("arial.ttf", 14)
        font_mono = ImageFont.truetype("consola.ttf", 13)
        font_heading = ImageFont.truetype("arialbd.ttf", 16)
    except Exception:
        font_title = font_body = font_mono = font_heading = ImageFont.load_default()

    draw.text((40, 38), "⚡ SuperReverse  •  by Manish (@officialgodgoku)", fill=(255, 255, 255), anchor="lm", font=font_title)
    draw.text((width - 60, 38), "🗕  ✕", fill=(200, 200, 200), anchor="mm", font=font_title)

    # Split: Left Panel (Drop Zone & Radial Hub)
    split_x = 440
    draw.line([(split_x, 65), (split_x, height - 15)], fill=(255, 255, 255, 20), width=1)

    # Left Drop Zone Box
    draw.rounded_rectangle([35, 85, split_x - 25, 260], radius=16, fill=(255, 255, 255, 8), outline=(0, 240, 255, 100), width=2)
    draw.text(((35 + split_x - 25) // 2, 130), "📥", fill=(255, 255, 255), anchor="mm", font=font_title)
    draw.text(((35 + split_x - 25) // 2, 170), "Drag & Drop Any Software or URL Here", fill=(255, 255, 255), anchor="mm", font=font_heading)
    draw.text(((35 + split_x - 25) // 2, 205), "APK, EXE, DLL, ELF, ASAR, WASM, or https://...", fill=(160, 160, 180), anchor="mm", font=font_body)

    # URL input box inside left
    draw.rounded_rectangle([50, 222, split_x - 40, 250], radius=8, fill=(0, 0, 0, 80), outline=(255, 255, 255, 40))
    draw.text((60, 236), "🌐 https://github.com/officialgodgoku", fill=(0, 240, 255), anchor="lm", font=font_mono)

    # Radial Hub Mockup (Bottom Left)
    cx, cy = (35 + split_x - 25) // 2, 455
    r_out, r_in = 135, 55
    # Slices
    colors = [(255, 107, 157), (255, 179, 107), (255, 230, 107), (125, 255, 176), (107, 213, 255), (138, 123, 255)]
    labels = ["🗺️ AI Map", "🛡️ Security", "📦 Unpack", "☕ Decompile", "🔍 Strings", "📋 Prompt"]
    for i in range(6):
        a_mid = i * (2 * math.pi / 6)
        tx = cx + 95 * math.cos(a_mid)
        ty = cy + 95 * math.sin(a_mid)
        draw.ellipse([tx - 28, ty - 18, tx + 28, ty + 18], fill=(35, 30, 55, 220), outline=colors[i], width=1)
        draw.text((tx, ty), labels[i], fill=(255, 255, 255), anchor="mm", font=font_body)

    # Center Hub
    draw.ellipse([cx - r_in, cy - r_in, cx + r_in, cy + r_in], fill=(28, 24, 45, 245), outline=(0, 240, 255, 200), width=2)
    draw.text((cx, cy - 8), "⚡", fill=(255, 255, 255), anchor="mm", font=font_title)
    draw.text((cx, cy + 14), "SuperReverse", fill=(0, 240, 255), anchor="mm", font=font_body)

    # Right Panel: Markdown Visual Map Viewer
    rx = split_x + 25
    draw.text((rx, 90), "🗺️ AI Software Architecture Blueprint: SuperDrag.apk", fill=(255, 255, 255), anchor="lm", font=font_heading)

    # Action buttons top right
    draw.rounded_rectangle([width - 240, 80, width - 40, 110], radius=8, fill=(0, 240, 255, 35), outline=(0, 240, 255, 120))
    draw.text((width - 140, 95), "📋 Copy for AI Prompt", fill=(0, 240, 255), anchor="mm", font=font_body)

    # Blueprint content preview
    lines = [
        ("## 1. Executive Summary & Machine Signature", (255, 156, 251)),
        ("• Target Artifact: SuperDrag.apk  |  Platform: Android APK / AAB", (220, 220, 220)),
        ("• SHA-256: 2559b98507b167aa0ac90e522640d7fad2ab64539e10e1930bc557b41d0a2f2c", (100, 220, 255)),
        ("• Package ID: com.officialgodgoku.superdrag  |  Version: 1.0", (220, 220, 220)),
        ("• Tech Stack: Apache Cordova / Ionic  |  Classes: ~2603 in 6 DEX files", (220, 220, 220)),
        ("", (220, 220, 220)),
        ("## 2. Security Posture & Vulnerability Matrix", (255, 156, 251)),
        ("• Debuggable: 🔴 ENABLED (CRITICAL: memory attach permitted in production)", (255, 100, 100)),
        ("• ADB Backup: 🟡 ALLOWED (Risk: private data extractable via adb backup)", (255, 200, 80)),
        ("• Cleartext HTTP: 🟢 Blocked  |  Signature: v2/v3/v4 APK Signature Scheme", (100, 255, 150)),
        ("", (220, 220, 220)),
        ("## 3. High-Level Architecture Flow (Mermaid)", (255, 156, 251)),
        ("Zygote Fork ➔ Application.onCreate() ➔ UI Main Thread ➔ Cordova Engine Dispatcher", (255, 221, 0)),
        ("", (220, 220, 220)),
        ("## 8. Reconstruction Obligation Ledger (For AI Rebuilding)", (255, 156, 251)),
        ("[x] Core Lifecycle Initialization in App class", (180, 180, 180)),
        ("[ ] Reconstruct Exported Component `com.officialgodgoku.superdrag.MainActivity`", (180, 180, 180)),
        ("[ ] Implement Native Interop for libflutter.so / libnative.so", (180, 180, 180)),
        ("", (220, 220, 220)),
        ("## 9. Dynamic Instrumentation & Frida Playbook", (255, 156, 251)),
        ("• Universal SSL Pinning Bypass (`ssl_bypass.js`) ➔ OkHttp3 + TrustManager", (100, 240, 255)),
        ("• Root & Anti-Tamper Bypass (`root_bypass.js`) ➔ Magisk & SafetyNet hooks", (100, 240, 255)),
    ]

    y = 135
    for text, col in lines:
        if text.startswith("##"):
            draw.text((rx, y), text, fill=col, anchor="lm", font=font_heading)
            y += 26
        else:
            draw.text((rx + 8, y), text, fill=col, anchor="lm", font=font_mono)
            y += 22

    preview_path = docs_dir / "preview.png"
    img.save(preview_path, "PNG")
    print(f"[+] Created {preview_path}")


def create_animated_demo_gif():
    width, height = 760, 480
    frames = []

    statuses = [
        ("Ready", "Waiting for software drop or URL...", 0),
        ("Drop Detected!", "Analyzing SuperDrag.apk (5.79 MB)...", 15),
        ("Extracting Headers...", "Parsing AndroidManifest.xml (Binary AXML)...", 35),
        ("DEX & Framework Scan...", "Decompiling 6 DEX files & Framework fingerprinting...", 60),
        ("Security Audit...", "Evaluating Mitigations, Permissions & Signatures...", 85),
        ("AI Blueprint Complete!", "Generated SuperDrag_AI_MAP.md with Mermaid diagrams", 100),
    ]

    try:
        font_large = ImageFont.truetype("arialbd.ttf", 26)
        font_sub = ImageFont.truetype("arial.ttf", 16)
        font_mono = ImageFont.truetype("consola.ttf", 14)
    except Exception:
        font_large = font_sub = font_mono = ImageFont.load_default()

    for title, desc, pct in statuses:
        # Create 4 frames per status for smooth delay
        for step in range(3):
            img = Image.new("RGBA", (width, height), (16, 14, 24, 255))
            draw = ImageDraw.Draw(img)

            # Outer liquid glass window
            draw.rounded_rectangle([12, 12, width - 12, height - 12], radius=18, fill=(22, 18, 32, 245), outline=(0, 240, 255, 150), width=2)

            # Title
            draw.text((36, 40), "⚡ SuperReverse  •  by Manish (@officialgodgoku)", fill=(255, 255, 255), anchor="lm", font=font_large)
            draw.text((width - 36, 40), "☕ Buy Me a Coffee", fill=(255, 221, 0), anchor="rm", font=font_sub)

            # Drop card
            draw.rounded_rectangle([40, 80, width - 40, 360], radius=16, fill=(0, 0, 0, 70), outline=(0, 240, 255, 90), width=1)

            draw.text((width // 2, 140), "📥" if pct < 100 else "🗺️", fill=(255, 255, 255), anchor="mm", font=font_large)
            draw.text((width // 2, 195), title, fill=(0, 240, 255), anchor="mm", font=font_large)
            draw.text((width // 2, 240), desc, fill=(210, 210, 230), anchor="mm", font=font_sub)

            # Progress Bar
            bar_w = 460
            bar_x = (width - bar_w) // 2
            bar_y = 290
            draw.rounded_rectangle([bar_x, bar_y, bar_x + bar_w, bar_y + 14], radius=7, fill=(255, 255, 255, 20))
            if pct > 0:
                fill_w = int(bar_w * (pct / 100))
                draw.rounded_rectangle([bar_x, bar_y, bar_x + fill_w, bar_y + 14], radius=7, fill=(0, 240, 255, 230))

            draw.text((width // 2, 330), f"{pct}% Complete", fill=(180, 180, 200), anchor="mm", font=font_mono)

            # Footer
            draw.text((width // 2, 420), "Created with 💖 by Manish (@officialgodgoku) • MIT License", fill=(140, 140, 160), anchor="mm", font=font_sub)

            frames.append(img.convert("RGB"))

    gif_path = docs_dir / "demo.gif"
    frames[0].save(gif_path, save_all=True, append_images=frames[1:], duration=350, loop=0)
    print(f"[+] Created {gif_path}")


if __name__ == "__main__":
    create_banner()
    create_preview_mockup()
    create_animated_demo_gif()
    print("[SUCCESS] All visual documentation assets created!")
