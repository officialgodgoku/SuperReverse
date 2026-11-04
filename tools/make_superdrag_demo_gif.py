"""Render high-resolution preview images and animated demo GIF using SuperDrag.apk."""
import sys
import time
from pathlib import Path
from PIL import Image
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from superreverse.core.cli import analyze_target_bundle
from superreverse.ui.window import MainWindow

app = QApplication.instance() or QApplication(sys.argv)
win = MainWindow()
win.resize(1180, 740)
win.show()
app.processEvents()

time.sleep(0.1)
app.processEvents()

apk_path = Path(r"C:\Users\Admin\.gemini\antigravity\scratch\superdrag-mobile\SuperDrag.apk")
if not apk_path.exists():
    raise FileNotFoundError(f"SuperDrag.apk not found at {apk_path}")

frames = []

# Frame 1: Idle state
app.processEvents()
f_idle = Image.fromqpixmap(win.grab()).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(4):
    frames.append(f_idle)

# Frame 2: Dropping SuperDrag.apk (hovering petal)
win.radial_dial.hovered_index = 0  # AI Map petal glowing
win.drop_label.setText("SuperDrag.apk")
win.radial_dial.set_target("SuperDrag.apk")
app.processEvents()
f_drop = Image.fromqpixmap(win.grab()).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(3):
    frames.append(f_drop)

# Frame 3: Progress Scanning Step 1
win.radial_dial.hovered_index = -1
win.progress_bar.show()
win.progress_bar.setValue(35)
win.status_lbl.setText("Extracting DEX classes, permissions, SQLite entities & endpoints...")
app.processEvents()
f_scan1 = Image.fromqpixmap(win.grab()).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(3):
    frames.append(f_scan1)

# Frame 4: Progress Scanning Step 2
win.progress_bar.setValue(75)
win.status_lbl.setText("Synthesizing AI Architecture Blueprint & Parameters Matrix...")
app.processEvents()
f_scan2 = Image.fromqpixmap(win.grab()).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(3):
    frames.append(f_scan2)

# Run full bundle analysis on SuperDrag.apk
bundle = analyze_target_bundle(apk_path)
win.last_bundle = bundle
win.active_target = str(apk_path)
win.progress_bar.setValue(100)
win.status_lbl.setText(f"✅ Generated: {bundle.out_file.name}")
win.viewer.load_bundle(bundle)
app.processEvents()
time.sleep(0.2)
app.processEvents()

# Frame 5: Tab 0 - AI Map (Master Blueprint)
win.viewer.switch_to_tab("ai_map")
app.processEvents()
time.sleep(0.1)
pm_map = win.grab()
pm_map.save(str(root / "docs" / "preview.png"), "PNG")
f_map = Image.fromqpixmap(pm_map).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(6):
    frames.append(f_map)

# Frame 6: Tab 1 - Tweakable Parameters Matrix
win.viewer.switch_to_tab("parameters")
app.processEvents()
time.sleep(0.1)
pm_params = win.grab()
pm_params.save(str(root / "docs" / "preview_parameters.png"), "PNG")
f_params = Image.fromqpixmap(pm_params).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(5):
    frames.append(f_params)

# Frame 7: Tab 3 - Decompiled Code & Sources
win.viewer.switch_to_tab("decompile")
app.processEvents()
time.sleep(0.1)
pm_dec = win.grab()
pm_dec.save(str(root / "docs" / "preview_disasm.png"), "PNG")
f_dec = Image.fromqpixmap(pm_dec).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(5):
    frames.append(f_dec)

# Frame 8: Tab 2 - Security Posture & Frida Scripts
win.viewer.switch_to_tab("security")
app.processEvents()
time.sleep(0.1)
pm_sec = win.grab()
f_sec = Image.fromqpixmap(pm_sec).resize((880, 550), Image.Resampling.LANCZOS)
for _ in range(5):
    frames.append(f_sec)

# Save animated GIF
gif_path = root / "docs" / "demo.gif"
frames[0].save(
    str(gif_path),
    save_all=True,
    append_images=frames[1:],
    duration=450,
    loop=0,
    optimize=True
)
print(f"[+] Saved docs/demo.gif using SuperDrag example ({len(frames)} frames)")
print(f"[+] Updated docs/preview.png with clean SuperDrag AI Map")

win.close()
