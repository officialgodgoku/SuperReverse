"""Render animated GIF from actual PySide6 window states."""
import sys
import time
from pathlib import Path
from PIL import Image
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root))

from superreverse.ui.window import MainWindow

app = QApplication.instance() or QApplication(sys.argv)
win = MainWindow()
win.resize(1120, 720)
win.show()
app.processEvents()

frames = []

# Frame 1: Idle state with drop zone
time.sleep(0.1)
app.processEvents()
pm1 = win.grab()
f1 = Image.fromqpixmap(pm1).resize((840, 540), Image.Resampling.LANCZOS)
for _ in range(4):
    frames.append(f1)

# Frame 2: URL / File input active
win.url_input.setText("https://github.com/officialgodgoku")
app.processEvents()
pm2 = win.grab()
f2 = Image.fromqpixmap(pm2).resize((840, 540), Image.Resampling.LANCZOS)
for _ in range(3):
    frames.append(f2)

# Frame 3: Analyzing target
win.drop_label.setText("SuperDrag.apk")
win.progress_bar.show()
win.progress_bar.setValue(35)
win.status_lbl.setText("Extracting strings, APIs and indicators...")
app.processEvents()
pm3 = win.grab()
f3 = Image.fromqpixmap(pm3).resize((840, 540), Image.Resampling.LANCZOS)
for _ in range(3):
    frames.append(f3)

# Frame 4: Running deep engines
win.progress_bar.setValue(75)
win.status_lbl.setText("Running deep reverse engineering engines...")
app.processEvents()
pm4 = win.grab()
f4 = Image.fromqpixmap(pm4).resize((840, 540), Image.Resampling.LANCZOS)
for _ in range(3):
    frames.append(f4)

# Frame 5: Loaded full AI Map
sample_apk = Path(r"C:\Users\Admin\.gemini\antigravity\scratch\superdrag-mobile\SuperDrag.apk")
if sample_apk.exists():
    win.start_analysis(str(sample_apk))
    t0 = time.time()
    while time.time() - t0 < 3.0:
        app.processEvents()
        time.sleep(0.05)

pm5 = win.grab()
f5 = Image.fromqpixmap(pm5).resize((840, 540), Image.Resampling.LANCZOS)
for _ in range(6):
    frames.append(f5)

# Save crisp GIF
gif_path = root / "docs" / "demo.gif"
frames[0].save(
    str(gif_path),
    save_all=True,
    append_images=frames[1:],
    duration=450,
    loop=0,
    optimize=True
)
print(f"[+] Saved crisp real-window demo GIF: {gif_path} ({len(frames)} frames)")
