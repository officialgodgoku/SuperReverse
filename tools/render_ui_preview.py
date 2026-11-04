"""Capture high-resolution screenshots and animated GIF of the updated UI."""
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
win.resize(1180, 750)
win.show()
app.processEvents()

time.sleep(0.1)
app.processEvents()

# Analyze notepad or python
target_sample = Path(r"C:\Windows\System32\notepad.exe")
if not target_sample.exists():
    target_sample = Path(sys.executable)

win.start_analysis(str(target_sample), action="ai_map")
t0 = time.time()
while time.time() - t0 < 3.5:
    app.processEvents()
    time.sleep(0.05)

# 1. Grab Main Visual Map Preview
pm_map = win.grab()
pm_map.save(str(root / "docs" / "preview.png"), "PNG")
print(f"[+] Saved docs/preview.png (Visual AI Map)")

# 2. Switch to Parameters Tab and grab
win.viewer.switch_to_tab("parameters")
app.processEvents()
time.sleep(0.1)
pm_params = win.grab()
pm_params.save(str(root / "docs" / "preview_parameters.png"), "PNG")

# 3. Switch to Decompile Tab and grab
win.viewer.switch_to_tab("decompile")
app.processEvents()
time.sleep(0.1)
pm_dec = win.grab()
pm_dec.save(str(root / "docs" / "preview_disasm.png"), "PNG")

# 4. Generate crisp dynamic animated GIF
frames = []
f_map = Image.fromqpixmap(pm_map).resize((880, 560), Image.Resampling.LANCZOS)
f_params = Image.fromqpixmap(pm_params).resize((880, 560), Image.Resampling.LANCZOS)
f_dec = Image.fromqpixmap(pm_dec).resize((880, 560), Image.Resampling.LANCZOS)

# Reset to idle for start of gif
win.viewer.switch_to_tab("ai_map")
app.processEvents()

for _ in range(4):
    frames.append(f_map)
for _ in range(4):
    frames.append(f_params)
for _ in range(4):
    frames.append(f_dec)

gif_path = root / "docs" / "demo.gif"
frames[0].save(
    str(gif_path),
    save_all=True,
    append_images=frames[1:],
    duration=650,
    loop=0,
    optimize=True
)
print(f"[+] Saved docs/demo.gif ({len(frames)} frames)")
win.close()
