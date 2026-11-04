"""Main launcher for SuperReverse.

Run GUI:
    python run.py

Run CLI Headless:
    python run.py <path_to_binary_or_apk>
"""
import io
import sys
from pathlib import Path

# Fix for windowed PyInstaller builds where stdout/stderr may be None
if sys.stdout is None:
    sys.stdout = io.StringIO()
if sys.stderr is None:
    sys.stderr = io.StringIO()

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

if __name__ == "__main__":
    # If user provided a target file as CLI argument with --cli or in headless mode:
    if len(sys.argv) > 1 and ("--cli" in sys.argv or "--help" in sys.argv or "-h" in sys.argv):
        from superreverse.core.cli import main as cli_main
        sys.argv = [a for a in sys.argv if a != "--cli"]
        cli_main(sys.argv[1:])
    else:
        from superreverse.app import main as gui_main
        sys.exit(gui_main(sys.argv[1:]))
