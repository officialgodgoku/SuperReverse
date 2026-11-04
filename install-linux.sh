#!/bin/bash
# SuperReverse installer for Linux (Ubuntu, Debian, Fedora, Arch, etc.)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/officialgodgoku/SuperReverse/main/install-linux.sh | bash
set -euo pipefail

REPO="officialgodgoku/SuperReverse"
echo "=== SuperReverse Linux Setup ==="
echo "Author: Manish (@officialgodgoku)"
echo "Repo: https://github.com/$REPO"

if ! command -v python3 &>/dev/null; then
    echo "[-] Python 3 not found. Please install Python 3:"
    echo "    sudo apt install python3 python3-pip python3-venv (Debian/Ubuntu)"
    echo "    sudo dnf install python3 python3-pip (Fedora)"
    exit 1
fi

INSTALL_DIR="$HOME/.local/share/superreverse"
mkdir -p "$INSTALL_DIR"

if [ ! -d "$INSTALL_DIR/repo" ]; then
    echo "[+] Cloning SuperReverse repository..."
    git clone --depth 1 "https://github.com/$REPO.git" "$INSTALL_DIR/repo"
else
    echo "[+] Updating SuperReverse repository..."
    cd "$INSTALL_DIR/repo" && git pull --quiet || true
fi

cd "$INSTALL_DIR/repo"

if [ ! -d "$INSTALL_DIR/venv" ]; then
    echo "[+] Setting up isolated Python environment..."
    python3 -m venv "$INSTALL_DIR/venv"
fi

echo "[+] Installing dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt --quiet

# Create command launcher in ~/.local/bin
mkdir -p "$HOME/.local/bin"
LAUNCHER="$HOME/.local/bin/superreverse"
cat << 'EOF' > "$LAUNCHER"
#!/bin/bash
exec "$HOME/.local/share/superreverse/venv/bin/python" "$HOME/.local/share/superreverse/repo/run.py" "$@"
EOF
chmod +x "$LAUNCHER"

# Install Desktop file and Icon
mkdir -p "$HOME/.local/share/applications"
mkdir -p "$HOME/.local/share/icons/hicolor/512x512/apps"

cp "$INSTALL_DIR/repo/superreverse/assets/icon.png" "$HOME/.local/share/icons/hicolor/512x512/apps/superreverse.png" 2>/dev/null || true

cat << EOF > "$HOME/.local/share/applications/superreverse.desktop"
[Desktop Entry]
Name=SuperReverse
Comment=Autonomous AI Software & Web Architecture Mapper
Exec=$LAUNCHER %F
Icon=superreverse
Terminal=false
Type=Application
Categories=Development;Security;ReverseEngineering;Utility;
MimeType=application/x-executable;application/x-sharedlib;application/vnd.android.package-archive;application/zip;
Keywords=reverse;engineering;binary;decompiler;frida;apk;pe;ai;
EOF
chmod +x "$HOME/.local/share/applications/superreverse.desktop"

echo "[SUCCESS] SuperReverse is installed and ready on Linux!"
echo "• Added to your application menu"
echo "• CLI command: superreverse <target>"
"$LAUNCHER" >/dev/null 2>&1 &
