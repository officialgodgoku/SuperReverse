#!/bin/bash
# SuperReverse installer & runner for macOS (Apple Silicon & Intel)
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/officialgodgoku/SuperReverse/main/install-mac.sh | bash
set -euo pipefail

REPO="officialgodgoku/SuperReverse"
echo "=== SuperReverse macOS Setup ==="
echo "Author: Manish (@officialgodgoku)"
echo "Repo: https://github.com/$REPO"

# Check Python 3
if ! command -v python3 &>/dev/null; then
    echo "[-] Python 3 not found. Please install Python 3 or Homebrew:"
    echo "    brew install python"
    exit 1
fi

INSTALL_DIR="$HOME/.superreverse"
mkdir -p "$INSTALL_DIR"

if [ ! -d "$INSTALL_DIR/repo" ]; then
    echo "[+] Cloning SuperReverse repository..."
    git clone --depth 1 "https://github.com/$REPO.git" "$INSTALL_DIR/repo"
else
    echo "[+] Updating SuperReverse repository..."
    cd "$INSTALL_DIR/repo" && git pull --quiet || true
fi

cd "$INSTALL_DIR/repo"

# Setup virtualenv
if [ ! -d "$INSTALL_DIR/venv" ]; then
    echo "[+] Creating virtual environment..."
    python3 -m venv "$INSTALL_DIR/venv"
fi

echo "[+] Installing / Verifying dependencies..."
"$INSTALL_DIR/venv/bin/pip" install --upgrade pip --quiet
"$INSTALL_DIR/venv/bin/pip" install -r requirements.txt --quiet

# Create symlink in ~/.local/bin
mkdir -p "$HOME/.local/bin"
LAUNCHER="$HOME/.local/bin/superreverse"
cat << 'EOF' > "$LAUNCHER"
#!/bin/bash
exec "$HOME/.superreverse/venv/bin/python" "$HOME/.superreverse/repo/run.py" "$@"
EOF
chmod +x "$LAUNCHER"

echo "[SUCCESS] SuperReverse installed successfully!"
echo "You can now run 'superreverse' from your terminal or launch via:"
echo "    $LAUNCHER"

# Launch in background
nohup "$LAUNCHER" >/dev/null 2>&1 &
echo "[+] SuperReverse is starting up!"
