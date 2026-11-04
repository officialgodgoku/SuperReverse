#!/bin/bash
# Builds a Debian / Ubuntu .deb package for SuperReverse
set -euo pipefail

VERSION="1.0.0"
ARCH="amd64"
PKG_NAME="superreverse_${VERSION}_${ARCH}"
BUILD_ROOT="/tmp/${PKG_NAME}"

rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT/usr/local/bin"
mkdir -p "$BUILD_ROOT/usr/share/applications"
mkdir -p "$BUILD_ROOT/usr/share/icons/hicolor/512x512/apps"
mkdir -p "$BUILD_ROOT/usr/lib/superreverse"
mkdir -p "$BUILD_ROOT/DEBIAN"

cat << EOF > "$BUILD_ROOT/DEBIAN/control"
Package: superreverse
Version: ${VERSION}
Section: devel
Priority: optional
Architecture: ${ARCH}
Maintainer: Manish <officialgodgoku@users.noreply.github.com>
Description: Autonomous AI Software & Web Architecture Mapper
 Fluid liquid-glass drag-and-drop reverse engineering and AI architecture mapper
 covering APK, PE, ELF, Mach-O, ASAR, WASM, and live websites.
EOF

# Copy binaries/scripts
cp dist/superreverse "$BUILD_ROOT/usr/lib/superreverse/superreverse-bin" 2>/dev/null || true
cp superreverse/assets/icon.png "$BUILD_ROOT/usr/share/icons/hicolor/512x512/apps/superreverse.png"
cp packaging/linux/superreverse.desktop "$BUILD_ROOT/usr/share/applications/"

cat << 'EOF' > "$BUILD_ROOT/usr/local/bin/superreverse"
#!/bin/bash
exec /usr/lib/superreverse/superreverse-bin "$@"
EOF
chmod +x "$BUILD_ROOT/usr/local/bin/superreverse"

dpkg-deb --build "$BUILD_ROOT"
mv "/tmp/${PKG_NAME}.deb" .
echo "[+] Generated ${PKG_NAME}.deb"
