#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "======================================================"
echo "    Building Au1Password Production AppImage          "
echo "======================================================"

# 1. Build Rust Release Binaries
echo "[1/5] Compiling Rust release binaries..."
cargo build --release

# 2. Download appimagetool if not present
if [ ! -f "tools/appimagetool" ]; then
  echo "[2/5] Downloading appimagetool..."
  mkdir -p tools
  curl -L -o tools/appimagetool "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage"
  chmod +x tools/appimagetool
else
  echo "[2/5] Using existing tools/appimagetool..."
fi

# 3. Prepare AppDir Structure
echo "[3/5] Constructing AppDir bundle..."
APPDIR="build/OtterVault.AppDir"
rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/otter-vault/app"
mkdir -p "$APPDIR/usr/share/icons/hicolor/scalable/apps"
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$APPDIR/usr/share/applications"

# Copy Rust CLI binary
cp "target/release/otter-cli" "$APPDIR/usr/bin/otter-cli"

# Copy App files
cp "app/server.py" "$APPDIR/usr/share/otter-vault/app/server.py"
cp "app/index.html" "$APPDIR/usr/share/otter-vault/app/index.html"

# Copy Desktop Entry and Icons
cp "resources/otter-vault.desktop" "$APPDIR/otter-vault.desktop"
cp "resources/otter-vault.desktop" "$APPDIR/usr/share/applications/otter-vault.desktop"
cp "resources/otter-vault.svg" "$APPDIR/otter-vault.svg"
cp "resources/otter-vault.svg" "$APPDIR/usr/share/icons/hicolor/scalable/apps/otter-vault.svg"

# Rasterize 256x256 PNG icon
if command -v rsvg-convert >/dev/null 2>&1; then
  rsvg-convert -w 256 -h 256 "resources/otter-vault.svg" -o "$APPDIR/otter-vault.png"
elif command -v magick >/dev/null 2>&1; then
  magick -background none "resources/otter-vault.svg" -resize 256x256 "$APPDIR/otter-vault.png"
elif command -v convert >/dev/null 2>&1; then
  convert -background none "resources/otter-vault.svg" -resize 256x256 "$APPDIR/otter-vault.png"
fi

if [ -f "$APPDIR/otter-vault.png" ]; then
  cp "$APPDIR/otter-vault.png" "$APPDIR/usr/share/icons/hicolor/256x256/apps/otter-vault.png"
  cp "$APPDIR/otter-vault.png" "$APPDIR/.DirIcon"
fi

# Create AppRun Script
cat << 'EOF' > "$APPDIR/AppRun"
#!/usr/bin/env bash
set -e

APPDIR="$(dirname "$(readlink -f "$0")")"
export APPDIR
export PATH="$APPDIR/usr/bin:$PATH"
export XDG_DATA_DIRS="$APPDIR/usr/share:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"

BIN_NAME="$(basename "$0")"
if [ "$BIN_NAME" = "otter-cli" ]; then
  exec "$APPDIR/usr/bin/otter-cli" "$@"
fi

case "${1:-}" in
  --cli|init|add-login|add-note|list|get|status)
    if [ "${1:-}" = "--cli" ]; then
      shift
    fi
    exec "$APPDIR/usr/bin/otter-cli" "$@"
    ;;
  --help|-h)
    cat << 'HELPEOF'
Au1Password - Linux Personal Zero-Knowledge Cloud-Sync Vault

Usage:
  Au1Password [OPTIONS]
  Au1Password --cli [SUBCOMMAND]

Options:
  --gui            Launch native Linux desktop GUI (default)
  --headless       Run local vault backend server in headless mode
  --browser        Launch server and open in default system browser
  --cli <CMD>      Run fast native Rust CLI utility (e.g. list, get, add-login)
  --help, -h       Show this help message

CLI Subcommands:
  init             Initialize a new encrypted vault
  add-login        Store a login credential
  add-note         Store an encrypted secure note
  list             List all stored items
  get <ID>         Retrieve and decrypt an item
  status           Show vault encryption and Google Drive sync status

HELPEOF
    exit 0
    ;;
  *)
    exec python3 "$APPDIR/usr/share/otter-vault/app/server.py" "$@"
    ;;
esac
EOF
chmod +x "$APPDIR/AppRun"

# 4. Generate AppImage using appimagetool
echo "[4/5] Packaging AppImage using appimagetool..."
mkdir -p dist
OUTPUT_APPIMAGE="dist/Au1Password-1.0.0-x86_64.AppImage"
rm -f "$OUTPUT_APPIMAGE"

export ARCH=x86_64
./tools/appimagetool --appimage-extract-and-run "$APPDIR" "$OUTPUT_APPIMAGE"
chmod +x "$OUTPUT_APPIMAGE"
cp "$OUTPUT_APPIMAGE" "dist/OtterVault-1.0.0-x86_64.AppImage"

# 5. Success
echo "[5/5] AppImage generated successfully!"
ls -lh "$OUTPUT_APPIMAGE"
echo "======================================================"
echo "Ready: $OUTPUT_APPIMAGE"
echo "To test GUI: ./$OUTPUT_APPIMAGE"
echo "To test CLI: ./$OUTPUT_APPIMAGE --cli list"
echo "======================================================"
