#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

echo "======================================================"
echo "    Installing Au1Password for Current Linux User     "
echo "======================================================"

# 1. Build if AppImage does not exist
if [ ! -f "dist/Au1Password-1.0.0-x86_64.AppImage" ]; then
  echo "Building AppImage first..."
  ./build-appimage.sh
fi

APPIMAGE_SRC="dist/Au1Password-1.0.0-x86_64.AppImage"

# 2. Setup user paths
BIN_DIR="$HOME/.local/bin"
APP_DIR="$HOME/.local/share/applications"
ICON_DIR="$HOME/.local/share/icons/hicolor/scalable/apps"
ICON_256_DIR="$HOME/.local/share/icons/hicolor/256x256/apps"

mkdir -p "$BIN_DIR" "$APP_DIR" "$ICON_DIR" "$ICON_256_DIR"

# 3. Copy binary
echo "[1/4] Installing executable to $BIN_DIR/au1password..."
install -m 755 "$APPIMAGE_SRC" "$BIN_DIR/au1password"

# Create symlinks
ln -sf "$BIN_DIR/au1password" "$BIN_DIR/au1-cli"

# 4. Install Icons
echo "[2/4] Installing application icons..."
cp "resources/au1password.svg" "$ICON_DIR/au1password.svg"
if [ -f "build/Au1Password.AppDir/au1password.png" ]; then
  cp "build/Au1Password.AppDir/au1password.png" "$ICON_256_DIR/au1password.png"
fi

# 5. Install Desktop Entry
echo "[3/4] Installing desktop entry to $APP_DIR/au1password.desktop..."
cat << EOF > "$APP_DIR/au1password.desktop"
[Desktop Entry]
Name=Au1Password
GenericName=Password & Key Vault
Comment=Zero-Knowledge Encrypted Vault with Personal Cloud Sync
Exec=$BIN_DIR/au1password %u
Icon=au1password
Terminal=false
Type=Application
Categories=Utility;Security;Settings;
Keywords=vault;password;credentials;encryption;gdrive;cloud;security;passkey;
StartupWMClass=server.py
MimeType=x-scheme-handler/au1password;x-scheme-handler/au1password-vault;
EOF
chmod +x "$APP_DIR/au1password.desktop"

# 6. Update Caches
echo "[4/4] Updating Linux desktop application database..."
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$APP_DIR" || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -f -t "$HOME/.local/share/icons/hicolor" >/dev/null 2>&1 || true
fi

echo "======================================================"
echo "Installation complete!"
echo "You can now launch Au1Password by:"
echo "  1. App Launcher: Press Super/Win, search for 'Au1Password'"
echo "  2. Terminal GUI: au1password"
echo "  3. Terminal CLI: au1-cli status"
echo "======================================================"
