#!/usr/bin/env bash
set -e

echo "Uninstalling Au1Password..."

rm -f "$HOME/.local/bin/au1password"
rm -f "$HOME/.local/bin/au1-cli"
rm -f "$HOME/.local/share/applications/au1password.desktop"
rm -f "$HOME/.local/share/icons/hicolor/scalable/apps/au1password.svg"
rm -f "$HOME/.local/share/icons/hicolor/256x256/apps/au1password.png"

# Clean up legacy otter links if present
rm -f "$HOME/.local/bin/otter-vault"
rm -f "$HOME/.local/bin/otter-cli"
rm -f "$HOME/.local/share/applications/otter-vault.desktop"
rm -f "$HOME/.local/share/icons/hicolor/scalable/apps/otter-vault.svg"
rm -f "$HOME/.local/share/icons/hicolor/256x256/apps/otter-vault.png"

if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database "$HOME/.local/share/applications" || true
fi

echo "Au1Password uninstalled. Your encrypted vault files remain safely stored."
