#!/usr/bin/env bash
# Package Au1Password Extension into standard zip archive
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$ROOT_DIR/dist"
mkdir -p "$DIST_DIR"

ZIP_NAME="au1password-chrome-extension.zip"
TARGET_ZIP="$DIST_DIR/$ZIP_NAME"

echo "Packaging Au1Password Extension..."
rm -f "$TARGET_ZIP"

cd "$SCRIPT_DIR"
zip -r "$TARGET_ZIP" manifest.json background.js popup scripts icons

echo "Extension packaged successfully at: $TARGET_ZIP"
ls -lh "$TARGET_ZIP"
