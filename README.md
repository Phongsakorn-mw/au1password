# Au1Password

A self-hosted, zero-knowledge password manager and 2FA vault designed for privacy, local control, and browser integration.

Au1Password provides a local daemon, web vault interface, and Chromium extension (Manifest V3) that communicate over encrypted local channels. All sensitive credentials are encrypted client-side using Argon2id and AES-256-GCM before storage or synchronization.

---

## Features

- **Zero-knowledge encryption**: Vault items are encrypted using AES-256-GCM with Argon2id key derivation (`au1password-vault-v1` envelope). Your master password never leaves your machine unhashed.
- **Chromium browser extension**: Manifest V3 extension with automatic login form detection, credential autofill, and quick search.
- **Built-in TOTP authenticator**: Full two-factor authentication support with RFC 6238 time-based tokens, countdown rings, and Google Authenticator export QR code import.
- **Multiple themes**: Light theme with high contrast readability, plus dark themes including Midnight, Obsidian, and Cyberpunk.
- **Bilingual interface**: Full English and Thai language support with automatic browser language detection.
- **Multi-select actions**: Select multiple credentials for batch removal or export.
- **Optional cloud backup**: Encrypted synchronization to Google Drive using minimal `drive.file` access scope.
- **Flexible deployment**: Run natively with Python/Rust, via Docker and Docker Compose, or as a standalone Linux AppImage.

---

## Architecture

Au1Password consists of three core components:

1. **Vault server (`app/server.py`)**: A lightweight Python daemon running on port 8765 that handles local vault storage, cryptographic operations, and WebSocket/HTTP APIs for extension communication.
2. **Web interface (`app/index.html`)**: A responsive single-page application providing vault management, TOTP viewing, security audits, and import/export tools.
3. **Browser extension (`extension/`)**: Manifest V3 extension providing background sync, autofill overlay on target web pages, and vault quick access.

Rust core libraries in `crates/` provide high-performance cryptographic primitives and data models:
- `crates/otter-crypto`: Argon2id KDF and AES-256-GCM encryption with dual AAD format support.
- `crates/otter-model`: Data structures for vault entries, folders, and metadata.
- `crates/otter-sync-gdrive`: Google Drive REST client for encrypted vault persistence.

---

## Getting started

### Prerequisites

- Python 3.10 or later
- (Optional for building native crates) Rust 1.75+ and Cargo
- Chromium-based browser (Chrome, Edge, Brave, Vivaldi)

### Quick start

1. Clone the repository:
   ```bash
   git clone https://github.com/Phongsakorn-mw/au1password.git
   cd au1password
   ```

2. Run the application:
   ```bash
   bash run.sh
   ```
   This starts the local daemon on `http://127.0.0.1:8765`. Open your browser to begin creating your master vault.

3. Stop the application:
   ```bash
   ./run.sh --stop
   ```

---

## Browser extension installation

1. Pack or locate the extension archive:
   ```bash
   bash extension/package.sh
   ```
   The packaged extension is saved to `dist/au1password-chrome-extension.zip`.

2. Open Chromium or Chrome and navigate to `chrome://extensions`.
3. Enable **Developer mode** in the top-right corner.
4. Click **Load unpacked** and select the `extension/` folder (or unzip `dist/au1password-chrome-extension.zip` and select the extracted folder).
5. The Au1Password shield icon will appear in your browser toolbar.

---

## Deployment with Docker

Au1Password can run in an isolated Docker container with automated HTTPS via Caddy:

```bash
docker compose up -d
```

This launches:
- `au1password`: The vault service bound to internal port 8765.
- `caddy`: Reverse proxy handling TLS certificates and external routing.

Configuration files:
- [Dockerfile](file:///home/phongsakorn-ma/orca/workspaces/value-personel/otter/Dockerfile)
- [docker-compose.yml](file:///home/phongsakorn-ma/orca/workspaces/value-personel/otter/docker-compose.yml)
- [Caddyfile](file:///home/phongsakorn-ma/orca/workspaces/value-personel/otter/Caddyfile)

---

## Linux desktop installation

To install Au1Password as a system-level desktop application with application launcher integration:

```bash
bash install.sh
```

To remove the installation:

```bash
bash uninstall.sh
```

---

## Testing

Run the automated test suite covering crypto verification, API routes, multi-select operations, and browser extension communication:

```bash
python3 tests/run_all_qa.py
```

---

## Security model

- Vault data is encrypted locally at rest in `~/.local/share/au1password/vault.enc`.
- Encryption uses AES-256-GCM with a 12-byte random IV and 16-byte authentication tag per encryption operation.
- Key derivation uses Argon2id with 64 MB memory cost and 3 iterations by default.
- Dual AAD verification supports both the modern `au1password-vault-v1` envelope and legacy format migrations without plaintext leakage.

---

## License

MIT License. See LICENSE for details.
