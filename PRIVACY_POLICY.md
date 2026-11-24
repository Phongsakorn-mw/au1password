# Privacy Policy for Au1Password

> Last Updated: November 24, 2026

Au1Password is designed with privacy and zero-knowledge cryptography at its core. This Privacy Policy describes how the Au1Password Chrome Extension and desktop software handle user information.

## 1. Zero-Knowledge Architecture
Au1Password operates entirely under a zero-knowledge security model:
- All encryption and decryption operations take place locally on your device.
- Cryptographic keys are derived from your Master Password using PBKDF2 with SHA-256 (600,000 iterations).
- Your Master Password and unencrypted vault data are never transmitted over the internet or stored on third-party servers.

## 2. What Data We Collect
- **Authentication Information**: Usernames, passwords, notes, and 2FA secrets that you choose to store are encrypted client-side using AES-256-GCM.
- **Preferences**: Local interface preferences (theme, auto-lock timeout, language) are stored locally on your device using browser storage (`chrome.storage.local`).
- **No Browsing History**: Au1Password only reads the host domain of the active tab when you trigger the extension to display relevant credentials. Full URLs and page browsing histories are never tracked, logged, or sent anywhere.
- **No Personal Identifiable Information (PII)**: We do not collect names, phone numbers, email addresses, or physical locations.
- **No Analytics or Telemetry**: The extension contains no tracking pixels, advertising SDKs, or analytics trackers.

## 3. How Data Is Stored
- Stored credentials and tokens reside inside client-side encrypted envelopes.
- Communication between the browser extension and the Au1Password backend occurs via secure encrypted HTTPS requests to `https://au1password.onrender.com` or locally via localhost requests (`http://127.0.0.1:8765`).

## 4. Third-Party Services & Data Sharing
- Au1Password does not sell, rent, or trade your data with any third parties or advertisers.
- Optional cloud sync (such as Google Drive) only transmits your pre-encrypted vault file directly to your personal cloud storage account. We do not operate any intermediary servers that hold your keys.

## 5. Permissions Used by the Browser Extension
- `storage`: Preserves your local extension settings, preferences, and remembered username.
- `activeTab` & `tabs`: Identifies the current web domain to match saved logins for autofill.
- `scripting`: Fills credential fields on the active webpage only upon your explicit request.
- `clipboardWrite`: Copies generated passwords or TOTP codes when you click copy.
- `host_permissions` (`https://au1password.onrender.com/*`, `http://127.0.0.1:8765/*`, `http://localhost:8765/*`): Connects to your Au1Password cloud service or local vault daemon.

## 6. User Rights & Data Deletion
You maintain complete control over your data:
- You may export, modify, or permanently delete items from your vault at any time.
- Uninstalling the extension or clearing extension data immediately purges all locally stored cached tokens and settings.

## 7. Contact
For questions or security disclosures regarding this policy, open an issue on GitHub:
https://github.com/Phongsakorn-mw/au1password/issues
