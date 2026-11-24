# Chrome Web Store Listing — Au1Password

> Last Updated: 2026-11-24

## Store Listing

**Extension Name** [REQUIRED]
Au1Password - Zero-Knowledge Password & Passkey Manager

**Short Description** [REQUIRED]
Zero-knowledge password manager and TOTP authenticator with automated autofill for secure logins.

**Detailed Description** [REQUIRED]
Au1Password is a zero-knowledge password manager and two-factor authentication (TOTP) companion for your browser.

KEY FEATURES
• Automated Autofill: Quickly fill usernames and passwords on login forms with a single click.
• Zero-Knowledge Security: Your master password never leaves your device. Data is encrypted using AES-256-GCM.
• Integrated Authenticator: View live two-factor authentication (2FA/TOTP) verification codes with copy-to-clipboard support.
• Strong Password Generator: Generate secure, customizable passwords directly in form fields.
• Security Health Audit: Detect weak, reused, and compromised passwords to protect your online accounts.
• Biometric and Master Lock: Securely lock your vault with customizable auto-lock timeouts.

HOW TO USE
1. Click the Au1Password icon in your browser toolbar to unlock your vault.
2. Navigate to any login page. Click the Au1Password badge or popup to fill your credentials.
3. Save new logins automatically as you browse or create them inside the vault.

PRIVACY & SECURITY
Au1Password operates on a strict zero-knowledge architecture. All cryptographic keys are derived client-side. We do not track browsing history, sell data, or transmit unencrypted credentials.

SUPPORT
Website: https://au1password.onrender.com
GitHub Repository: https://github.com/Phongsakorn-mw/au1password
Issues: https://github.com/Phongsakorn-mw/au1password/issues

Version 1.0.1 — Official release featuring cloud vault synchronization with https://au1password.onrender.com, configurable server settings, TOTP authenticator, zero-knowledge file sharing, and intelligent autofill.

**Category** [REQUIRED]
Productivity

**Single Purpose** [REQUIRED]
Zero-knowledge credential manager and automated login autofill tool for web browsers.

**Primary Language** [REQUIRED]
English

---

## Graphics & Assets Checklist

| Asset | Dimensions | Status | Notes |
|-------|-----------|--------|-------|
| Store Icon [REQUIRED] | 128×128 PNG | ✅ Ready | `extension/icons/icon-128.png` |
| Screenshot 1 [REQUIRED] | 1280×800 PNG | 🟡 Prepare | Popup unlocked showing vault items & TOTP codes |
| Screenshot 2 [RECOMMENDED] | 1280×800 PNG | 🟡 Prepare | Autofill in action on a login form |
| Screenshot 3 [RECOMMENDED] | 1280×800 PNG | 🟡 Prepare | Strong Password Generator modal |
| Small Promo Tile [RECOMMENDED] | 440×280 PNG | 🟡 Optional | Featured card asset with logo and tagline |

---

## Permissions Justification

| Permission | Type | Justification |
|------------|------|---------------|
| `storage` | permissions | Saves user preferences, active theme, remembered username, and local session configuration on the local device. |
| `activeTab` | permissions | Detects username and password input fields on the active webpage when the user triggers autofill. |
| `tabs` | permissions | Retrieves the domain of the active tab to match and display corresponding saved login credentials in the popup. |
| `scripting` | permissions | Fills credentials directly into login form fields when the user explicitly clicks autofill. |
| `clipboardWrite` | permissions | Enables users to copy generated passwords and 2FA TOTP codes to the clipboard with one click. |
| `https://au1password.onrender.com/*` | host_permissions | Primary cloud vault synchronization and authentication service endpoint. |
| `http://127.0.0.1:8765/*` | host_permissions | Communicates with the local Au1Password vault service on the user's computer for local-first sync. |
| `http://localhost:8765/*` | host_permissions | Fallback localhost address to communicate with the user's local Au1Password vault service. |

---

## Privacy & Data Use

### Data Collection

**Does the extension collect user data?** Yes (Authentication info only)

| Data Type | Collected? | Transmitted Off-Device? | Purpose | Shared with Third Parties? |
|-----------|-----------|------------------------|---------|---------------------------|
| Personally identifiable info | No | No | N/A | No |
| Authentication info | Yes | No | Encrypted locally for autofill and login management | No |
| Financial info | No | No | N/A | No |
| Location | No | No | N/A | No |
| Web history | No | No | N/A | No |
| User activity | No | No | N/A | No |
| Website content | No | No | N/A | No |

### Data Use Certification
- [x] Data is NOT sold to third parties
- [x] Data is NOT used for purposes unrelated to the extension's core functionality
- [x] Data is NOT used for creditworthiness or lending purposes

---

## Privacy Policy

**Privacy Policy URL** [REQUIRED]
https://github.com/Phongsakorn-mw/au1password/blob/main/PRIVACY_POLICY.md

---

## Distribution

**Visibility**: Public
**Pricing**: Free
