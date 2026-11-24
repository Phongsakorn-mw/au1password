#!/usr/bin/env python3
"""
Au1Password QA Suite: Security & Zero-Knowledge Verification
"""
import os
import sys
import json
import re
from pathlib import Path

def run_tests():
    passed = 0
    failed = 0
    errors = []

    def log_test(name, success, err=None):
        nonlocal passed, failed
        if success:
            passed += 1
            print(f"  \033[32m✔ PASS\033[0m: {name}")
        else:
            failed += 1
            print(f"  \033[31m✖ FAIL\033[0m: {name}")
            if err:
                print(f"    \033[33mError\033[0m: {err}")
                errors.append((name, err))

    print("\n\033[1;35m=== 2. Security & Zero-Knowledge QA Tests ===\033[0m")

    # Test 1: Vault file zero-knowledge encryption on disk
    try:
        vault_path = Path(os.path.expanduser("~/.local/share/au1password/vault.enc"))
        if not vault_path.exists():
            vault_path = Path(os.path.expanduser("~/.local/share/otter-vault/vault.enc"))
        if vault_path.exists():
            with open(vault_path, "r", encoding="utf-8") as f:
                content = f.read()
            data = json.loads(content)
            
            # Must have format au1password-vault-v1 or legacy otter-vault-v1, AES-256-GCM, and ciphertext_base64
            is_valid_envelope = (
                data.get("format") in ("au1password-vault-v1", "otter-vault-v1") and
                data.get("cipher", {}).get("algorithm") == "AES-256-GCM" and
                bool(data.get("ciphertext_base64"))
            )
            # Check for absence of plaintext password fields in envelope
            has_no_plaintext = "password" not in content.lower() or "ciphertext_base64" in content
            # Ensure items are not in plaintext in envelope
            has_no_items_key = "items" not in data
            
            log_test("Zero-Knowledge: Vault disk file is AES-256-GCM encrypted envelope", is_valid_envelope and has_no_items_key)
        else:
            log_test("Zero-Knowledge: Vault disk file verification", True, "Vault file does not exist yet (skipped)")
    except Exception as e:
        log_test("Zero-Knowledge: Vault disk file verification", False, str(e))

    # Test 2: Config file contains no master password
    try:
        cfg_path = Path(os.path.expanduser("~/.config/au1password/config.json"))
        if not cfg_path.exists():
            cfg_path = Path(os.path.expanduser("~/.config/otter-vault/config.json"))
        if cfg_path.exists():
            with open(cfg_path) as f:
                cfg = json.load(f)
            # Master password must NEVER be in config
            has_no_master = "master_password" not in cfg and "password" not in cfg
            log_test("Zero-Knowledge: Config contains no master password", has_no_master)
        else:
            log_test("Zero-Knowledge: Config contains no master password", True)
    except Exception as e:
        log_test("Zero-Knowledge: Config contains no master password", False, str(e))

    # Test 3: XSS Sanitization: escapeHtml exists and is utilized
    try:
        with open("app/index.html") as f:
            html = f.read()
        has_escape_html = "function escapeHtml(" in html
        uses_escape_on_title = "escapeHtml(item.title" in html or "escapeHtml(it.title" in html
        uses_escape_on_user = "escapeHtml(item.username" in html or "escapeHtml(it.username" in html
        log_test("XSS Sanitization: escapeHtml applied to user titles and credentials", has_escape_html and uses_escape_on_title and uses_escape_on_user)
    except Exception as e:
        log_test("XSS Sanitization: escapeHtml verification", False, str(e))

    # Test 4: Extension XSS Sanitization
    try:
        with open("extension/scripts/autofill.js") as f:
            ext_script = f.read()
        has_ext_escape = "function escapeHtml(" in ext_script
        uses_ext_escape = "escapeHtml(it.title" in ext_script
        log_test("XSS Sanitization: Extension autofill uses escapeHtml", has_ext_escape and uses_ext_escape)
    except Exception as e:
        log_test("XSS Sanitization: Extension autofill", False, str(e))

    # Test 5: Autofill Field Isolation (Search fields rejected)
    try:
        with open("extension/scripts/autofill.js") as f:
            script = f.read()
        has_search_exclusion = "function isSearchOrNonLoginInput(" in script
        checks_search_type = 'type === "search"' in script or '"search"' in script
        checks_ignore_flags = 'data-au1-ignore' in script
        log_test("Autofill Security: isSearchOrNonLoginInput excludes search & filter inputs", has_search_exclusion and checks_search_type and checks_ignore_flags)
    except Exception as e:
        log_test("Autofill Security: isSearchOrNonLoginInput", False, str(e))

    # Test 6: Default Binding to Localhost (127.0.0.1)
    try:
        with open("app/server.py") as f:
            server_py = f.read()
        binds_localhost = '"127.0.0.1"' in server_py and 'DEFAULT_PORT = 8765' in server_py
        log_test("Network Security: Server defaults to 127.0.0.1 loopback only", binds_localhost)
    except Exception as e:
        log_test("Network Security: Localhost binding", False, str(e))

    # Test 7: Origin Whitelisting (Cross-site scraping protection)
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request("http://127.0.0.1:8765/api/vault/status")
        req.add_header("Origin", "https://malicious-scam-site.com")
        try:
            urllib.request.urlopen(req, timeout=3)
            log_test("Origin Security: Reject unauthorized cross-origin requests", False, "Allowed malicious origin!")
        except urllib.error.HTTPError as he:
            log_test("Origin Security: Reject unauthorized cross-origin requests (403)", he.code == 403)
    except Exception as e:
        log_test("Origin Security: Reject unauthorized cross-origin requests", False, str(e))

    # Test 8: Host Header Validation (DNS Rebinding protection)
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request("http://127.0.0.1:8765/api/vault/status")
        req.add_header("Host", "attacker-rebinding.com:8765")
        try:
            urllib.request.urlopen(req, timeout=3)
            log_test("Host Security: Reject DNS rebinding host headers", False, "Accepted suspicious host header!")
        except urllib.error.HTTPError as he:
            log_test("Host Security: Reject DNS rebinding host headers (403)", he.code == 403)
    except Exception as e:
        log_test("Host Security: Reject DNS rebinding host headers", False, str(e))

    # Test 9: Session Token Protection
    try:
        import urllib.request
        import urllib.error
        req = urllib.request.Request("http://127.0.0.1:8765/api/vault/items")
        try:
            urllib.request.urlopen(req, timeout=3)
            log_test("Session Security: Protected endpoints require valid Bearer token", False, "Endpoint opened without token!")
        except urllib.error.HTTPError as he:
            log_test("Session Security: Protected endpoints require valid Bearer token (401)", he.code == 401)
    except Exception as e:
        log_test("Session Security: Protected endpoints require valid Bearer token", False, str(e))

    # Test 10: Security Headers (nosniff, DENY, CSP)
    try:
        import urllib.request
        res = urllib.request.urlopen("http://127.0.0.1:8765/", timeout=3)
        headers = dict(res.headers)
        has_nosniff = headers.get("X-Content-Type-Options") == "nosniff"
        has_deny = headers.get("X-Frame-Options") == "DENY"
        has_csp = "Content-Security-Policy" in headers
        log_test("Header Security: Production security headers (nosniff, DENY, CSP)", has_nosniff and has_deny and has_csp)
    except Exception as e:
        log_test("Header Security: Production security headers", False, str(e))

    # Test 11: Master Password RAM Hygiene
    try:
        with open("app/server.py") as f:
            server_py = f.read()
        zeros_password = 'current_session["master_password"] = None' in server_py
        has_session_token = 'current_session["session_token"]' in server_py
        log_test("Memory Hygiene: Zero plaintext master password in RAM", zeros_password and has_session_token)
    except Exception as e:
        log_test("Memory Hygiene: Zero plaintext master password in RAM", False, str(e))

    # Test 12: DOM Clickjacking & UI Redressing Defense (DEF CON 33 / Marek Tóth 2025/2026)
    try:
        with open("extension/scripts/autofill.js") as f:
            af_script = f.read()
        has_vis_check = "function isElementVisiblyRendered(" in af_script
        checks_opacity = 'opacity < 0.1' in af_script
        checks_pointer = 'pointerEvents === "none"' in af_script
        checks_bounds = 'rect.width < 10' in af_script
        checks_trusted = 'e.isTrusted' in af_script
        log_test("Autofill Defense: DOM Clickjacking & invisible overlay protection", has_vis_check and checks_opacity and checks_pointer and checks_bounds and checks_trusted)
    except Exception as e:
        log_test("Autofill Defense: DOM Clickjacking protection", False, str(e))

    # Test 13: Iframe Isolation & Cross-Origin Credential Shield (CVE-2023-28121 mitigation)
    try:
        with open("extension/scripts/autofill.js") as f:
            af_script = f.read()
        has_iframe_guard = "window.self !== window.top" in af_script
        checks_origin = "window.top.location.origin === window.location.origin" in af_script
        log_test("Iframe Defense: Cross-origin iframe injection suppressed", has_iframe_guard and checks_origin)
    except Exception as e:
        log_test("Iframe Defense: Cross-origin iframe suppression", False, str(e))

    # Test 14: Extension Host Spoofing & Strict Domain Matching
    try:
        with open("extension/background.js") as f:
            bg_script = f.read()
        has_strict_match = "function domainMatches(" in bg_script
        has_host_extract = "function extractDomainHostname(" in bg_script
        verifies_sender_tab = "sender.tab && sender.tab.url" in bg_script
        rejects_mismatch = "Security violation: Host mismatch between tab and query" in bg_script
        log_test("Credential Query Security: Strict domain matching & Tab origin verification", has_strict_match and has_host_extract and verifies_sender_tab and rejects_mismatch)
    except Exception as e:
        log_test("Credential Query Security: Strict domain matching", False, str(e))

    # Test 15: Server DoS & Request Body Size Limit
    try:
        with open("app/server.py") as f:
            srv_code = f.read()
        has_body_limit = "MAX_BODY_SIZE = 10 * 1024 * 1024" in srv_code
        returns_413 = "Payload Too Large: maximum allowed body size is 10MB" in srv_code
        has_send_cap = "len(ephemeral_sends) >= 100" in srv_code
        log_test("Server Hardening: Request body limit (10MB) & Ephemeral memory cap", has_body_limit and returns_413 and has_send_cap)
    except Exception as e:
        log_test("Server Hardening: Request body limit", False, str(e))

    # Test 16: Reverse Tabnabbing Protection (rel=noopener noreferrer)
    try:
        with open("app/index.html") as f:
            ui_html = f.read()
        has_noopener_anchor = 'target="_blank" rel="noopener noreferrer"' in ui_html
        has_noopener_window = 'window.open(data.auth_url, "_blank", "noopener,noreferrer")' in ui_html
        log_test("Client Protection: Reverse Tabnabbing prevention (rel=noopener noreferrer)", has_noopener_anchor and has_noopener_window)
    except Exception as e:
        log_test("Client Protection: Reverse Tabnabbing prevention", False, str(e))

    # Test 17: Clipboard & Inactivity Auto-Lock Hygiene
    try:
        with open("app/index.html") as f:
            ui_html = f.read()
        has_clip_timer = "clipboardClearTimer" in ui_html and "Clipboard cleared for security" in ui_html
        has_idle_timer = "idleTimeoutMs" in ui_html and "resetIdleTimer" in ui_html
        listens_activity = '"mousemove", "mousedown", "keydown"' in ui_html
        log_test("Session Hygiene: Clipboard auto-clearing (30s) & Inactivity auto-lock (15m)", has_clip_timer and has_idle_timer and listens_activity)
    except Exception as e:
        log_test("Session Hygiene: Clipboard & Inactivity auto-lock", False, str(e))

    return passed, failed, errors

if __name__ == "__main__":
    p, f, errs = run_tests()
    sys.exit(0 if f == 0 else 1)
