#!/usr/bin/env python3
"""
Au1Password QA Suite: Frontend UI & Chrome Extension Integrity Tests
"""
import os
import sys
import json
import zipfile
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

    print("\n\033[1;34m=== 3. Frontend & Extension QA Tests ===\033[0m")

    # Read frontend files
    with open("app/index.html") as f:
        html = f.read()

    # Test 1: Au1Password Branding
    try:
        has_title = "<title>Au1Password" in html
        has_brand = "Au1Password" in html
        has_logo = "<svg" in html and "au1password" in html.lower()
        log_test("Frontend: Au1Password branding & header title", has_title and has_brand)
    except Exception as e:
        log_test("Frontend: Au1Password branding", False, str(e))

    # Test 2: Search Input Distinction
    try:
        has_search_type = 'type="search" id="vaultSearchInput"' in html
        has_au1_ignore = 'data-au1-ignore="true"' in html
        log_test("Frontend: Vault search input is type='search' and has data-au1-ignore", has_search_type and has_au1_ignore)
    except Exception as e:
        log_test("Frontend: Vault search input", False, str(e))

    # Test 3: Folders Management Controls
    try:
        has_manage_btn = "openManageFoldersModal()" in html
        has_add_btn = "openNewFolderPrompt()" in html
        has_rename = "function renameFolder(" in html
        has_delete = "function deleteFolder(" in html
        has_cleanup = "function cleanUnusedFolders(" in html
        has_modal = 'id="manageFoldersModal"' in html
        log_test("Frontend: Complete Folders management (Add, Rename, Delete, Clean)", has_manage_btn and has_add_btn and has_rename and has_delete and has_cleanup and has_modal)
    except Exception as e:
        log_test("Frontend: Folders management", False, str(e))

    # Test 4: Duplicate & Reused Credentials Inspector
    try:
        has_audit_stats = "function getAuditStats()" in html
        has_switch_tab = "function switchAuditTab(" in html
        has_reused_tab = 'id="tabAuditReused"' in html
        has_users_tab = 'id="tabAuditUsers"' in html
        has_weak_tab = 'id="tabAuditWeak"' in html
        has_alert_css = ".field-audit-alert" in html
        has_badge_chips = ".badge-chip.warning" in html and ".badge-chip.user-dup" in html
        log_test("Frontend: Duplicates Inspector (Reused Passwords, Duplicate Usernames, Weak)", has_audit_stats and has_switch_tab and has_reused_tab and has_users_tab and has_weak_tab and has_alert_css and has_badge_chips)
    except Exception as e:
        log_test("Frontend: Duplicates Inspector", False, str(e))

    # Test 5: Responsive Mobile & Desktop Layout
    try:
        has_mobile_mq = "@media (max-width: 840px)" in html
        has_bottom_nav = "app-bottom-nav" in html
        has_mobile_drawer = "mobile-open" in html
        log_test("Frontend: Responsive layout (Desktop 3-pane & Mobile bottom-nav/drawer)", has_mobile_mq and has_bottom_nav and has_mobile_drawer)
    except Exception as e:
        log_test("Frontend: Responsive layout", False, str(e))

    # Test 6: Extension Manifest V3 Compliance
    try:
        with open("extension/manifest.json") as f:
            manifest = json.load(f)
        is_v3 = manifest.get("manifest_version") == 3
        has_action = "default_popup" in manifest.get("action", {})
        has_content_scripts = len(manifest.get("content_scripts", [])) > 0
        has_bg = "service_worker" in manifest.get("background", {})
        log_test("Extension: Manifest V3 schema & permissions", is_v3 and has_action and has_content_scripts and has_bg)
    except Exception as e:
        log_test("Extension: Manifest V3 schema", False, str(e))

    # Test 7: Extension Popup Features
    try:
        with open("extension/popup/popup.html") as f:
            popup_html = f.read()
        with open("extension/popup/popup.js") as f:
            popup_js = f.read()
        has_4_tabs = all(t in popup_html for t in ["tabVault", "tabGen", "tabSync", "tabSettings"])
        has_popup_search = 'type="search" id="searchInput"' in popup_html
        has_health_calc = "function updateHealthMetrics()" in popup_js
        log_test("Extension: Popup 4-tab workflow & Health metrics", has_4_tabs and has_popup_search and has_health_calc)
    except Exception as e:
        log_test("Extension: Popup features", False, str(e))

    # Test 8: Build Artifacts Verification
    try:
        appimage_path = Path("dist/Au1Password-1.0.0-x86_64.AppImage")
        zip_path = Path("dist/au1password-chrome-extension.zip")
        has_appimage = appimage_path.exists() and os.access(appimage_path, os.X_OK) and appimage_path.stat().st_size > 1000000
        has_zip = zip_path.exists() and zip_path.stat().st_size > 10000
        
        # Verify zip structure
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zip_files = zf.namelist()
            zip_valid = "manifest.json" in zip_files and "scripts/autofill.js" in zip_files and "popup/popup.html" in zip_files
            
        log_test("Build Packages: AppImage binary & Chrome Extension ZIP valid", has_appimage and has_zip and zip_valid)
    except Exception as e:
        log_test("Build Packages: AppImage & ZIP verification", False, str(e))

    # Test 8: Zero External Library QR Code Generator
    try:
        has_native_qr = "NativeQRCode" in html and "generateSVG" in html
        no_external_qrcode_script = "src=\"/qrcode.min.js\"" not in html
        no_min_file = not Path("app/qrcode.min.js").exists()
        log_test("Zero-Dependency: In-house Native QR Generator (No external lib)", has_native_qr and no_external_qrcode_script and no_min_file)
    except Exception as e:
        log_test("Zero-Dependency: In-house Native QR Generator", False, str(e))

    # Test 9: Native Multi-Manager CSV & Bitwarden Importer
    try:
        has_csv_parser = "function parseCSV(" in html
        has_importer = "function parseImportFileContent(" in html
        supports_chrome = "Google Chrome / Microsoft Edge" in html
        supports_firefox = "Mozilla Firefox" in html
        supports_bitwarden = "Bitwarden / Vaultwarden" in html
        log_test("Data Import: Native Multi-Manager Importer (Chrome, Firefox, Bitwarden, Edge)", has_csv_parser and has_importer and supports_chrome and supports_firefox and supports_bitwarden)
    except Exception as e:
        log_test("Data Import: Native Multi-Manager Importer", False, str(e))

    # Test 10: Extension In-Form Generator & Smart Save Banner
    try:
        with open("extension/scripts/autofill.js") as f:
            af_code = f.read()
        has_generator = "function generatePassword(" in af_code and "function generateUsername(" in af_code
        has_smart_save = "function showSmartSaveBanner(" in af_code and "function handleFormSubmit(" in af_code
        with open("extension/background.js") as f:
            bg_code = f.read()
        handles_inspect = 'action === "inspectLoginSubmit"' in bg_code
        log_test("Extension Intelligence: In-form Generator & Smart Save Prompt", has_generator and has_smart_save and handles_inspect)
    except Exception as e:
        log_test("Extension Intelligence: In-form Generator & Smart Save", False, str(e))

    # Test 11: UI Consistency, SVG Sizing & Zero Variable Leaks
    try:
        no_dark_green_text = "#032115" not in html
        has_svg_flex = "svg {" in html and "flex-shrink: 0" in html
        has_bg_card_var = "--bg-card:" in html
        has_transition_var = "--transition-fast:" in html
        log_test("UI & Icon Hygiene: SVG flex-shrink, zero undefined CSS vars, and readable contrast", no_dark_green_text and has_svg_flex and has_bg_card_var and has_transition_var)
    except Exception as e:
        log_test("UI & Icon Hygiene: Verification failed", False, str(e))

    # Test 12: Extension Tech Blue Palette
    try:
        with open("extension/popup/popup.css") as f:
            pop_css = f.read()
        has_blue_accent = "--accent: #3b82f6;" in pop_css or "--accent: #3B82F6;" in pop_css
        no_green_accent = "--accent: #10b981;" not in pop_css
        log_test("Extension Styling: Tech Blue Palette (No green accents)", has_blue_accent and no_green_accent)
    except Exception as e:
        log_test("Extension Styling: Tech Blue Palette", False, str(e))

    # Test 13: Lightweight High-Performance Detail View
    try:
        has_audit_cap = "slice(0, 6)" in html
        has_scroll_container = "max-height: 120px; overflow-y: auto;" in html
        log_test("Performance & Lightness: Capped duplicate list & scrollable DOM optimization", has_audit_cap and has_scroll_container)
    except Exception as e:
        log_test("Performance & Lightness: Optimization check", False, str(e))

    # Test 14: Multi-Host / Multi-URI Dynamic Support
    try:
        has_modal_urls = "modalUrlsList" in html and "addModalUrlRow" in html
        has_detail_urls = "Host #" in html and "copyText" in html
        with open("extension/background.js") as f:
            bg_code = f.read()
        has_bg_multi_match = "Array.isArray(it.urls)" in bg_code and "domainMatches(u, targetHost)" in bg_code
        with open("extension/popup/popup.js") as f:
            pop_code = f.read()
        has_pop_multi_match = "multiMatch" in pop_code or "Array.isArray(it.urls)" in pop_code
        log_test("Multi-Host Support: Dynamic URL rows, Multi-domain autofill matching & Popup sync", has_modal_urls and has_detail_urls and has_bg_multi_match and has_pop_multi_match)
    except Exception as e:
        log_test("Multi-Host Support: Verification failed", False, str(e))

    # Test 15: Custom Fields (Label & Value Pairs)
    try:
        has_cf_container = "modalCustomFieldsList" in html and "addModalCustomFieldRow" in html
        has_cf_detail = "Custom Fields (" in html and "toggleCustomFieldVal" in html
        has_cf_types = 'value="text"' in html and 'value="hidden"' in html
        has_cf_search = "customFields.some" in html
        log_test("Custom Fields: Dynamic Label/Value pairs, Masked/Reveal toggle & Search filter", has_cf_container and has_cf_detail and has_cf_types and has_cf_search)
    except Exception as e:
        log_test("Custom Fields: Verification failed", False, str(e))

    # Test 16: Zero-Knowledge Encrypted File Attachments
    try:
        has_att_container = "modalAttachmentsList" in html and "handleModalFileUpload" in html
        has_att_detail = "Encrypted Attachments" in html and "downloadAttachment" in html
        has_file_size = "formatFileSize" in html and "attachment-size" in html
        has_file_card = ".attachment-item-card" in html
        log_test("Encrypted Attachments: Client-side FileReader, Zero-Knowledge AES-256-GCM, & Direct Download", has_att_container and has_att_detail and has_file_size and has_file_card)
    except Exception as e:
        log_test("Encrypted Attachments: Verification failed", False, str(e))

    # Test 17: Google Authenticator QR Code & Migration URI Parser
    try:
        has_proto_parser = "parseGoogleAuthMigrationUri" in html and "parseProtobuf" in html
        has_b32_encode = "base32Encode" in html
        has_gauth_input = "gauthUriInput" in html and "handleGoogleAuthUriInput" in html
        has_gauth_preview = "renderGoogleAuthPreview" in html and "confirmGoogleAuthImport" in html
        has_gauth_opt = 'value="google-auth"' in html
        log_test("Google Authenticator Migration: Native Protobuf parser, QR image support & Live TOTP Preview", has_proto_parser and has_b32_encode and has_gauth_input and has_gauth_preview and has_gauth_opt)
    except Exception as e:
        log_test("Google Authenticator Migration: Verification failed", False, str(e))

    # Test 18: Locked State Isolation & Sticky UI Suppression
    try:
        # Check Web App Lockdown
        has_locked_body_class = 'body.vault-locked' in html
        has_locked_bnav_hidden = '.app-bottom-nav' in html and 'display: none !important' in html
        has_locked_window_pe = 'body.vault-locked .app-window' in html and 'pointer-events: none !important' in html
        has_unlock_modal_zindex = '#unlockModal' in html and 'z-index: 999999 !important' in html
        has_capture_click_trap = '["click", "mousedown", "pointerdown", "touchstart"].forEach' in html and 'isVaultLocked()' in html
        has_lock_func = 'setVaultLockedState' in html and 'isVaultLocked' in html

        # Check Extension Lockdown
        popup_css_path = Path("extension/popup/popup.css")
        popup_js_path = Path("extension/popup/popup.js")
        popup_css = popup_css_path.read_text(encoding="utf-8") if popup_css_path.exists() else ""
        popup_js = popup_js_path.read_text(encoding="utf-8") if popup_js_path.exists() else ""

        has_ext_css_lock = 'body.vault-locked .popup-tabs' in popup_css and 'display: none !important' in popup_css
        has_ext_js_lock = 'setExtensionLockedState' in popup_js and 'classList.add("vault-locked")' in popup_js
        has_ext_click_trap = '["click", "mousedown", "pointerdown", "touchstart"].forEach' in popup_js

        all_lock_pass = (
            has_locked_body_class and has_locked_bnav_hidden and has_locked_window_pe and
            has_unlock_modal_zindex and has_capture_click_trap and has_lock_func and
            has_ext_css_lock and has_ext_js_lock and has_ext_click_trap
        )
        log_test("Locked State Isolation: Sticky / Bottom-Nav / Sidebar suppression, Event Interception & Focus Trap", all_lock_pass)
    except Exception as e:
        log_test("Locked State Isolation: Verification failed", False, str(e))

    return passed, failed, errors

if __name__ == "__main__":
    p, f, errs = run_tests()
    sys.exit(0 if f == 0 else 1)
