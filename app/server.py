#!/usr/bin/env python3
"""
OtterVault - Linux Desktop Application & Local Backend Server
Handles zero-knowledge vault storage, real Google OAuth 2.0 PKCE / Web flow,
and real Google Drive API v3 synchronization (appDataFolder).
"""

import os
import sys
import json
import base64
import time
import shutil
import urllib.parse
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Paths
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "otter-vault"
DEFAULT_CONFIG_PATH = DEFAULT_DATA_DIR / "config.json"
DEFAULT_TOKEN_PATH = DEFAULT_DATA_DIR / "token.json"
DEFAULT_VAULT_PATH = DEFAULT_DATA_DIR / "vault.enc"
DEFAULT_BACKUP_DIR = DEFAULT_DATA_DIR / "backups"
APP_DIR = Path(__file__).resolve().parent

DEFAULT_CONFIG = {
    "vault": {
        "file_path": str(DEFAULT_VAULT_PATH),
        "backup_dir": str(DEFAULT_BACKUP_DIR),
        "auto_backup": True,
        "max_backups": 5
    },
    "gdrive": {
        "enabled": True,
        "client_id": "",
        "client_secret": "",
        "target_folder": "appDataFolder",
        "sync_mode": "auto",
        "sync_interval_mins": 15,
        "last_sync": None,
        "account_email": None
    },
    "security": {
        "auto_lock_mins": 15,
        "clear_clipboard_secs": 30,
        "mask_passwords_default": True,
        "kdf_iterations": 250000
    },
    "appearance": {
        "theme": "adwaita-dark",
        "default_layout": "adwaita",
        "compact_mode": False
    }
}

current_session = {
    "unlocked": False,
    "master_password": None,
    "vault": None
}

def load_config():
    if DEFAULT_CONFIG_PATH.exists():
        try:
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
                cfg = DEFAULT_CONFIG.copy()
                for section in ["vault", "gdrive", "security", "appearance"]:
                    if section in user_cfg:
                        cfg[section].update(user_cfg[section])
                return cfg
        except Exception as e:
            print(f"[Config] Error loading config: {e}, using defaults")
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DEFAULT_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    return cfg

def load_tokens():
    if DEFAULT_TOKEN_PATH.exists():
        try:
            with open(DEFAULT_TOKEN_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return None

def save_tokens(tokens):
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DEFAULT_TOKEN_PATH, "w", encoding="utf-8") as f:
        json.dump(tokens, f, indent=2)

def open_system_browser(url):
    import subprocess
    import shutil
    for cmd in ["google-chrome-stable", "google-chrome", "chromium", "firefox", "xdg-open"]:
        if shutil.which(cmd):
            try:
                subprocess.Popen([cmd, url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[OtterVault] Launched system browser using {cmd}: {url[:60]}...")
                return True
            except Exception as e:
                print(f"[OtterVault] Failed to launch {cmd}: {e}")
    import webbrowser
    return webbrowser.open(url)

# Cryptography helpers (PBKDF2-HMAC-SHA256 & AES-256-GCM)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_vault(vault_data: dict, password: str, iterations: int = 250000) -> dict:
    salt = os.urandom(32)
    key = derive_key(password, salt, iterations)
    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    plaintext = json.dumps(vault_data).encode("utf-8")
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext, b"otter-vault-v1")

    split_idx = len(ciphertext_and_tag) - 16
    ciphertext = ciphertext_and_tag[:split_idx]
    tag = ciphertext_and_tag[split_idx:]

    envelope = {
        "version": 1,
        "format": "otter-vault-v1",
        "kdf": {
            "algorithm": "PBKDF2-HMAC-SHA256",
            "salt_base64": base64.b64encode(salt).decode("ascii"),
            "iterations": iterations
        },
        "cipher": {
            "algorithm": "AES-256-GCM",
            "iv_base64": base64.b64encode(iv).decode("ascii"),
            "tag_base64": base64.b64encode(tag).decode("ascii")
        },
        "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        "meta": {
            "last_modified": int(time.time()),
            "item_count": len(vault_data.get("items", []))
        }
    }
    return envelope

def decrypt_vault(envelope: dict, password: str) -> dict:
    if envelope.get("format") != "otter-vault-v1":
        raise ValueError(f"Unsupported format: {envelope.get('format')}")

    salt = base64.b64decode(envelope["kdf"]["salt_base64"])
    iterations = envelope["kdf"]["iterations"]
    key = derive_key(password, salt, iterations)

    iv = base64.b64decode(envelope["cipher"]["iv_base64"])
    tag = base64.b64decode(envelope["cipher"]["tag_base64"])
    ciphertext = base64.b64decode(envelope["ciphertext_base64"])

    ciphertext_and_tag = ciphertext + tag
    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, b"otter-vault-v1")
    return json.loads(plaintext.decode("utf-8"))

def write_envelope_atomically(path: Path, envelope: dict, backup: bool = True):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(".tmp")
    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(envelope, f, indent=2)

    if backup and path.exists():
        backup_dir = DEFAULT_BACKUP_DIR
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_file = backup_dir / f"vault_{int(time.time())}.bak"
        shutil.copy2(path, backup_file)

    os.replace(temp_path, path)

# ==============================================================================
# REAL GOOGLE DRIVE V3 & OAUTH 2.0 INTEGRATION
# ==============================================================================

def gdrive_refresh_access_token(tokens, client_id, client_secret):
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise ValueError("No refresh token available")

    token_url = "https://oauth2.googleapis.com/token"
    post_data = {
        "client_id": client_id,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token"
    }
    if client_secret:
        post_data["client_secret"] = client_secret

    encoded_data = urllib.parse.urlencode(post_data).encode("utf-8")
    req = urllib.request.Request(token_url, data=encoded_data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    with urllib.request.urlopen(req) as resp:
        new_tokens = json.loads(resp.read().decode("utf-8"))

    tokens["access_token"] = new_tokens["access_token"]
    tokens["expires_at"] = time.time() + new_tokens.get("expires_in", 3600)
    save_tokens(tokens)
    return tokens["access_token"]

def gdrive_get_valid_token(cfg):
    tokens = load_tokens()
    if not tokens:
        raise ValueError("Google Drive is not connected. Please authenticate in Settings.")

    target_folder = cfg["gdrive"].get("target_folder", "appDataFolder")
    if target_folder in ("MyDrive", "root"):
        token_scopes = tokens.get("scope", "")
        if "drive.file" not in token_scopes and "https://www.googleapis.com/auth/drive" not in token_scopes:
            raise ValueError(
                "Google Account needs 'drive.file' scope for My Drive. "
                "Please click 'Connect with Google' again in Settings, or change Target Folder back to 'appDataFolder'."
            )

    client_id = cfg["gdrive"]["client_id"]
    client_secret = cfg["gdrive"]["client_secret"]

    # If expires in under 60 seconds, refresh
    if time.time() >= (tokens.get("expires_at", 0) - 60):
        return gdrive_refresh_access_token(tokens, client_id, client_secret)
    return tokens["access_token"]

def gdrive_find_vault_file(token, target_folder="appDataFolder"):
    if target_folder in ("MyDrive", "root"):
        spaces = "drive"
        q = urllib.parse.quote("name = 'otter-vault.enc' and trashed = false and 'root' in parents")
    else:
        spaces = "appDataFolder"
        q = urllib.parse.quote("name = 'otter-vault.enc' and trashed = false")
    fields = urllib.parse.quote("files(id, name, modifiedTime, size)")
    url = f"https://www.googleapis.com/drive/v3/files?spaces={spaces}&q={q}&fields={fields}"

    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")

    with urllib.request.urlopen(req) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        files = data.get("files", [])
        return files[0] if files else None

def gdrive_upload_vault(token, vault_path, target_folder="appDataFolder"):
    with open(vault_path, "rb") as f:
        file_bytes = f.read()

    existing_file = gdrive_find_vault_file(token, target_folder)

    if existing_file:
        # Update existing file content
        file_id = existing_file["id"]
        upload_url = f"https://www.googleapis.com/upload/drive/v3/files/{file_id}?uploadType=media"
        req = urllib.request.Request(upload_url, data=file_bytes, method="PATCH")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", "application/octet-stream")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8")), "updated"
    else:
        # Create new file using multipart upload
        boundary = f"-------OtterVaultBoundary{int(time.time())}"
        parent_id = "root" if target_folder in ("MyDrive", "root") else "appDataFolder"
        metadata = {
            "name": "otter-vault.enc",
            "parents": [parent_id]
        }
        meta_part = json.dumps(metadata).encode("utf-8")

        body = (
            f"--{boundary}\r\n"
            f"Content-Type: application/json; charset=UTF-8\r\n\r\n"
        ).encode("utf-8") + meta_part + f"\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n".encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        upload_url = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"
        req = urllib.request.Request(upload_url, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Content-Type", f"multipart/related; boundary={boundary}")
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8")), "created"

def gdrive_download_vault(token, file_id, dest_path):
    download_url = f"https://www.googleapis.com/drive/v3/files/{file_id}?alt=media"
    req = urllib.request.Request(download_url, method="GET")
    req.add_header("Authorization", f"Bearer {token}")

    with urllib.request.urlopen(req) as resp:
        content = resp.read()

    # Validate that it is valid JSON envelope
    parsed = json.loads(content.decode("utf-8"))
    if parsed.get("format") != "otter-vault-v1":
        raise ValueError("Downloaded file is not a valid otter-vault-v1 envelope")

    write_envelope_atomically(dest_path, parsed, backup=True)
    return parsed

# ==============================================================================
# HTTP SERVER & API HANDLERS
# ==============================================================================

class OtterRequestHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(url.query)

        # Google OAuth Loopback Callback
        if url.path == "/oauth/callback":
            code = params.get("code", [None])[0]
            error = params.get("error", [None])[0]
            if error:
                self.send_response(400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<h2>Google OAuth Error: {error}</h2>".encode("utf-8"))
                return

            if not code:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Missing authorization code")
                return

            cfg = load_config()
            client_id = cfg["gdrive"]["client_id"]
            client_secret = cfg["gdrive"]["client_secret"]

            token_url = "https://oauth2.googleapis.com/token"
            post_data = {
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": "http://127.0.0.1:8765/oauth/callback",
                "grant_type": "authorization_code"
            }
            try:
                encoded_data = urllib.parse.urlencode(post_data).encode("utf-8")
                req = urllib.request.Request(token_url, data=encoded_data, method="POST")
                with urllib.request.urlopen(req) as resp:
                    tokens = json.loads(resp.read().decode("utf-8"))

                tokens["expires_at"] = time.time() + tokens.get("expires_in", 3600)
                save_tokens(tokens)

                # Fetch user email for display
                email = None
                try:
                    userinfo_req = urllib.request.Request("https://www.googleapis.com/oauth2/v2/userinfo")
                    userinfo_req.add_header("Authorization", f"Bearer {tokens['access_token']}")
                    with urllib.request.urlopen(userinfo_req) as uresp:
                        uinfo = json.loads(uresp.read().decode("utf-8"))
                        email = uinfo.get("email")
                        cfg["gdrive"]["account_email"] = email
                        save_config(cfg)
                except Exception:
                    pass

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                html = f"""
                <!DOCTYPE html>
                <html>
                <head>
                  <title>Google Drive Connected - OtterVault</title>
                  <style>
                    body {{ font-family: system-ui, sans-serif; background: #181825; color: #cdd6f4; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                    .card {{ background: #1e1e2e; padding: 32px; border-radius: 12px; border: 1px solid #313244; text-align: center; max-width: 420px; }}
                    h2 {{ color: #a6e3a1; margin-bottom: 12px; }}
                    p {{ color: #a6adc8; font-size: 14px; line-height: 1.5; }}
                  </style>
                </head>
                <body>
                  <div class="card">
                    <h2>Google Drive Connected!</h2>
                    <p>Connected account: <strong>{email or 'Authorized User'}</strong></p>
                    <p>You can close this tab now and return to OtterVault.</p>
                    <script>
                      setTimeout(() => {{ window.close(); }}, 2500);
                    </script>
                  </div>
                </body>
                </html>
                """
                self.wfile.write(html.encode("utf-8"))
            except Exception as e:
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(f"<h2>OAuth Exchange Failed</h2><p>{str(e)}</p>".encode("utf-8"))
            return

        if url.path == "/api/config":
            cfg = load_config()
            tokens = load_tokens()
            cfg["gdrive"]["connected"] = bool(tokens and tokens.get("access_token"))
            self._send_json(cfg)

        elif url.path == "/api/vault/status":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            tokens = load_tokens()
            exists = vault_path.exists()
            status = {
                "exists": exists,
                "file_path": str(vault_path),
                "unlocked": current_session["unlocked"],
                "gdrive_connected": bool(tokens and tokens.get("access_token")),
                "gdrive_email": cfg["gdrive"].get("account_email"),
                "last_sync": cfg["gdrive"].get("last_sync")
            }
            if exists:
                try:
                    with open(vault_path, "r", encoding="utf-8") as f:
                        env = json.load(f)
                    status["version"] = env.get("version")
                    status["format"] = env.get("format")
                    status["item_count"] = env.get("meta", {}).get("item_count", 0)
                    status["last_modified"] = env.get("meta", {}).get("last_modified")
                except Exception:
                    pass
            self._send_json(status)

        elif url.path == "/api/vault/items":
            if not current_session["unlocked"]:
                self._send_json({"error": "Vault is locked"}, 401)
            else:
                self._send_json({"items": current_session["vault"].get("items", [])})

        elif url.path == "/" or url.path == "/index.html":
            html_path = APP_DIR / "index.html"
            with open(html_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        url = urllib.parse.urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_len).decode("utf-8")) if content_len > 0 else {}

        if url.path == "/api/config":
            updated = save_config(body)
            self._send_json({"success": True, "config": updated})

        elif url.path == "/api/gdrive/auth-url":
            cfg = load_config()
            client_id = cfg["gdrive"]["client_id"].strip()
            if not client_id:
                self._send_json({"error": "Google Client ID is not configured. Please paste it in Settings first."}, 400)
                return

            redirect_uri = "http://127.0.0.1:8765/oauth/callback"
            scope = "https://www.googleapis.com/auth/drive.appdata https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/userinfo.email"
            auth_url = (
                f"https://accounts.google.com/o/oauth2/v2/auth?"
                f"client_id={urllib.parse.quote(client_id)}&"
                f"redirect_uri={urllib.parse.quote(redirect_uri)}&"
                f"response_type=code&"
                f"scope={urllib.parse.quote(scope)}&"
                f"access_type=offline&"
                f"prompt=consent"
            )
            # Directly launch system browser on Linux
            launched = open_system_browser(auth_url)
            self._send_json({"auth_url": auth_url, "launched": launched})

        elif url.path == "/api/gdrive/disconnect":
            if DEFAULT_TOKEN_PATH.exists():
                DEFAULT_TOKEN_PATH.unlink()
            cfg = load_config()
            cfg["gdrive"]["account_email"] = None
            save_config(cfg)
            self._send_json({"success": True, "message": "Google Drive disconnected"})

        elif url.path == "/api/gdrive/sync":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            if not vault_path.exists():
                self._send_json({"error": "Local vault file does not exist yet. Please add an item first."}, 400)
                return

            try:
                token = gdrive_get_valid_token(cfg)
                target_folder = cfg["gdrive"].get("target_folder", "appDataFolder")

                # Perform actual Google Drive upload
                res_meta, action = gdrive_upload_vault(token, vault_path, target_folder)

                cfg["gdrive"]["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
                save_config(cfg)

                self._send_json({
                    "success": True,
                    "action": action,
                    "drive_file_id": res_meta.get("id"),
                    "timestamp": cfg["gdrive"]["last_sync"],
                    "message": f"Successfully synced vault to Google Drive ({action})"
                })
            except ValueError as ve:
                print(f"[OtterVault] Sync notice: {ve}")
                self._send_json({"error": str(ve)}, 400)
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="ignore")
                try:
                    err_json = json.loads(err_body)
                    msg = err_json.get("error", {}).get("message", err_body)
                except Exception:
                    msg = err_body or str(e)
                print(f"[OtterVault] Google Drive API Error ({e.code}): {msg}")
                self._send_json({"error": msg}, 500)
            except Exception as e:
                print(f"[OtterVault] Sync Exception: {str(e)}")
                self._send_json({"error": f"Google Drive sync failed: {str(e)}"}, 500)

        elif url.path == "/api/vault/init":
            master_pass = body.get("password")
            if not master_pass:
                self._send_json({"error": "Master password is required"}, 400)
                return
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            empty_vault = {
                "version": 1,
                "items": [],
                "created_at": int(time.time()),
                "updated_at": int(time.time())
            }
            envelope = encrypt_vault(empty_vault, master_pass, cfg["security"]["kdf_iterations"])
            write_envelope_atomically(vault_path, envelope)
            current_session["unlocked"] = True
            current_session["master_password"] = master_pass
            current_session["vault"] = empty_vault
            self._send_json({"success": True, "message": "Vault initialized successfully"})

        elif url.path == "/api/vault/unlock":
            master_pass = body.get("password")
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            if not vault_path.exists():
                self._send_json({"error": "Vault file does not exist, run init first"}, 404)
                return
            try:
                with open(vault_path, "r", encoding="utf-8") as f:
                    envelope = json.load(f)
                decrypted = decrypt_vault(envelope, master_pass)
                current_session["unlocked"] = True
                current_session["master_password"] = master_pass
                current_session["vault"] = decrypted
                self._send_json({"success": True, "items": decrypted.get("items", [])})
            except Exception:
                self._send_json({"error": "Invalid master password or corrupted envelope"}, 401)

        elif url.path == "/api/vault/lock":
            current_session["unlocked"] = False
            current_session["master_password"] = None
            current_session["vault"] = None
            self._send_json({"success": True, "message": "Vault locked"})

        elif url.path == "/api/vault/save":
            if not current_session["unlocked"]:
                self._send_json({"error": "Vault is locked"}, 401)
                return
            items = body.get("items", [])
            current_session["vault"]["items"] = items
            current_session["vault"]["updated_at"] = int(time.time())

            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            envelope = encrypt_vault(
                current_session["vault"],
                current_session["master_password"],
                cfg["security"]["kdf_iterations"]
            )
            write_envelope_atomically(vault_path, envelope, cfg["vault"]["auto_backup"])

            # Auto sync if enabled and connected
            sync_result = None
            if cfg["gdrive"]["enabled"] and load_tokens():
                try:
                    token = gdrive_get_valid_token(cfg)
                    res_meta, action = gdrive_upload_vault(token, vault_path, cfg["gdrive"]["target_folder"])
                    cfg["gdrive"]["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    save_config(cfg)
                    sync_result = "synced_to_drive"
                except Exception as ex:
                    sync_result = f"drive_error: {str(ex)}"

            self._send_json({
                "success": True,
                "message": "Vault saved successfully",
                "auto_sync": sync_result
            })

        elif url.path == "/api/vault/change-password":
            if not current_session["unlocked"]:
                self._send_json({"error": "Vault is locked"}, 401)
                return
            current_pass = body.get("current_password")
            new_pass = body.get("new_password")
            if current_pass != current_session["master_password"]:
                self._send_json({"error": "Current password does not match"}, 400)
                return
            if not new_pass:
                self._send_json({"error": "New password cannot be empty"}, 400)
                return

            current_session["master_password"] = new_pass
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            envelope = encrypt_vault(
                current_session["vault"],
                new_pass,
                cfg["security"]["kdf_iterations"]
            )
            write_envelope_atomically(vault_path, envelope, True)
            self._send_json({"success": True, "message": "Master password changed and vault re-encrypted"})

        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=8765):
    server = HTTPServer(("127.0.0.1", port), OtterRequestHandler)
    print(f"[OtterVault] Live server running on http://127.0.0.1:{port}")
    server.serve_forever()

def launch_gtk_window(port=8765):
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("WebKit2", "4.1")
    from gi.repository import Gtk, WebKit2

    win = Gtk.Window(title="OtterVault - Linux Personal Vault")
    win.set_default_size(1240, 800)
    win.set_position(Gtk.WindowPosition.CENTER)
    win.connect("destroy", Gtk.main_quit)

    webview = WebKit2.WebView()
    settings = webview.get_settings()
    settings.set_enable_developer_extras(True)
    settings.set_javascript_can_open_windows_automatically(True)

    # Intercept any external links or popups and open in the system browser
    def on_decide_policy(view, decision, decision_type):
        if decision_type in (WebKit2.PolicyDecisionType.NAVIGATION_ACTION, WebKit2.PolicyDecisionType.NEW_WINDOW_ACTION):
            req = decision.get_request()
            uri = req.get_uri()
            if uri and not uri.startswith("http://127.0.0.1") and not uri.startswith("http://localhost"):
                open_system_browser(uri)
                decision.ignore()
                return True
        return False

    webview.connect("decide-policy", on_decide_policy)

    webview.load_uri(f"http://127.0.0.1:{port}")
    win.add(webview)
    win.show_all()
    Gtk.main()

if __name__ == "__main__":
    import threading
    port = 8765
    server_thread = threading.Thread(target=run_server, args=(port,), daemon=True)
    server_thread.start()
    time.sleep(0.5)

    if "--headless" in sys.argv or "--server" in sys.argv:
        print(f"Server running at http://127.0.0.1:{port}. Press Ctrl+C to stop.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    elif "--browser" in sys.argv:
        import webbrowser
        webbrowser.open(f"http://127.0.0.1:{port}")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
    else:
        try:
            launch_gtk_window(port)
        except Exception as e:
            print(f"[OtterVault] GTK window error: {e}")
            import webbrowser
            webbrowser.open(f"http://127.0.0.1:{port}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
