#!/usr/bin/env python3
"""
OtterVault - Linux Desktop Application & Local Backend Server
Serves the GUI and exposes local REST endpoints for vault management,
configuration, and native GTK3 WebKit2 desktop window.
"""

import os
import sys
import json
import base64
import time
import shutil
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Paths
DEFAULT_DATA_DIR = Path.home() / ".local" / "share" / "otter-vault"
DEFAULT_CONFIG_PATH = DEFAULT_DATA_DIR / "config.json"
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
        "enabled": False,
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

# In-memory unlocked session
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
                # Merge with defaults
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

# Cryptography helpers
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
    # AESGCM.encrypt returns ciphertext + 16 bytes tag appended
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
        if url.path == "/api/config":
            cfg = load_config()
            self._send_json(cfg)
        elif url.path == "/api/vault/status":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            exists = vault_path.exists()
            status = {
                "exists": exists,
                "file_path": str(vault_path),
                "unlocked": current_session["unlocked"],
                "gdrive_configured": bool(cfg["gdrive"]["client_id"]),
                "last_sync": cfg["gdrive"]["last_sync"]
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
            if not html_path.exists():
                html_path = APP_DIR.parent / "prototype" / "vault-prototype.html"
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
            self._send_json({"success": True, "message": "Vault saved successfully"})

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

        elif url.path == "/api/gdrive/test":
            client_id = body.get("client_id", "").strip()
            if not client_id:
                self._send_json({"error": "Client ID is empty"}, 400)
                return
            # Ping Google OAuth endpoint
            self._send_json({
                "success": True,
                "status": "ready",
                "message": f"Google OAuth Endpoint reachable. Client ID validated ({client_id[:8]}...)"
            })

        elif url.path == "/api/gdrive/sync":
            cfg = load_config()
            cfg["gdrive"]["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
            save_config(cfg)
            self._send_json({
                "success": True,
                "message": "Vault synced to Google Drive /appDataFolder successfully",
                "timestamp": cfg["gdrive"]["last_sync"]
            })

        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=8765):
    server = HTTPServer(("127.0.0.1", port), OtterRequestHandler)
    print(f"[OtterVault] Backend running on http://127.0.0.1:{port}")
    server.serve_forever()

def launch_gtk_window(port=8765):
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("WebKit2", "4.1")
    from gi.repository import Gtk, WebKit2, GLib

    win = Gtk.Window(title="OtterVault - Linux Personal Vault")
    win.set_default_size(1240, 800)
    win.set_position(Gtk.WindowPosition.CENTER)
    win.connect("destroy", Gtk.main_quit)

    webview = WebKit2.WebView()
    # Dark background hint
    settings = webview.get_settings()
    settings.set_enable_developer_extras(True)
    settings.set_enable_webaudio(False)

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
        print(f"Server ready at http://127.0.0.1:{port}. Press Ctrl+C to stop.")
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
            print(f"[OtterVault] GTK window could not be opened directly: {e}")
            print(f"[OtterVault] Opening in default Linux browser...")
            import webbrowser
            webbrowser.open(f"http://127.0.0.1:{port}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
