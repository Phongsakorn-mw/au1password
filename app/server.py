#!/usr/bin/env python3
"""
Au1Password - Linux Desktop Application & Local Backend Server
Handles zero-knowledge vault storage, real Google OAuth 2.0 PKCE / Web flow,
Multi-Cloud Sync (GitHub, GitLab, SafeHost), and local REST API.
"""

import os
import secrets
import sys
import json
import base64
import time
import shutil
import uuid
import socket
import subprocess
import tempfile
import sqlite3
import re
import hmac
import hashlib
import struct
import urllib.parse
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# Paths
data_dir_env = os.environ.get("AU1_DATA_DIR") or os.environ.get("OTTER_DATA_DIR")
if data_dir_env:
    DEFAULT_DATA_DIR = Path(data_dir_env)
else:
    new_dir = Path.home() / ".local" / "share" / "au1password"
    legacy_dir = Path.home() / ".local" / "share" / "otter-vault"
    DEFAULT_DATA_DIR = legacy_dir if (not new_dir.exists() and legacy_dir.exists()) else new_dir

CURRENT_FORMAT_ID = "au1password-vault-v1"
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
    "sync": {
        "active_provider": "gdrive",
        "sync_mode": "auto",
        "conflict_policy": "prompt",
        "github": {
            "enabled": False,
            "token": "",
            "target_type": "repo",
            "repo": "",
            "branch": "main",
            "file_path": "vault.enc",
            "gist_id": "",
            "last_sync": None
        },
        "gitlab": {
            "enabled": False,
            "server_url": "https://gitlab.com",
            "token": "",
            "project_id": "",
            "branch": "main",
            "file_path": "vault.enc",
            "last_sync": None
        },
        "safehost": {
            "enabled": False,
            "endpoint_url": "",
            "auth_type": "bearer",
            "auth_token": "",
            "last_sync": None
        }
    },
    "security": {
        "auto_lock_mins": 15,
        "clear_clipboard_secs": 30,
        "mask_passwords_default": True,
        "kdf_iterations": 600000
    },
    "appearance": {
        "theme": "adwaita-dark",
        "default_layout": "adwaita",
        "compact_mode": False
    }
}

current_session = {
    "username": None,
    "unlocked": False,
    "derived_key": None,
    "salt": None,
    "vault": None,
    "session_token": None,
    "token_created_at": 0,
    "master_password": None
}

# Multi-User Database & Active Sessions Store
DB_PATH = DEFAULT_DATA_DIR / "au1password.db"
active_sessions = {}
temp_2fa_sessions = {}
temp_2fa_setups = {}

def verify_totp(secret: str, code: str, window: int = 1) -> bool:
    """Verify standard RFC 6238 TOTP 6-digit code with +/- window steps."""
    if not secret or not code:
        return False
    try:
        clean = str(secret).strip().replace(" ", "").upper()
        clean += "=" * ((8 - len(clean) % 8) % 8)
        key = base64.b32decode(clean, casefold=True)
    except Exception:
        return False

    current_t = int(time.time() // 30)
    target = str(code).strip()
    if len(target) != 6 or not target.isdigit():
        return False

    for t in range(current_t - window, current_t + window + 1):
        counter = struct.pack(">Q", t)
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset = digest[19] & 0x0F
        val = (
            ((digest[offset] & 0x7F) << 24)
            | ((digest[offset + 1] & 0xFF) << 16)
            | ((digest[offset + 2] & 0xFF) << 8)
            | (digest[offset + 3] & 0xFF)
        ) % 1_000_000
        step_code = f"{val:06d}"
        if hmac.compare_digest(step_code, target):
            return True
    return False

def init_db():
    DEFAULT_DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY COLLATE NOCASE,
                salt TEXT,
                envelope TEXT,
                created_at REAL,
                updated_at REAL,
                totp_secret TEXT,
                totp_enabled INTEGER DEFAULT 0
            )
        """)
        try:
            conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass
        conn.commit()

init_db()

ephemeral_sends = {}

unlock_rate_limiter = {
    "failed_attempts": 0,
    "lockout_until": 0.0,
    "last_attempt": 0.0
}

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"

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
                print(f"[Au1Password] Launched system browser using {cmd}: {url[:60]}...")
                return True
            except Exception as e:
                print(f"[Au1Password] Failed to launch {cmd}: {e}")
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

def encrypt_vault(vault_data: dict, password: str = None, key: bytes = None, salt: bytes = None, iterations: int = 600000) -> tuple:
    if key is None:
        if not password:
            raise ValueError("Either password or key must be provided")
        salt = os.urandom(32)
        key = derive_key(password, salt, iterations)
    elif salt is None:
        salt = os.urandom(32)

    iv = os.urandom(12)
    aesgcm = AESGCM(key)

    plaintext = json.dumps(vault_data).encode("utf-8")
    ciphertext_and_tag = aesgcm.encrypt(iv, plaintext, b"au1password-vault-v1")

    split_idx = len(ciphertext_and_tag) - 16
    ciphertext = ciphertext_and_tag[:split_idx]
    tag = ciphertext_and_tag[split_idx:]

    envelope = {
        "version": 1,
        "format": "au1password-vault-v1",
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
    return envelope, key, salt

def decrypt_vault(envelope: dict, password: str = None, key: bytes = None) -> tuple:
    fmt = envelope.get("format")
    if fmt not in ("au1password-vault-v1", "otter-vault-v1"):
        raise ValueError(f"Unsupported format: {fmt}")

    salt = base64.b64decode(envelope["kdf"]["salt_base64"])
    iterations = envelope["kdf"]["iterations"]

    iv = base64.b64decode(envelope["cipher"]["iv_base64"])
    tag = base64.b64decode(envelope["cipher"]["tag_base64"])
    ciphertext = base64.b64decode(envelope["ciphertext_base64"])
    ciphertext_and_tag = ciphertext + tag

    # AAD candidates: primary first, fallback second
    primary_aad = b"au1password-vault-v1" if fmt == "au1password-vault-v1" else b"otter-vault-v1"
    candidate_aads = [primary_aad, b"otter-vault-v1" if primary_aad == b"au1password-vault-v1" else b"au1password-vault-v1"]

    if key is not None:
        aesgcm = AESGCM(key)
        for aad in candidate_aads:
            try:
                plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, aad)
                return json.loads(plaintext.decode("utf-8")), key, salt
            except Exception:
                pass
        raise ValueError("Decryption failed with provided key")

    if not password:
        raise ValueError("Either password or key must be provided")

    # Seamless Iteration Compatibility:
    # Try envelope iteration count first (e.g. 600,000), then fallback to legacy 250,000
    candidate_iterations = [iterations]
    if 250000 not in candidate_iterations:
        candidate_iterations.append(250000)
    if 600000 not in candidate_iterations:
        candidate_iterations.append(600000)

    last_error = None
    for it in candidate_iterations:
        candidate_key = derive_key(password, salt, it)
        aesgcm = AESGCM(candidate_key)
        for aad in candidate_aads:
            try:
                plaintext = aesgcm.decrypt(iv, ciphertext_and_tag, aad)
                return json.loads(plaintext.decode("utf-8")), candidate_key, salt
            except Exception as e:
                last_error = e

    raise last_error

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
        token_scopes = tokens.get("scope", "").split()
        has_drive_scope = any(s in ("https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file") for s in token_scopes)
        if not has_drive_scope:
            raise ValueError(
                "Google Account needs 'drive.file' scope for My Drive. "
                "Please click 'Re-connect' in Settings to grant Drive access, or change Target Folder back to 'appDataFolder'."
            )

    client_id = cfg["gdrive"]["client_id"]
    client_secret = cfg["gdrive"]["client_secret"]

    # If expires in under 60 seconds, refresh
    if time.time() >= (tokens.get("expires_at", 0) - 60):
        return gdrive_refresh_access_token(tokens, client_id, client_secret)
    return tokens["access_token"]

def gdrive_find_vault_file(token, target_folder="appDataFolder"):
    spaces = "drive" if target_folder in ("MyDrive", "root") else "appDataFolder"
    # Search for canonical au1password-vault.enc first, then fallback to legacy otter-vault.enc
    for fname in ("au1password-vault.enc", "otter-vault.enc"):
        q = urllib.parse.quote(f"name = '{fname}' and trashed = false")
        fields = urllib.parse.quote("files(id, name, modifiedTime, size)")
        url = f"https://www.googleapis.com/drive/v3/files?spaces={spaces}&q={q}&fields={fields}"

        req = urllib.request.Request(url, method="GET")
        req.add_header("Authorization", f"Bearer {token}")

        try:
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                files = data.get("files", [])
                if files:
                    return files[0]
        except Exception:
            pass
    return None

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
        boundary = f"-------Au1PasswordBoundary{int(time.time())}"
        parent_id = "root" if target_folder in ("MyDrive", "root") else "appDataFolder"
        metadata = {
            "name": "au1password-vault.enc",
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
    if parsed.get("format") not in ("au1password-vault-v1", "otter-vault-v1"):
        raise ValueError("Downloaded file is not a valid vault envelope")

    write_envelope_atomically(dest_path, parsed, backup=True)
    return parsed

# ==============================================================================
# MULTI-CLOUD SYNC ENGINES: GITHUB, GITLAB, SAFEHOST
# ==============================================================================

def github_test_connection(token: str) -> dict:
    """Validate GitHub Personal Access Token."""
    if not token:
        raise ValueError("GitHub token is required")
    req = urllib.request.Request("https://api.github.com/user")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "Au1Password-Vault/1.0")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return {"login": data.get("login"), "name": data.get("name"), "id": data.get("id")}

def github_upload_vault(cfg_gh: dict, vault_path: Path) -> dict:
    """Push Zero-Knowledge encrypted vault to GitHub (Private Repo or Gist)."""
    with open(vault_path, "rb") as f:
        vault_bytes = f.read()

    token = cfg_gh.get("token", "").strip()
    if not token:
        raise ValueError("GitHub token is not configured")

    target_type = cfg_gh.get("target_type", "repo")
    file_path = cfg_gh.get("file_path", "vault.enc").strip() or "vault.enc"

    if target_type == "gist":
        gist_id = cfg_gh.get("gist_id", "").strip()
        url = f"https://api.github.com/gists/{gist_id}" if gist_id else "https://api.github.com/gists"
        method = "PATCH" if gist_id else "POST"
        payload = {
            "description": "Au1Password Zero-Knowledge Encrypted Vault",
            "public": False,
            "files": {
                file_path: {"content": vault_bytes.decode("utf-8")}
            }
        }
        req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), method=method)
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "Au1Password-Vault/1.0")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return {"id": data.get("id"), "url": data.get("html_url"), "action": "updated" if gist_id else "created", "provider": "github_gist"}

    # Private Repository Push
    repo = cfg_gh.get("repo", "").strip()
    if not repo or "/" not in repo:
        raise ValueError("GitHub repository must be specified as 'owner/repo'")
    branch = cfg_gh.get("branch", "main").strip() or "main"

    # Check existing file for sha
    api_url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch}"
    sha = None
    try:
        check_req = urllib.request.Request(api_url)
        check_req.add_header("Authorization", f"Bearer {token}")
        check_req.add_header("Accept", "application/vnd.github.v3+json")
        check_req.add_header("User-Agent", "Au1Password-Vault/1.0")
        with urllib.request.urlopen(check_req, timeout=10) as resp:
            existing = json.loads(resp.read().decode("utf-8"))
            sha = existing.get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    b64_content = base64.b64encode(vault_bytes).decode("ascii")
    put_url = f"https://api.github.com/repos/{repo}/contents/{file_path}"
    payload = {
        "message": f"Au1Password Zero-Knowledge vault sync [{time.strftime('%Y-%m-%d %H:%M:%S')}]",
        "content": b64_content,
        "branch": branch
    }
    if sha:
        payload["sha"] = sha

    put_req = urllib.request.Request(put_url, data=json.dumps(payload).encode("utf-8"), method="PUT")
    put_req.add_header("Authorization", f"Bearer {token}")
    put_req.add_header("Accept", "application/vnd.github.v3+json")
    put_req.add_header("User-Agent", "Au1Password-Vault/1.0")
    with urllib.request.urlopen(put_req, timeout=15) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        commit_sha = res.get("commit", {}).get("sha", "")[:7]
        return {"commit": commit_sha, "action": "updated" if sha else "created", "provider": "github"}

def github_download_vault(cfg_gh: dict, vault_path: Path) -> dict:
    """Pull Zero-Knowledge encrypted vault from GitHub."""
    token = cfg_gh.get("token", "").strip()
    if not token:
        raise ValueError("GitHub token is not configured")

    target_type = cfg_gh.get("target_type", "repo")
    file_path = cfg_gh.get("file_path", "vault.enc").strip() or "vault.enc"

    if target_type == "gist":
        gist_id = cfg_gh.get("gist_id", "").strip()
        if not gist_id:
            raise ValueError("GitHub Gist ID is required")
        req = urllib.request.Request(f"https://api.github.com/gists/{gist_id}")
        req.add_header("Authorization", f"Bearer {token}")
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "Au1Password-Vault/1.0")
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            files = data.get("files", {})
            file_info = files.get(file_path) or (list(files.values())[0] if files else None)
            if not file_info:
                raise ValueError("Vault file not found in Gist")
            content = file_info.get("content", "")
            envelope = json.loads(content)
            write_envelope_atomically(vault_path, envelope, backup=True)
            return envelope

    repo = cfg_gh.get("repo", "").strip()
    if not repo or "/" not in repo:
        raise ValueError("GitHub repository must be specified as 'owner/repo'")
    branch = cfg_gh.get("branch", "main").strip() or "main"

    api_url = f"https://api.github.com/repos/{repo}/contents/{file_path}?ref={branch}"
    req = urllib.request.Request(api_url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "Au1Password-Vault/1.0")
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        b64_content = data.get("content", "").replace("\n", "").replace("\r", "")
        content = base64.b64decode(b64_content).decode("utf-8")
        envelope = json.loads(content)
        write_envelope_atomically(vault_path, envelope, backup=True)
        return envelope

def gitlab_test_connection(server_url: str, token: str) -> dict:
    """Validate GitLab Personal/Project Access Token."""
    if not token:
        raise ValueError("GitLab token is required")
    base_url = (server_url or "https://gitlab.com").rstrip("/")
    req = urllib.request.Request(f"{base_url}/api/v4/user")
    req.add_header("PRIVATE-TOKEN", token)
    req.add_header("User-Agent", "Au1Password-Vault/1.0")
    with urllib.request.urlopen(req, timeout=10) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return {"username": data.get("username"), "name": data.get("name"), "id": data.get("id")}

def gitlab_upload_vault(cfg_gl: dict, vault_path: Path) -> dict:
    """Push Zero-Knowledge encrypted vault to GitLab Project."""
    with open(vault_path, "rb") as f:
        vault_bytes = f.read()

    token = cfg_gl.get("token", "").strip()
    if not token:
        raise ValueError("GitLab token is not configured")
    project_id = str(cfg_gl.get("project_id", "")).strip()
    if not project_id:
        raise ValueError("GitLab Project ID or URL-encoded path is required")

    server_url = (cfg_gl.get("server_url") or "https://gitlab.com").rstrip("/")
    branch = cfg_gl.get("branch", "main").strip() or "main"
    file_path = urllib.parse.quote(cfg_gl.get("file_path", "vault.enc").strip() or "vault.enc", safe="")
    encoded_project = urllib.parse.quote(project_id, safe="")

    # Check if file exists
    check_url = f"{server_url}/api/v4/projects/{encoded_project}/repository/files/{file_path}?ref={branch}"
    exists = False
    try:
        check_req = urllib.request.Request(check_url)
        check_req.add_header("PRIVATE-TOKEN", token)
        check_req.add_header("User-Agent", "Au1Password-Vault/1.0")
        with urllib.request.urlopen(check_req, timeout=10) as resp:
            exists = True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            exists = False
        else:
            raise

    b64_content = base64.b64encode(vault_bytes).decode("ascii")
    action_url = f"{server_url}/api/v4/projects/{encoded_project}/repository/files/{file_path}"
    method = "PUT" if exists else "POST"
    payload = {
        "branch": branch,
        "content": b64_content,
        "encoding": "base64",
        "commit_message": f"Au1Password Zero-Knowledge automated vault sync [skip ci]"
    }
    req = urllib.request.Request(action_url, data=json.dumps(payload).encode("utf-8"), method=method)
    req.add_header("PRIVATE-TOKEN", token)
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "Au1Password-Vault/1.0")
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return {"file_path": data.get("file_path"), "action": "updated" if exists else "created", "provider": "gitlab"}

def gitlab_download_vault(cfg_gl: dict, vault_path: Path) -> dict:
    """Pull Zero-Knowledge encrypted vault from GitLab."""
    token = cfg_gl.get("token", "").strip()
    if not token:
        raise ValueError("GitLab token is not configured")
    project_id = str(cfg_gl.get("project_id", "")).strip()
    if not project_id:
        raise ValueError("GitLab Project ID is required")

    server_url = (cfg_gl.get("server_url") or "https://gitlab.com").rstrip("/")
    branch = cfg_gl.get("branch", "main").strip() or "main"
    file_path = urllib.parse.quote(cfg_gl.get("file_path", "vault.enc").strip() or "vault.enc", safe="")
    encoded_project = urllib.parse.quote(project_id, safe="")

    raw_url = f"{server_url}/api/v4/projects/{encoded_project}/repository/files/{file_path}/raw?ref={branch}"
    req = urllib.request.Request(raw_url)
    req.add_header("PRIVATE-TOKEN", token)
    req.add_header("User-Agent", "Au1Password-Vault/1.0")
    with urllib.request.urlopen(req, timeout=15) as resp:
        content = resp.read().decode("utf-8")
        envelope = json.loads(content)
        write_envelope_atomically(vault_path, envelope, backup=True)
        return envelope

def safehost_upload_vault(cfg_sh: dict, vault_path: Path) -> dict:
    """Push Zero-Knowledge encrypted vault to SafeHost / Custom WebDAV / HTTPS Object Storage."""
    with open(vault_path, "rb") as f:
        vault_bytes = f.read()

    endpoint_url = cfg_sh.get("endpoint_url", "").strip()
    if not endpoint_url:
        raise ValueError("SafeHost endpoint URL is not configured")

    auth_type = cfg_sh.get("auth_type", "bearer").lower()
    auth_token = cfg_sh.get("auth_token", "").strip()

    req = urllib.request.Request(endpoint_url, data=vault_bytes, method="PUT")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    req.add_header("User-Agent", "Au1Password-Vault/1.0")
    if auth_token:
        if auth_type == "bearer":
            req.add_header("Authorization", f"Bearer {auth_token}")
        elif auth_type == "basic":
            req.add_header("Authorization", f"Basic {auth_token}")
        elif auth_type == "header":
            req.add_header("X-SafeHost-Key", auth_token)

    with urllib.request.urlopen(req, timeout=15) as resp:
        return {"status": resp.status, "action": "pushed", "provider": "safehost"}

def safehost_download_vault(cfg_sh: dict, vault_path: Path) -> dict:
    """Pull Zero-Knowledge encrypted vault from SafeHost / Custom WebDAV / HTTPS Object Storage."""
    endpoint_url = cfg_sh.get("endpoint_url", "").strip()
    if not endpoint_url:
        raise ValueError("SafeHost endpoint URL is not configured")

    auth_type = cfg_sh.get("auth_type", "bearer").lower()
    auth_token = cfg_sh.get("auth_token", "").strip()

    req = urllib.request.Request(endpoint_url, method="GET")
    req.add_header("User-Agent", "Au1Password-Vault/1.0")
    if auth_token:
        if auth_type == "bearer":
            req.add_header("Authorization", f"Bearer {auth_token}")
        elif auth_type == "basic":
            req.add_header("Authorization", f"Basic {auth_token}")
        elif auth_type == "header":
            req.add_header("X-SafeHost-Key", auth_token)

    with urllib.request.urlopen(req, timeout=15) as resp:
        content = resp.read().decode("utf-8")
        envelope = json.loads(content)
        write_envelope_atomically(vault_path, envelope, backup=True)
        return envelope

def sync_push_active(cfg: dict, vault_path: Path) -> tuple:
    """Unified push to active sync provider."""
    active = cfg.get("sync", {}).get("active_provider", "gdrive")
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    if active == "github":
        res = github_upload_vault(cfg["sync"]["github"], vault_path)
        cfg["sync"]["github"]["last_sync"] = now_str
        save_config(cfg)
        return res, "GitHub"
    elif active == "gitlab":
        res = gitlab_upload_vault(cfg["sync"]["gitlab"], vault_path)
        cfg["sync"]["gitlab"]["last_sync"] = now_str
        save_config(cfg)
        return res, "GitLab"
    elif active == "safehost":
        res = safehost_upload_vault(cfg["sync"]["safehost"], vault_path)
        cfg["sync"]["safehost"]["last_sync"] = now_str
        save_config(cfg)
        return res, "SafeHost"
    else:
        # Default Google Drive
        token = gdrive_get_valid_token(cfg)
        target_folder = cfg["gdrive"].get("target_folder", "appDataFolder")
        res_meta, action = gdrive_upload_vault(token, vault_path, target_folder)
        cfg["gdrive"]["last_sync"] = now_str
        save_config(cfg)
        return {"action": action, "drive_file_id": res_meta.get("id")}, "Google Drive"

def sync_pull_active(cfg: dict, vault_path: Path) -> tuple:
    """Unified pull from active sync provider."""
    active = cfg.get("sync", {}).get("active_provider", "gdrive")
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    if active == "github":
        envelope = github_download_vault(cfg["sync"]["github"], vault_path)
        cfg["sync"]["github"]["last_sync"] = now_str
        save_config(cfg)
        return envelope, "GitHub"
    elif active == "gitlab":
        envelope = gitlab_download_vault(cfg["sync"]["gitlab"], vault_path)
        cfg["sync"]["gitlab"]["last_sync"] = now_str
        save_config(cfg)
        return envelope, "GitLab"
    elif active == "safehost":
        envelope = safehost_download_vault(cfg["sync"]["safehost"], vault_path)
        cfg["sync"]["safehost"]["last_sync"] = now_str
        save_config(cfg)
        return envelope, "SafeHost"
    else:
        token = gdrive_get_valid_token(cfg)
        target_folder = cfg["gdrive"].get("target_folder", "appDataFolder")
        cloud_file = gdrive_find_vault_file(token, target_folder)
        if not cloud_file:
            raise ValueError("No vault file found on Google Drive. Push first.")
        envelope = gdrive_download_vault(token, cloud_file["id"], vault_path)
        cfg["gdrive"]["last_sync"] = now_str
        save_config(cfg)
        return envelope, "Google Drive"

# ==============================================================================
# GOOGLE AUTHENTICATOR MIGRATION & QR CODE DECODER (PURE NATIVE)
# ==============================================================================

def base32_encode(raw_bytes: bytes) -> str:
    """Encode raw bytes to RFC 4648 Base32 string without external libs."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    bits = ""
    for b in raw_bytes:
        bits += f"{b:08b}"
    padding = (5 - (len(bits) % 5)) % 5
    bits += "0" * padding
    res = []
    for i in range(0, len(bits), 5):
        chunk = bits[i:i+5]
        res.append(chars[int(chunk, 2)])
    return "".join(res)

def parse_varint(buffer: bytes, offset: int) -> tuple:
    """Parse a protobuf varint starting at offset."""
    res = 0
    shift = 0
    while True:
        if offset >= len(buffer):
            raise ValueError("Truncated protobuf varint")
        b = buffer[offset]
        offset += 1
        res |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return res, offset

def parse_protobuf(buffer: bytes) -> list:
    """Parse protobuf wire format into list of (field_num, wire_type, data)."""
    offset = 0
    fields = []
    while offset < len(buffer):
        try:
            tag, offset = parse_varint(buffer, offset)
        except ValueError:
            break
        field_num = tag >> 3
        wire_type = tag & 0x07
        if wire_type == 0:  # Varint
            val, offset = parse_varint(buffer, offset)
            fields.append((field_num, wire_type, val))
        elif wire_type == 2:  # Length-delimited
            length, offset = parse_varint(buffer, offset)
            if offset + length > len(buffer):
                break
            val = buffer[offset:offset+length]
            offset += length
            fields.append((field_num, wire_type, val))
        else:
            break
    return fields

def parse_migration_uri(uri: str) -> list:
    """
    Parse a Google Authenticator 'otpauth-migration://offline?data=...' URI.
    Extracts all accounts and returns list of dicts with Base32 secret, name, issuer.
    """
    parsed = urllib.parse.urlparse(uri)
    query = urllib.parse.parse_qs(parsed.query)
    data_b64 = query.get("data", [""])[0]
    if not data_b64:
        raise ValueError("Missing 'data' parameter in migration URI")
    
    data_b64 = urllib.parse.unquote(data_b64)
    missing_padding = len(data_b64) % 4
    if missing_padding:
        data_b64 += "=" * (4 - missing_padding)
    
    payload_bytes = base64.b64decode(data_b64)
    top_fields = parse_protobuf(payload_bytes)
    accounts = []

    for f_num, w_type, val in top_fields:
        if f_num == 1 and w_type == 2:  # otp_parameters
            subfields = parse_protobuf(val)
            acc = {
                "secret": "",
                "name": "",
                "issuer": "",
                "algorithm": "SHA1",
                "digits": 6,
                "type": "TOTP"
            }
            for sf_num, sw_type, sval in subfields:
                if sf_num == 1:  # secret bytes
                    acc["secret"] = base32_encode(sval)
                elif sf_num == 2:  # name string
                    acc["name"] = sval.decode("utf-8", errors="replace")
                elif sf_num == 3:  # issuer string
                    acc["issuer"] = sval.decode("utf-8", errors="replace")
                elif sf_num == 4:  # algorithm enum
                    acc["algorithm"] = {1: "SHA1", 2: "SHA256", 3: "SHA512", 4: "MD5"}.get(sval, "SHA1")
                elif sf_num == 5:  # digits enum
                    acc["digits"] = 8 if sval == 2 else 6
                elif sf_num == 6:  # type enum
                    acc["type"] = "HOTP" if sval == 1 else "TOTP"
            if acc["secret"]:
                if not acc["issuer"] and ":" in acc["name"]:
                    acc["issuer"] = acc["name"].split(":", 1)[0].strip()
                accounts.append(acc)
    return accounts

def parse_standard_otpauth(uri: str) -> dict:
    """Parse standard otpauth://totp/... single account URI."""
    parsed = urllib.parse.urlparse(uri)
    path = urllib.parse.unquote(parsed.path.lstrip("/"))
    query = urllib.parse.parse_qs(parsed.query)
    secret = query.get("secret", [""])[0].strip().upper().replace(" ", "")
    issuer = query.get("issuer", [""])[0].strip()
    if not issuer and ":" in path:
        issuer = path.split(":", 1)[0].strip()
    name = path or "Authenticator Account"
    algo = query.get("algorithm", ["SHA1"])[0].upper()
    try:
        digits = int(query.get("digits", [6])[0])
    except Exception:
        digits = 6
    otp_type = parsed.netloc.upper() or "TOTP"
    return {
        "secret": secret,
        "name": name,
        "issuer": issuer,
        "algorithm": algo,
        "digits": digits,
        "type": otp_type
    }

def decode_qr_image(img_data: bytes) -> str:
    """Decode QR code from image bytes using system zbarimg safely."""
    with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as tf:
        tf.write(img_data)
        tf_path = tf.name
    try:
        res = subprocess.run(
            ["zbarimg", "--raw", "-q", tf_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        out = res.stdout.strip()
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("otpauth-migration://") or line.startswith("otpauth://") or line:
                return line
        return out
    finally:
        if os.path.exists(tf_path):
            try:
                os.remove(tf_path)
            except Exception:
                pass

# ==============================================================================
# HTTP SERVER & API HANDLERS
# ==============================================================================

class Au1RequestHandler(BaseHTTPRequestHandler):
    ALLOWED_ORIGINS = {
        "http://127.0.0.1:8765",
        "http://localhost:8765",
        "https://127.0.0.1:8765",
        "https://localhost:8765"
    }

    def _apply_security_headers(self, origin: str = None):
        """Inject production-grade security headers on all responses."""
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Vault-Token")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Vary", "Origin")

        # Hardened defense-in-depth headers
        self.send_header("X-Content-Type-Options", "nosniff")
        host_header = self.headers.get("Host", "").split(":")[0].lower()
        is_hf = host_header.endswith(".hf.space") or host_header.endswith(".huggingface.co") or os.environ.get("ENABLE_HF_EMBED") == "1"

        if is_hf:
            # Allow embedding in Hugging Face Spaces interface
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' http://127.0.0.1:8765 http://localhost:8765 https:; frame-ancestors 'self' https://huggingface.co https://*.huggingface.co;"
            )
        else:
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' http://127.0.0.1:8765 http://localhost:8765 https:;"
            )
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")

    def _validate_origin_and_host(self) -> tuple:
        """Check Origin and Host against strict whitelist to prevent DNS Rebinding and CSRF/SOP bypass."""
        origin = self.headers.get("Origin")
        host_header = self.headers.get("Host", "").split(":")[0].lower()

        # 1. Host Validation (Prevent DNS Rebinding attacks)
        if host_header and host_header not in ("127.0.0.1", "localhost", "0.0.0.0"):
            cfg = load_config()
            allowed_hosts = set(cfg.get("server", {}).get("allowed_hosts", []))
            env_allowed_hosts = os.environ.get("ALLOWED_HOSTS", "")
            if env_allowed_hosts:
                allowed_hosts.update([h.strip().lower() for h in env_allowed_hosts.split(",") if h.strip()])

            # Built-in safe hosting domains and wildcards
            is_allowed = (
                "*" in allowed_hosts
                or host_header in allowed_hosts
                or host_header.endswith(".onrender.com")
                or host_header.endswith(".hf.space")
                or host_header == "huggingface.co"
                or host_header.endswith(".huggingface.co")
                or any(h.startswith("*.") and host_header.endswith(h[1:]) for h in allowed_hosts)
            )

            if not is_allowed:
                print(f"[Security Alert] Blocked suspicious Host header: {host_header}")
                return False, ""

        # 2. Origin Validation
        if not origin:
            # Same-origin direct requests, curl, or CLI
            return True, ""

        if origin in self.ALLOWED_ORIGINS or origin.startswith("chrome-extension://"):
            return True, origin

        clean_origin = origin.lower()
        if (
            clean_origin.endswith(".onrender.com")
            or clean_origin.endswith(".hf.space")
            or clean_origin == "https://huggingface.co"
            or clean_origin.endswith(".huggingface.co")
        ):
            return True, origin

        cfg = load_config()
        allowed_origins = set(cfg.get("server", {}).get("allowed_origins", []))
        env_allowed_origins = os.environ.get("ALLOWED_ORIGINS", "")
        if env_allowed_origins:
            allowed_origins.update([o.strip().lower() for o in env_allowed_origins.split(",") if o.strip()])

        is_origin_allowed = (
            "*" in allowed_origins
            or clean_origin in allowed_origins
            or any(o.startswith("*.") and clean_origin.endswith(o[1:]) for o in allowed_origins)
        )

        if is_origin_allowed:
            return True, origin

        print(f"[Security Alert] Rejected unauthorized cross-origin request from: {origin}")
        return False, ""

    def _extract_token(self) -> str:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        if "X-Vault-Token" in self.headers:
            return self.headers.get("X-Vault-Token", "").strip()
        return ""

    def _validate_session_token(self) -> bool:
        """Enforce cryptographic Bearer Session Token for sensitive vault operations."""
        token = self._extract_token()
        if token and token in active_sessions and active_sessions[token].get("unlocked"):
            return True

        if not current_session["unlocked"] or not current_session.get("session_token"):
            return False

        if not token:
            origin = self.headers.get("Origin", "")
            if origin.startswith("chrome-extension://") and current_session["unlocked"]:
                return True
            return False

        return secrets.compare_digest(token, current_session["session_token"])

    def _get_active_session(self) -> dict:
        token = self._extract_token()
        if token and token in active_sessions:
            return active_sessions[token]
        return current_session

    def _save_session_vault(self, sess: dict, auto_backup: bool = True):
        username = sess.get("username")
        cfg = load_config()
        envelope, _, _ = encrypt_vault(
            sess["vault"],
            key=sess["derived_key"],
            salt=sess["salt"],
            iterations=cfg["security"]["kdf_iterations"]
        )
        if username:
            init_db()
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE users SET envelope = ?, updated_at = ? WHERE username = ?",
                    (json.dumps(envelope), time.time(), username)
                )
                conn.commit()
        else:
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            write_envelope_atomically(vault_path, envelope, auto_backup)

    def _send_json(self, data, status=200, origin=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._apply_security_headers(origin)
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_OPTIONS(self):
        valid, origin = self._validate_origin_and_host()
        if not valid:
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._apply_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden: cross-origin preflight rejected"}).encode("utf-8"))
            return

        self.send_response(200)
        self._apply_security_headers(origin)
        self.end_headers()

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        valid, origin = self._validate_origin_and_host()
        if not valid:
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._apply_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden: cross-origin request rejected"}).encode("utf-8"))
            return

        url = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(url.query)

        # Au1Send Zero-Knowledge Fetch
        if url.path.startswith("/api/send/"):
            send_id = url.path[len("/api/send/"):]
            entry = ephemeral_sends.get(send_id)
            if not entry:
                self._send_json({"error": "Secure link not found or already deleted"}, 404, origin)
                return
            if time.time() > entry["expires_at"] or entry["views_left"] <= 0:
                ephemeral_sends.pop(send_id, None)
                self._send_json({"error": "This secure link has expired or reached maximum views"}, 410, origin)
                return

            entry["views_left"] -= 1
            ct = entry["ciphertext"]
            if entry["views_left"] <= 0:
                ephemeral_sends.pop(send_id, None)

            self._send_json({
                "success": True,
                "ciphertext": ct,
                "views_left": entry.get("views_left", 0)
            }, 200, origin)
            return

        elif url.path.startswith("/send/"):
            # Serve native zero-knowledge decryption viewer page
            send_viewer_html = '''<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Au1Send - Secure Decrypted Item</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  body { background: #090a0f; color: #f4f4f5; display: flex; align-items: center; justify-content: center; min-height: 100vh; padding: 20px; }
  .card { background: #11131c; border: 1px solid #1e2638; border-radius: 12px; padding: 28px; max-width: 440px; width: 100%; box-shadow: 0 16px 40px rgba(0,0,0,0.5); }
  .brand { display: flex; align-items: center; gap: 8px; font-weight: 800; font-size: 15px; margin-bottom: 20px; }
  .box { background: #08090d; border: 1px solid #272833; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 13px; color: #38bdf8; word-break: break-all; margin: 16px 0; user-select: all; }
  .btn { display: block; width: 100%; padding: 10px; background: #3b82f6; border: none; color: #fff; border-radius: 6px; font-weight: 700; font-size: 13px; cursor: pointer; text-align: center; }
  .meta { font-size: 11px; color: #71717a; text-align: center; margin-top: 14px; line-height: 1.4; }
  .err { color: #f87171; font-size: 13px; text-align: center; line-height: 1.5; }
</style>
</head>
<body>
  <div class="card">
    <div class="brand">
      <svg width="20" height="20" viewBox="0 0 32 32" fill="none">
        <path d="M7.5 24.5L15 7.5" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round"/>
        <path d="M15 7.5V24.5" stroke="#FFFFFF" stroke-width="2.6" stroke-linecap="round"/>
        <path d="M15 7.5H19.5C22 7.5 24 9.5 24 12C24 14.5 22 16.5 19.5 16.5H15" stroke="#3B82F6" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/>
        <path d="M11 17.5H15" stroke="#FFFFFF" stroke-width="2.2" stroke-linecap="round"/>
      </svg>
      <span><span style="color:#3B82F6;">Au1</span>Send</span>
    </div>

    <div id="loading" style="text-align: center; color: #94a3b8; font-size: 13px;">Decrypting zero-knowledge payload...</div>
    <div id="contentBox" style="display: none;">
      <p style="font-size: 12.5px; color: #cbd5e1; font-weight: 600;">Secure Shared Content:</p>
      <div class="box" id="secretText"></div>
      <button class="btn" id="btnCopy" onclick="copySecret()">Copy to Clipboard</button>
      <p class="meta"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-1px; margin-right:4px;"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>End-to-end encrypted in your browser using AES-256-GCM. The server never sees the plaintext or the decryption key.</p>
    </div>
    <div id="errorBox" class="err" style="display: none;"></div>
  </div>

  <script>
    async function decryptPayload() {
      try {
        const hash = window.location.hash.substring(1);
        const params = new URLSearchParams(hash);
        const keyB64 = params.get("key");
        const ivB64 = params.get("iv");
        if (!keyB64 || !ivB64) {
          throw new Error("Invalid or missing decryption key in link fragment (#key).");
        }

        const pathParts = window.location.pathname.split("/");
        const sendId = pathParts[pathParts.length - 1];

        const res = await fetch("/api/send/" + sendId);
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to fetch secure item");

        // Native WebCrypto AES-GCM Decryption
        const rawKey = Uint8Array.from(atob(keyB64), c => c.charCodeAt(0));
        const iv = Uint8Array.from(atob(ivB64), c => c.charCodeAt(0));
        const ct = Uint8Array.from(atob(data.ciphertext), c => c.charCodeAt(0));

        const cryptoKey = await window.crypto.subtle.importKey(
          "raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]
        );
        const ptBuffer = await window.crypto.subtle.decrypt(
          { name: "AES-GCM", iv: iv }, cryptoKey, ct
        );
        const ptText = new TextDecoder().decode(ptBuffer);

        document.getElementById("loading").style.display = "none";
        document.getElementById("secretText").textContent = ptText;
        document.getElementById("contentBox").style.display = "block";
      } catch (err) {
        document.getElementById("loading").style.display = "none";
        document.getElementById("errorBox").textContent = err.message;
        document.getElementById("errorBox").style.display = "block";
      }
    }

    function copySecret() {
      const text = document.getElementById("secretText").textContent;
      navigator.clipboard.writeText(text);
      const btn = document.getElementById("btnCopy");
      btn.textContent = "Copied to Clipboard!";
      setTimeout(() => btn.textContent = "Copy to Clipboard", 2000);
    }

    decryptPayload();
  </script>
</body>
</html>'''
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._apply_security_headers(origin)
            self.end_headers()
            self.wfile.write(send_viewer_html.encode("utf-8"))
            return

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
                  <title>Google Drive Connected - Au1Password</title>
                  <style>
                    body {{ font-family: system-ui, sans-serif; background: #181825; color: #cdd6f4; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }}
                    .card {{ background: #1e1e2e; padding: 32px; border-radius: 12px; border: 1px solid #313244; text-align: center; max-width: 420px; }}
                    h2 {{ color: #60a5fa; margin-bottom: 12px; }}
                    p {{ color: #a6adc8; font-size: 14px; line-height: 1.5; }}
                  </style>
                </head>
                <body>
                  <div class="card">
                    <h2>Google Drive Connected!</h2>
                    <p>Connected account: <strong>{email or 'Authorized User'}</strong></p>
                    <p>You can close this tab now and return to Au1Password.</p>
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

        elif url.path == "/api/config":
            cfg = load_config()
            tokens = load_tokens()
            token_scopes = tokens.get("scope", "").split() if tokens else []
            cfg["gdrive"]["connected"] = bool(tokens and tokens.get("access_token"))
            cfg["gdrive"]["has_drive_scope"] = any(s in ("https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file") for s in token_scopes)
            self._send_json(cfg, 200, origin)

        elif url.path == "/api/auth/me":
            sess = self._get_active_session()
            if sess.get("unlocked") and self._validate_session_token():
                self._send_json({
                    "authenticated": True,
                    "username": sess.get("username", "Default User"),
                    "item_count": len(sess["vault"].get("items", [])) if sess.get("vault") else 0
                }, 200, origin)
            else:
                self._send_json({"authenticated": False}, 200, origin)

        elif url.path == "/api/auth/2fa/status":
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized"}, 401, origin)
                return
            sess = self._get_active_session()
            username = sess.get("username")
            if not username:
                self._send_json({"error": "No user session"}, 401, origin)
                return
            init_db()
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT totp_enabled FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                enabled = bool(row and row[0])
            self._send_json({"success": True, "enabled": enabled, "username": username}, 200, origin)

        elif url.path in ("/api/auth/logout", "/api/auth/signout"):
            token = self._extract_token()
            if token in active_sessions:
                del active_sessions[token]
            if current_session.get("session_token") == token:
                current_session["unlocked"] = False
                current_session["derived_key"] = None
                current_session["vault"] = None
                current_session["session_token"] = None
                current_session["username"] = None
            self._send_json({"success": True, "message": "Signed out successfully"}, 200, origin)

        elif url.path == "/api/vault/status":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            tokens = load_tokens()
            token_scopes = tokens.get("scope", "").split() if tokens else []
            exists = vault_path.exists()
            sess = self._get_active_session()

            # Check multi-user accounts
            init_db()
            user_count = 0
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT count(*) FROM users")
                    user_count = c.fetchone()[0]
            except Exception:
                pass

            status = {
                "exists": exists or (user_count > 0),
                "user_count": user_count,
                "file_path": str(vault_path),
                "unlocked": bool(sess.get("unlocked")),
                "username": sess.get("username"),
                "gdrive_connected": bool(tokens and tokens.get("access_token")),
                "gdrive_email": cfg["gdrive"].get("account_email"),
                "has_drive_scope": any(s in ("https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/drive.file") for s in token_scopes),
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
            elif sess.get("vault"):
                status["item_count"] = len(sess["vault"].get("items", []))
            if sess.get("unlocked") and origin.startswith("chrome-extension://"):
                status["session_token"] = sess.get("session_token")
            self._send_json(status, 200, origin)

        elif url.path == "/api/vault/items":
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized: valid session token required"}, 401, origin)
                return
            sess = self._get_active_session()
            if not sess.get("unlocked"):
                self._send_json({"error": "Vault is locked"}, 401, origin)
                return
            self._send_json({
                "username": sess.get("username"),
                "items": sess["vault"].get("items", []),
                "folders": sess["vault"].get("folders", [])
            }, 200, origin)

        elif url.path == "/api/gdrive/status":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            tokens = load_tokens()
            connected = bool(tokens and tokens.get("access_token"))
            res = {
                "connected": connected,
                "email": cfg["gdrive"].get("account_email"),
                "target_folder": cfg["gdrive"].get("target_folder", "appDataFolder"),
                "last_sync": cfg["gdrive"].get("last_sync"),
                "cloud_file": None,
                "local_file": {
                    "exists": vault_path.exists(),
                    "size": vault_path.stat().st_size if vault_path.exists() else 0,
                    "mtime": int(vault_path.stat().st_mtime) if vault_path.exists() else 0,
                    "mtime_str": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(vault_path.stat().st_mtime)) if vault_path.exists() else None
                }
            }
            if connected:
                try:
                    token = gdrive_get_valid_token(cfg)
                    cf = gdrive_find_vault_file(token, res["target_folder"])
                    if cf:
                        res["cloud_file"] = cf
                except Exception as e:
                    res["cloud_error"] = str(e)
            self._send_json(res, 200, origin)

        elif url.path in ("/api/sync/providers", "/api/sync/status"):
            cfg = load_config()
            sync_cfg = cfg.get("sync", {})
            tokens = load_tokens()
            gdrive_connected = bool(tokens and tokens.get("access_token"))

            def mask_token(val):
                if not val:
                    return ""
                s = str(val).strip()
                if len(s) <= 8:
                    return "••••••••"
                return s[:4] + "••••" + s[-4:]

            gh = sync_cfg.get("github", {}).copy()
            gh_token_clean = gh.get("token", "")
            gh["has_token"] = bool(gh_token_clean)
            gh["token"] = mask_token(gh_token_clean)

            gl = sync_cfg.get("gitlab", {}).copy()
            gl_token_clean = gl.get("token", "")
            gl["has_token"] = bool(gl_token_clean)
            gl["token"] = mask_token(gl_token_clean)

            sh = sync_cfg.get("safehost", {}).copy()
            sh_token_clean = sh.get("auth_token", "")
            sh["has_token"] = bool(sh_token_clean)
            sh["auth_token"] = mask_token(sh_token_clean)

            self._send_json({
                "active_provider": sync_cfg.get("active_provider", "gdrive"),
                "sync_mode": sync_cfg.get("sync_mode", "auto"),
                "conflict_policy": sync_cfg.get("conflict_policy", "prompt"),
                "providers": {
                    "gdrive": {
                        "name": "Google Drive",
                        "enabled": cfg.get("gdrive", {}).get("enabled", True),
                        "connected": gdrive_connected,
                        "email": cfg.get("gdrive", {}).get("account_email"),
                        "target_folder": cfg.get("gdrive", {}).get("target_folder", "appDataFolder"),
                        "last_sync": cfg.get("gdrive", {}).get("last_sync")
                    },
                    "github": {
                        "name": "GitHub (Repo / Gist)",
                        "enabled": gh.get("enabled", False),
                        "connected": bool(gh_token_clean and (gh.get("repo") or gh.get("gist_id"))),
                        "target_type": gh.get("target_type", "repo"),
                        "repo": gh.get("repo", ""),
                        "branch": gh.get("branch", "main"),
                        "gist_id": gh.get("gist_id", ""),
                        "last_sync": gh.get("last_sync"),
                        "has_token": bool(gh_token_clean),
                        "token": mask_token(gh_token_clean)
                    },
                    "gitlab": {
                        "name": "GitLab",
                        "enabled": gl.get("enabled", False),
                        "connected": bool(gl_token_clean and gl.get("project_id")),
                        "server_url": gl.get("server_url", "https://gitlab.com"),
                        "project_id": gl.get("project_id", ""),
                        "branch": gl.get("branch", "main"),
                        "last_sync": gl.get("last_sync"),
                        "has_token": bool(gl_token_clean),
                        "token": mask_token(gl_token_clean)
                    },
                    "safehost": {
                        "name": "SafeHost (WebDAV / HTTPS)",
                        "enabled": sh.get("enabled", False),
                        "connected": bool(sh.get("endpoint_url")),
                        "endpoint_url": sh.get("endpoint_url", ""),
                        "auth_type": sh.get("auth_type", "bearer"),
                        "last_sync": sh.get("last_sync"),
                        "has_token": bool(sh_token_clean),
                        "auth_token": mask_token(sh_token_clean)
                    }
                }
            }, 200, origin)

        elif url.path == "/api/system/network":
            local_ip = get_local_ip()
            self._send_json({
                "local_ip": local_ip,
                "port": 8765,
                "lan_url": f"http://{local_ip}:8765"
            }, 200, origin)

        elif url.path == "/api/vault/export":
            if not current_session["unlocked"]:
                self._send_json({"error": "Vault is locked"}, 401, origin)
                return
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized: valid session token required"}, 401, origin)
                return
            format_type = params.get("format", ["json"])[0]
            if format_type == "encrypted":
                cfg = load_config()
                vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
                if not vault_path.exists():
                    self._send_json({"error": "No vault file exists"}, 404)
                    return
                with open(vault_path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", 'attachment; filename="au1password-backup.enc"')
                self.end_headers()
                self.wfile.write(data)
            else:
                export_data = {
                    "generator": "Au1Password Pro",
                    "exported_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "items": current_session["vault"].get("items", [])
                }
                export_bytes = json.dumps(export_data, indent=2).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="au1password-export.json"')
                self.end_headers()
                self.wfile.write(export_bytes)

        elif url.path in ("/favicon.svg", "/favicon.png", "/favicon.ico", "/apple-touch-icon.png"):
            file_name = url.path.lstrip("/")
            file_path = APP_DIR / file_name
            if not file_path.exists():
                file_path = APP_DIR / "favicon.svg"
            if file_path.exists():
                with open(file_path, "rb") as f:
                    content = f.read()
                content_type = "image/svg+xml"
                if file_name.endswith(".png"):
                    content_type = "image/png"
                elif file_name.endswith(".ico"):
                    content_type = "image/x-icon"
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "public, max-age=86400")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()


        elif url.path == "/" or url.path == "/index.html":
            html_path = APP_DIR / "index.html"
            with open(html_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._apply_security_headers(origin)
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        valid, origin = self._validate_origin_and_host()
        if not valid:
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._apply_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Forbidden: cross-origin request rejected"}).encode("utf-8"))
            return

        url = urllib.parse.urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))

        # DoS Protection: Maximum request body size limit (10MB)
        MAX_BODY_SIZE = 10 * 1024 * 1024
        if content_len > MAX_BODY_SIZE:
            self.send_response(413)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._apply_security_headers()
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Payload Too Large: maximum allowed body size is 10MB"}).encode("utf-8"))
            return

        body = json.loads(self.rfile.read(content_len).decode("utf-8")) if content_len > 0 else {}

        if url.path == "/api/send/create":
            ciphertext = body.get("ciphertext")
            expires_secs = int(body.get("expires_secs", 86400))
            max_views = int(body.get("max_views", 1))
            if not ciphertext:
                self._send_json({"error": "Missing ciphertext"}, 400, origin)
                return
            if len(ciphertext) > 100 * 1024:  # 100 KB max for ephemeral secrets
                self._send_json({"error": "Payload too large for ephemeral send (max 100KB)"}, 413, origin)
                return

            # Prune expired entries to prevent memory exhaustion DoS
            now = time.time()
            expired_keys = [k for k, v in ephemeral_sends.items() if v.get("expires_at", 0) < now or v.get("views_left", 0) <= 0]
            for k in expired_keys:
                ephemeral_sends.pop(k, None)
            if len(ephemeral_sends) >= 100:
                self._send_json({"error": "Ephemeral send capacity reached. Please try again later."}, 503, origin)
                return

            send_id = secrets.token_urlsafe(16)
            ephemeral_sends[send_id] = {
                "ciphertext": ciphertext,
                "expires_at": time.time() + expires_secs,
                "views_left": max_views,
                "created_at": time.time()
            }
            self._send_json({"success": True, "send_id": send_id}, 200, origin)
            return

        elif url.path == "/api/qr/decode":
            img_b64 = body.get("image_base64", "")
            raw_url = body.get("url", "")

            # 1. Direct URI string supplied
            if raw_url:
                try:
                    if raw_url.startswith("otpauth-migration://"):
                        accounts = parse_migration_uri(raw_url)
                        self._send_json({"success": True, "raw": raw_url, "accounts": accounts}, 200, origin)
                        return
                    elif raw_url.startswith("otpauth://"):
                        acc = parse_standard_otpauth(raw_url)
                        self._send_json({"success": True, "raw": raw_url, "accounts": [acc]}, 200, origin)
                        return
                    else:
                        self._send_json({"success": True, "raw": raw_url, "accounts": []}, 200, origin)
                        return
                except Exception as e:
                    self._send_json({"error": f"Failed to parse OTP URI: {str(e)}"}, 400, origin)
                    return

            # 2. Image payload supplied
            if not img_b64:
                self._send_json({"error": "No image or URI provided"}, 400, origin)
                return

            try:
                if "," in img_b64:
                    img_b64 = img_b64.split(",", 1)[1]
                img_data = base64.b64decode(img_b64)
                decoded_text = decode_qr_image(img_data)
                if not decoded_text:
                    self._send_json({"error": "No QR code could be detected in this image"}, 400, origin)
                    return

                accounts = []
                if decoded_text.startswith("otpauth-migration://"):
                    accounts = parse_migration_uri(decoded_text)
                elif decoded_text.startswith("otpauth://"):
                    acc = parse_standard_otpauth(decoded_text)
                    if acc:
                        accounts = [acc]

                self._send_json({
                    "success": True,
                    "text": decoded_text,
                    "accounts": accounts
                }, 200, origin)
            except Exception as e:
                self._send_json({"error": f"QR decoding failed: {str(e)}"}, 500, origin)
            return

        elif url.path == "/api/config":
            updated = save_config(body)
            self._send_json({"success": True, "config": updated}, 200, origin)

        elif url.path == "/api/gdrive/auth-url":
            cfg = load_config()
            client_id = cfg["gdrive"]["client_id"].strip()
            if not client_id:
                self._send_json({"error": "Google Client ID is not configured. Please paste it in Settings first."}, 400, origin)
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
            self._send_json({"auth_url": auth_url, "launched": launched}, 200, origin)

        elif url.path == "/api/gdrive/disconnect":
            if DEFAULT_TOKEN_PATH.exists():
                DEFAULT_TOKEN_PATH.unlink()
            cfg = load_config()
            cfg["gdrive"]["account_email"] = None
            save_config(cfg)
            self._send_json({"success": True, "message": "Google Drive disconnected"}, 200, origin)

        elif url.path == "/api/gdrive/sync":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            if not vault_path.exists():
                self._send_json({"error": "Local vault file does not exist yet. Please add an item first."}, 400, origin)
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
                }, 200, origin)
            except ValueError as ve:
                print(f"[OtterVault] Sync notice: {ve}")
                self._send_json({"error": str(ve)}, 400, origin)
            except urllib.error.HTTPError as e:
                err_body = e.read().decode("utf-8", errors="ignore")
                try:
                    err_json = json.loads(err_body)
                    msg = err_json.get("error", {}).get("message", err_body)
                except Exception:
                    msg = err_body or str(e)
                if "granted scopes" in msg.lower() or "spaces" in msg.lower():
                    msg = "Google Account needs updated permissions for My Drive. Please click 'Re-connect' in Settings to grant Drive file access."
                print(f"[Au1Password] Google Drive API Error ({e.code}): {msg}")
                self._send_json({"error": msg}, 403 if e.code == 403 else 500, origin)
            except Exception as e:
                print(f"[Au1Password] Sync Exception: {str(e)}")
                self._send_json({"error": f"Google Drive sync failed: {str(e)}"}, 500, origin)

        elif url.path == "/api/gdrive/sync-push":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            if not vault_path.exists():
                self._send_json({"error": "Local vault file does not exist yet. Please add an item first."}, 400, origin)
                return

            try:
                token = gdrive_get_valid_token(cfg)
                target_folder = cfg["gdrive"].get("target_folder", "appDataFolder")
                res_meta, action = gdrive_upload_vault(token, vault_path, target_folder)
                cfg["gdrive"]["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
                save_config(cfg)
                self._send_json({
                    "success": True,
                    "direction": "push",
                    "action": action,
                    "drive_file_id": res_meta.get("id"),
                    "timestamp": cfg["gdrive"]["last_sync"],
                    "message": f"Successfully pushed vault to Google Drive ({action})"
                }, 200, origin)
            except Exception as e:
                self._send_json({"error": f"Push failed: {str(e)}"}, 500, origin)

        elif url.path == "/api/gdrive/sync-pull":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            try:
                token = gdrive_get_valid_token(cfg)
                target_folder = cfg["gdrive"].get("target_folder", "appDataFolder")
                cloud_file = gdrive_find_vault_file(token, target_folder)
                if not cloud_file:
                    self._send_json({"error": "No vault file (au1password-vault.enc) found on Google Drive. Sync Up first."}, 404, origin)
                    return
                downloaded_envelope = gdrive_download_vault(token, cloud_file["id"], vault_path)
                cfg["gdrive"]["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
                save_config(cfg)

                unlocked_updated = False
                items_count = downloaded_envelope.get("meta", {}).get("item_count", 0)
                if current_session["unlocked"] and current_session.get("derived_key"):
                    try:
                        decrypted, _, _ = decrypt_vault(downloaded_envelope, key=current_session["derived_key"])
                        current_session["vault"] = decrypted
                        unlocked_updated = True
                        items_count = len(decrypted.get("items", []))
                    except Exception as de:
                        print(f"[Au1Password] Decryption warning after pull: {de}")

                self._send_json({
                    "success": True,
                    "direction": "pull",
                    "action": "downloaded",
                    "cloud_modified": cloud_file.get("modifiedTime"),
                    "item_count": items_count,
                    "unlocked_updated": unlocked_updated,
                    "timestamp": cfg["gdrive"]["last_sync"],
                    "message": f"Successfully pulled vault from Google Drive ({items_count} items)"
                }, 200, origin)
            except Exception as e:
                self._send_json({"error": f"Pull failed: {str(e)}"}, 500, origin)

        # ----------------------------------------------------------------------
        # MULTI-CLOUD SYNC CONTROLS: GITHUB, GITLAB, SAFEHOST, GDRIVE
        # ----------------------------------------------------------------------
        elif url.path == "/api/sync/provider/select":
            req_data = self._read_json()
            provider = req_data.get("provider", "gdrive").lower().strip()
            if provider not in ("gdrive", "github", "gitlab", "safehost"):
                self._send_json({"error": "Invalid provider. Supported: gdrive, github, gitlab, safehost"}, 400, origin)
                return
            cfg = load_config()
            if "sync" not in cfg:
                cfg["sync"] = {}
            cfg["sync"]["active_provider"] = provider
            save_config(cfg)
            self._send_json({"success": True, "active_provider": provider, "message": f"Active sync provider set to {provider}"}, 200, origin)

        elif url.path == "/api/sync/config":
            req_data = self._read_json()
            cfg = load_config()
            if "sync" not in cfg:
                cfg["sync"] = {}

            provider = req_data.get("provider")
            if provider in ("github", "gitlab", "safehost"):
                if provider not in cfg["sync"]:
                    cfg["sync"][provider] = {}
                p_cfg = req_data.get("config", {})
                for k, v in p_cfg.items():
                    if v is not None and "••••" not in str(v):
                        cfg["sync"][provider][k] = v
                if "enabled" in req_data:
                    cfg["sync"][provider]["enabled"] = bool(req_data["enabled"])

            if "active_provider" in req_data:
                cfg["sync"]["active_provider"] = req_data["active_provider"]
            if "sync_mode" in req_data:
                cfg["sync"]["sync_mode"] = req_data["sync_mode"]
            if "conflict_policy" in req_data:
                cfg["sync"]["conflict_policy"] = req_data["conflict_policy"]

            save_config(cfg)
            self._send_json({"success": True, "message": "Cloud sync settings saved successfully"}, 200, origin)

        elif url.path == "/api/sync/push":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            if not vault_path.exists():
                self._send_json({"error": "Local vault file does not exist yet. Please create an item first."}, 400, origin)
                return
            try:
                res_meta, provider_name = sync_push_active(cfg, vault_path)
                self._send_json({
                    "success": True,
                    "direction": "push",
                    "provider": provider_name,
                    "result": res_meta,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "message": f"Successfully pushed Zero-Knowledge vault to {provider_name}"
                }, 200, origin)
            except Exception as e:
                self._send_json({"error": f"Push to cloud failed: {str(e)}"}, 500, origin)

        elif url.path == "/api/sync/pull":
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            try:
                downloaded_envelope, provider_name = sync_pull_active(cfg, vault_path)
                unlocked_updated = False
                items_count = downloaded_envelope.get("meta", {}).get("item_count", 0)
                if current_session["unlocked"] and current_session.get("derived_key"):
                    try:
                        decrypted, _, _ = decrypt_vault(downloaded_envelope, key=current_session["derived_key"])
                        current_session["vault"] = decrypted
                        unlocked_updated = True
                        items_count = len(decrypted.get("items", []))
                    except Exception as de:
                        print(f"[Au1Password] Decryption notice after pull: {de}")

                self._send_json({
                    "success": True,
                    "direction": "pull",
                    "provider": provider_name,
                    "item_count": items_count,
                    "unlocked_updated": unlocked_updated,
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "message": f"Successfully pulled vault from {provider_name} ({items_count} items)"
                }, 200, origin)
            except Exception as e:
                self._send_json({"error": f"Pull from cloud failed: {str(e)}"}, 500, origin)

        elif url.path == "/api/sync/test":
            req_data = self._read_json()
            provider = req_data.get("provider", "").lower()
            token = req_data.get("token", "").strip()
            # If token is masked or omitted, pull stored token from config
            cfg = load_config()
            if not token or "••••" in token:
                token = cfg.get("sync", {}).get(provider, {}).get("token") or cfg.get("sync", {}).get(provider, {}).get("auth_token", "")

            try:
                if provider == "github":
                    info = github_test_connection(token)
                    self._send_json({"success": True, "provider": "GitHub", "message": f"Connected to GitHub as @{info.get('login')}"}, 200, origin)
                elif provider == "gitlab":
                    server_url = req_data.get("server_url") or cfg.get("sync", {}).get("gitlab", {}).get("server_url", "https://gitlab.com")
                    info = gitlab_test_connection(server_url, token)
                    self._send_json({"success": True, "provider": "GitLab", "message": f"Connected to GitLab as @{info.get('username')}"}, 200, origin)
                elif provider == "safehost":
                    endpoint_url = req_data.get("endpoint_url") or cfg.get("sync", {}).get("safehost", {}).get("endpoint_url", "")
                    if not endpoint_url:
                        raise ValueError("SafeHost endpoint URL is required")
                    self._send_json({"success": True, "provider": "SafeHost", "message": f"SafeHost endpoint ready ({endpoint_url})"}, 200, origin)
                elif provider == "gdrive":
                    g_token = gdrive_get_valid_token(cfg)
                    self._send_json({"success": True, "provider": "Google Drive", "message": f"Connected to Google Drive"}, 200, origin)
                else:
                    self._send_json({"error": f"Unknown provider: {provider}"}, 400, origin)
            except Exception as e:
                self._send_json({"error": f"Connection test failed: {str(e)}"}, 400, origin)

        elif url.path == "/api/vault/import":
            if not current_session["unlocked"]:
                self._send_json({"error": "Vault is locked. Unlock before importing."}, 401, origin)
                return
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized: valid session token required"}, 401, origin)
                return
            imported_items = body.get("items", [])
            if not isinstance(imported_items, list):
                self._send_json({"error": "Invalid items list payload"}, 400, origin)
                return

            existing_items = current_session["vault"].get("items", [])
            existing_ids = {it.get("id") for it in existing_items if it.get("id")}
            count = 0
            for item in imported_items:
                if not item.get("id") or item.get("id") in existing_ids:
                    item["id"] = str(uuid.uuid4())
                existing_items.append(item)
                existing_ids.add(item["id"])
                count += 1

            current_session["vault"]["items"] = existing_items
            current_session["vault"]["updated_at"] = int(time.time())

            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            envelope, _, _ = encrypt_vault(
                current_session["vault"],
                key=current_session["derived_key"],
                salt=current_session["salt"],
                iterations=cfg["security"]["kdf_iterations"]
            )
            write_envelope_atomically(vault_path, envelope, cfg["vault"]["auto_backup"])

            auto_synced = False
            if cfg["gdrive"]["enabled"] and load_tokens():
                try:
                    token = gdrive_get_valid_token(cfg)
                    gdrive_upload_vault(token, vault_path, cfg["gdrive"]["target_folder"])
                    cfg["gdrive"]["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    save_config(cfg)
                    auto_synced = True
                except Exception:
                    pass

            self._send_json({
                "success": True,
                "imported_count": count,
                "total_items": len(existing_items),
                "auto_synced": auto_synced,
                "message": f"Successfully imported {count} items into vault."
            })

        elif url.path in ("/api/auth/register", "/api/auth/signup"):
            username = body.get("username", "").strip()
            password = body.get("password", "")
            if not username or len(username) < 3 or len(username) > 32:
                self._send_json({"error": "Username must be between 3 and 32 characters"}, 400, origin)
                return
            if not re.match(r"^[a-zA-Z0-9_\-\.]{3,32}$", username):
                self._send_json({"error": "Username can only contain letters, numbers, hyphens, and underscores"}, 400, origin)
                return
            if not password or len(password) < 4:
                self._send_json({"error": "Password must be at least 4 characters"}, 400, origin)
                return

            init_db()
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    self._send_json({"error": f"Username '{username}' is already taken. Please sign in or choose another name."}, 409, origin)
                    return

                empty_vault = {
                    "version": 1,
                    "items": [],
                    "folders": ["Personal", "Work", "Finance", "Social"],
                    "created_at": int(time.time()),
                    "updated_at": int(time.time())
                }
                cfg = load_config()
                envelope, key, salt = encrypt_vault(
                    empty_vault,
                    password=password,
                    iterations=cfg["security"]["kdf_iterations"]
                )
                now = time.time()
                cursor.execute(
                    "INSERT INTO users (username, salt, envelope, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (username, salt, json.dumps(envelope), now, now)
                )
                conn.commit()

            session_token = secrets.token_hex(32)
            sess = {
                "username": username,
                "unlocked": True,
                "derived_key": key,
                "salt": salt,
                "vault": empty_vault,
                "session_token": session_token,
                "token_created_at": time.time(),
                "master_password": None
            }
            active_sessions[session_token] = sess
            current_session.update(sess)

            self._send_json({
                "success": True,
                "token": session_token,
                "session_token": session_token,
                "username": username,
                "items": [],
                "folders": empty_vault["folders"],
                "message": "User registered and vault created successfully"
            }, 200, origin)

        elif url.path in ("/api/auth/login", "/api/auth/signin"):
            username = body.get("username", "").strip()
            password = body.get("password", "")
            totp_code = str(body.get("totp_code", "")).strip()
            if not username or not password:
                self._send_json({"error": "Username and password are required"}, 400, origin)
                return

            init_db()
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, salt, envelope, totp_secret, totp_enabled FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()

            if not row:
                self._send_json({"error": "Invalid username or password"}, 401, origin)
                return

            username_db, salt_db, envelope_str, totp_secret, totp_enabled = row
            try:
                envelope = json.loads(envelope_str)
                decrypted, key, salt = decrypt_vault(envelope, password)
            except Exception:
                self._send_json({"error": "Invalid username or password"}, 401, origin)
                return

            # Check 2FA requirement
            if totp_enabled and totp_secret:
                if not totp_code:
                    temp_token = secrets.token_hex(32)
                    temp_2fa_sessions[temp_token] = {
                        "username": username_db,
                        "derived_key": key,
                        "salt": salt,
                        "vault": decrypted,
                        "totp_secret": totp_secret,
                        "expires_at": time.time() + 300
                    }
                    self._send_json({
                        "success": True,
                        "requires_2fa": True,
                        "temp_token": temp_token,
                        "username": username_db,
                        "message": "Two-factor authentication code required"
                    }, 200, origin)
                    return

                if not verify_totp(totp_secret, totp_code):
                    self._send_json({"error": "Invalid 2FA Authenticator code"}, 401, origin)
                    return

            session_token = secrets.token_hex(32)
            sess = {
                "username": username_db,
                "unlocked": True,
                "derived_key": key,
                "salt": salt,
                "vault": decrypted,
                "session_token": session_token,
                "token_created_at": time.time(),
                "master_password": None
            }
            active_sessions[session_token] = sess
            current_session.update(sess)

            self._send_json({
                "success": True,
                "token": session_token,
                "session_token": session_token,
                "username": username_db,
                "items": decrypted.get("items", []),
                "folders": decrypted.get("folders", [])
            }, 200, origin)

        elif url.path == "/api/auth/2fa/verify":
            temp_token = body.get("temp_token", "").strip()
            totp_code = str(body.get("totp_code", "")).strip()
            if not temp_token or not totp_code:
                self._send_json({"error": "temp_token and totp_code are required"}, 400, origin)
                return

            now = time.time()
            sess_2fa = temp_2fa_sessions.get(temp_token)
            if not sess_2fa or sess_2fa.get("expires_at", 0) < now:
                if temp_token in temp_2fa_sessions:
                    del temp_2fa_sessions[temp_token]
                self._send_json({"error": "2FA session expired. Please sign in again."}, 401, origin)
                return

            if not verify_totp(sess_2fa["totp_secret"], totp_code):
                self._send_json({"error": "Invalid 2FA Authenticator code"}, 401, origin)
                return

            # Verification success - promote to active session
            del temp_2fa_sessions[temp_token]
            session_token = secrets.token_hex(32)
            sess = {
                "username": sess_2fa["username"],
                "unlocked": True,
                "derived_key": sess_2fa["derived_key"],
                "salt": sess_2fa["salt"],
                "vault": sess_2fa["vault"],
                "session_token": session_token,
                "token_created_at": now,
                "master_password": None
            }
            active_sessions[session_token] = sess
            current_session.update(sess)

            self._send_json({
                "success": True,
                "token": session_token,
                "session_token": session_token,
                "username": sess_2fa["username"],
                "items": sess_2fa["vault"].get("items", []),
                "folders": sess_2fa["vault"].get("folders", [])
            }, 200, origin)

        elif url.path == "/api/auth/2fa/setup":
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized"}, 401, origin)
                return
            sess = self._get_active_session()
            username = sess.get("username")
            if not username:
                self._send_json({"error": "No user session"}, 401, origin)
                return

            # Generate standard Base32 secret (20 bytes = 32 base32 characters)
            secret = base64.b32encode(secrets.token_bytes(20)).decode("utf-8").replace("=", "")
            temp_2fa_setups[username] = {
                "secret": secret,
                "expires_at": time.time() + 600
            }
            otpauth_url = f"otpauth://totp/Au1Password:{urllib.parse.quote(username)}?secret={secret}&issuer=Au1Password&algorithm=SHA1&digits=6&period=30"
            self._send_json({
                "success": True,
                "secret": secret,
                "otpauth_url": otpauth_url,
                "username": username
            }, 200, origin)

        elif url.path == "/api/auth/2fa/enable":
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized"}, 401, origin)
                return
            sess = self._get_active_session()
            username = sess.get("username")
            code = str(body.get("code", "")).strip()

            setup = temp_2fa_setups.get(username)
            if not setup or setup.get("expires_at", 0) < time.time():
                self._send_json({"error": "2FA setup session expired. Please start setup again."}, 400, origin)
                return

            secret = setup["secret"]
            if not verify_totp(secret, code):
                self._send_json({"error": "Invalid verification code. Check your authenticator app."}, 400, origin)
                return

            init_db()
            now = time.time()
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE users SET totp_secret = ?, totp_enabled = 1, updated_at = ? WHERE username = ?",
                    (secret, now, username)
                )
                conn.commit()

            if username in temp_2fa_setups:
                del temp_2fa_setups[username]

            self._send_json({
                "success": True,
                "message": "Two-factor authentication enabled successfully"
            }, 200, origin)

        elif url.path == "/api/auth/2fa/disable":
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized"}, 401, origin)
                return
            sess = self._get_active_session()
            username = sess.get("username")
            code = str(body.get("code", "")).strip()

            init_db()
            with sqlite3.connect(DB_PATH) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT totp_secret, totp_enabled FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()

            if not row or not row[0]:
                self._send_json({"error": "2FA is not enabled"}, 400, origin)
                return

            secret = row[0]
            if code and not verify_totp(secret, code):
                self._send_json({"error": "Invalid 2FA code"}, 400, origin)
                return

            now = time.time()
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE users SET totp_secret = NULL, totp_enabled = 0, updated_at = ? WHERE username = ?",
                    (now, username)
                )
                conn.commit()

            self._send_json({
                "success": True,
                "message": "Two-factor authentication disabled successfully"
            }, 200, origin)

        elif url.path in ("/api/auth/logout", "/api/auth/signout"):
            token = self._extract_token()
            if token in active_sessions:
                del active_sessions[token]
            if current_session.get("session_token") == token:
                current_session["unlocked"] = False
                current_session["derived_key"] = None
                current_session["vault"] = None
                current_session["session_token"] = None
                current_session["username"] = None
            self._send_json({"success": True, "message": "Signed out successfully"}, 200, origin)

        elif url.path == "/api/vault/init":
            username = body.get("username", "").strip()
            master_pass = body.get("password")
            if username:
                # Delegate to register for named users
                init_db()
                with sqlite3.connect(DB_PATH) as conn:
                    c = conn.cursor()
                    c.execute("SELECT username FROM users WHERE username = ?", (username,))
                    if c.fetchone():
                        self._send_json({"error": f"Username '{username}' already exists"}, 409, origin)
                        return
                    empty_vault = {
                        "version": 1,
                        "items": [],
                        "folders": ["Personal", "Work", "Finance", "Social"],
                        "created_at": int(time.time()),
                        "updated_at": int(time.time())
                    }
                    cfg = load_config()
                    envelope, key, salt = encrypt_vault(empty_vault, password=master_pass, iterations=cfg["security"]["kdf_iterations"])
                    now = time.time()
                    c.execute(
                        "INSERT INTO users (username, salt, envelope, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                        (username, salt, json.dumps(envelope), now, now)
                    )
                    conn.commit()

                session_token = secrets.token_hex(32)
                sess = {
                    "username": username,
                    "unlocked": True,
                    "derived_key": key,
                    "salt": salt,
                    "vault": empty_vault,
                    "session_token": session_token,
                    "token_created_at": time.time(),
                    "master_password": None
                }
                active_sessions[session_token] = sess
                current_session.update(sess)
                self._send_json({"success": True, "token": session_token, "username": username, "message": "Vault initialized successfully"}, 200, origin)
                return

            if not master_pass:
                self._send_json({"error": "Master password is required"}, 400, origin)
                return
            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            empty_vault = {
                "version": 1,
                "items": [],
                "folders": ["Personal", "Work", "Finance", "Social"],
                "created_at": int(time.time()),
                "updated_at": int(time.time())
            }
            envelope, key, salt = encrypt_vault(empty_vault, password=master_pass, iterations=cfg["security"]["kdf_iterations"])
            write_envelope_atomically(vault_path, envelope)
            
            session_token = secrets.token_hex(32)
            sess = {
                "username": None,
                "unlocked": True,
                "derived_key": key,
                "salt": salt,
                "vault": empty_vault,
                "session_token": session_token,
                "token_created_at": time.time(),
                "master_password": None
            }
            active_sessions[session_token] = sess
            current_session.update(sess)

            self._send_json({"success": True, "token": session_token, "message": "Vault initialized successfully"}, 200, origin)

        elif url.path == "/api/vault/unlock":
            now = time.time()
            if now < unlock_rate_limiter["lockout_until"]:
                remaining = int(unlock_rate_limiter["lockout_until"] - now) + 1
                self._send_json({
                    "error": f"Too many failed unlock attempts. Rate limited for security. Retry in {remaining}s."
                }, 429, origin)
                return

            username = body.get("username", "").strip()
            master_pass = body.get("password")
            if username:
                # Delegate to multi-user login
                init_db()
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT username, salt, envelope FROM users WHERE username = ?", (username,))
                    row = cursor.fetchone()

                if not row:
                    self._send_json({"error": "Invalid username or password"}, 401, origin)
                    return

                username_db, salt_db, envelope_str = row
                try:
                    envelope = json.loads(envelope_str)
                    decrypted, key, salt = decrypt_vault(envelope, master_pass)
                    session_token = secrets.token_hex(32)
                    sess = {
                        "username": username_db,
                        "unlocked": True,
                        "derived_key": key,
                        "salt": salt,
                        "vault": decrypted,
                        "session_token": session_token,
                        "token_created_at": time.time(),
                        "master_password": None
                    }
                    active_sessions[session_token] = sess
                    current_session.update(sess)

                    self._send_json({
                        "success": True,
                        "token": session_token,
                        "username": username_db,
                        "items": decrypted.get("items", []),
                        "folders": decrypted.get("folders", [])
                    }, 200, origin)
                    return
                except Exception:
                    self._send_json({"error": "Invalid username or password"}, 401, origin)
                    return

            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            if not vault_path.exists():
                self._send_json({"error": "Vault file does not exist, run init first"}, 404, origin)
                return
            try:
                with open(vault_path, "r", encoding="utf-8") as f:
                    envelope = json.load(f)
                decrypted, key, salt = decrypt_vault(envelope, master_pass)
                
                # Reset rate limiter on success
                unlock_rate_limiter["failed_attempts"] = 0
                unlock_rate_limiter["lockout_until"] = 0.0

                session_token = secrets.token_hex(32)
                sess = {
                    "username": None,
                    "unlocked": True,
                    "derived_key": key,
                    "salt": salt,
                    "vault": decrypted,
                    "session_token": session_token,
                    "token_created_at": time.time(),
                    "master_password": None
                }
                active_sessions[session_token] = sess
                current_session.update(sess)

                self._send_json({
                    "success": True,
                    "token": session_token,
                    "items": decrypted.get("items", []),
                    "folders": decrypted.get("folders", [])
                }, 200, origin)
            except Exception:
                unlock_rate_limiter["failed_attempts"] += 1
                attempts = unlock_rate_limiter["failed_attempts"]
                if attempts >= 5:
                    penalty = min(300, 2 ** (attempts - 4) * 5)
                    unlock_rate_limiter["lockout_until"] = now + penalty
                    print(f"[Security Alert] Brute-force threshold reached ({attempts} failed attempts). Locked for {penalty}s.")
                self._send_json({"error": "Invalid master password or corrupted envelope"}, 401, origin)

        elif url.path == "/api/vault/lock":
            token = self._extract_token()
            if token in active_sessions:
                del active_sessions[token]
            current_session["unlocked"] = False
            current_session["derived_key"] = None
            current_session["salt"] = None
            current_session["vault"] = None
            current_session["session_token"] = None
            current_session["master_password"] = None
            current_session["username"] = None
            self._send_json({"success": True, "message": "Vault locked"}, 200, origin)

        elif url.path in ("/api/vault/save", "/api/vault/items"):
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized: valid session token required"}, 401, origin)
                return
            sess = self._get_active_session()
            if not sess.get("unlocked"):
                self._send_json({"error": "Vault is locked"}, 401, origin)
                return
            items = body.get("items", [])
            sess["vault"]["items"] = items
            if "folders" in body:
                sess["vault"]["folders"] = body["folders"]
            sess["vault"]["updated_at"] = int(time.time())

            try:
                self._save_session_vault(sess)
            except Exception as e:
                self._send_json({"error": f"Failed to save vault: {str(e)}"}, 500, origin)
                return

            cfg = load_config()
            sync_result = None
            if not sess.get("username") and cfg["gdrive"]["enabled"] and load_tokens():
                try:
                    vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
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

        elif url.path == "/api/vault/items/bulk-delete":
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized: valid session token required"}, 401, origin)
                return
            sess = self._get_active_session()
            if not sess.get("unlocked"):
                self._send_json({"error": "Vault is locked"}, 401, origin)
                return
            item_ids = set(body.get("item_ids", []))
            permanent = bool(body.get("permanent", False))
            if not item_ids:
                self._send_json({"error": "item_ids array is required"}, 400, origin)
                return

            vault_items = sess["vault"].get("items", [])
            affected_count = 0
            if permanent:
                before_len = len(vault_items)
                vault_items = [it for it in vault_items if it.get("id") not in item_ids]
                affected_count = before_len - len(vault_items)
            else:
                now_ts = int(time.time())
                for it in vault_items:
                    if it.get("id") in item_ids:
                        it["trashed"] = True
                        it["trashed_at"] = now_ts
                        affected_count += 1

            sess["vault"]["items"] = vault_items
            sess["vault"]["updated_at"] = int(time.time())

            try:
                self._save_session_vault(sess)
            except Exception as e:
                self._send_json({"error": f"Failed to save vault: {str(e)}"}, 500, origin)
                return

            cfg = load_config()
            sync_result = None
            if not sess.get("username") and cfg["gdrive"]["enabled"] and load_tokens():
                try:
                    vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
                    token = gdrive_get_valid_token(cfg)
                    res_meta, action = gdrive_upload_vault(token, vault_path, cfg["gdrive"]["target_folder"])
                    cfg["gdrive"]["last_sync"] = time.strftime("%Y-%m-%d %H:%M:%S")
                    save_config(cfg)
                    sync_result = "synced_to_drive"
                except Exception as ex:
                    sync_result = f"drive_error: {str(ex)}"

            self._send_json({
                "success": True,
                "deleted_count": affected_count,
                "permanent": permanent,
                "remaining_count": len(vault_items),
                "auto_sync": sync_result
            }, 200, origin)

        elif url.path == "/api/vault/items/bulk-restore":
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized: valid session token required"}, 401, origin)
                return
            sess = self._get_active_session()
            if not sess.get("unlocked"):
                self._send_json({"error": "Vault is locked"}, 401, origin)
                return
            item_ids = set(body.get("item_ids", []))
            if not item_ids:
                self._send_json({"error": "item_ids array is required"}, 400, origin)
                return

            vault_items = sess["vault"].get("items", [])
            restored_count = 0
            for it in vault_items:
                if it.get("id") in item_ids:
                    it["trashed"] = False
                    it.pop("trashed_at", None)
                    restored_count += 1

            sess["vault"]["items"] = vault_items
            sess["vault"]["updated_at"] = int(time.time())

            try:
                self._save_session_vault(sess)
            except Exception as e:
                self._send_json({"error": f"Failed to save vault: {str(e)}"}, 500, origin)
                return

            self._send_json({
                "success": True,
                "restored_count": restored_count,
                "total_items": len(vault_items)
            }, 200, origin)

            self._send_json({
                "success": True,
                "restored_count": restored_count,
                "total_items": len(vault_items)
            }, 200, origin)

        elif url.path == "/api/vault/change-password":
            if not current_session["unlocked"]:
                self._send_json({"error": "Vault is locked"}, 401, origin)
                return
            if not self._validate_session_token():
                self._send_json({"error": "Unauthorized: valid session token required"}, 401, origin)
                return
            current_pass = body.get("current_password")
            new_pass = body.get("new_password")
            if not new_pass:
                self._send_json({"error": "New password cannot be empty"}, 400, origin)
                return

            cfg = load_config()
            vault_path = Path(os.path.expanduser(cfg["vault"]["file_path"]))
            # Verify current password by test-decrypting the existing on-disk envelope
            try:
                with open(vault_path, "r", encoding="utf-8") as f:
                    disk_env = json.load(f)
                decrypt_vault(disk_env, current_pass)
            except Exception:
                self._send_json({"error": "Current password does not match"}, 400, origin)
                return

            envelope, new_key, new_salt = encrypt_vault(
                current_session["vault"],
                password=new_pass,
                iterations=cfg["security"]["kdf_iterations"]
            )
            write_envelope_atomically(vault_path, envelope, True)
            current_session["derived_key"] = new_key
            current_session["salt"] = new_salt
            current_session["master_password"] = None
            self._send_json({"success": True, "message": "Master password changed and vault re-encrypted"}, 200, origin)

        else:
            self.send_response(404)
            self.end_headers()

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

def run_server(port=DEFAULT_PORT, host=DEFAULT_HOST):
    HTTPServer.allow_reuse_address = True
    server = HTTPServer((host, port), Au1RequestHandler)
    print(f"[Au1Password] Live server running on http://{host}:{port}")
    server.serve_forever()

def launch_gtk_window(port=8765):
    import gi
    gi.require_version("Gtk", "3.0")
    gi.require_version("WebKit2", "4.1")
    from gi.repository import Gtk, WebKit2

    win = Gtk.Window(title="Au1Password - Linux Personal Vault")
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
    port = int(os.environ.get("PORT", "8765"))
    host = os.environ.get("HOST", DEFAULT_HOST)
    server_thread = threading.Thread(target=run_server, args=(port, host), daemon=True)
    server_thread.start()
    time.sleep(0.5)

    if "--headless" in sys.argv or "--server" in sys.argv or os.environ.get("HEADLESS") == "1":
        print(f"Server running at http://{host}:{port}. Press Ctrl+C to stop.")
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
            print(f"[Au1Password] GTK window error: {e}")
            import webbrowser
            webbrowser.open(f"http://127.0.0.1:{port}")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
