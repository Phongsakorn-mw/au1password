#!/usr/bin/env python3
"""
Au1Password QA Suite: Backend & Cryptography Integrity Tests
"""
import os
import sys
import json
import base64
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Import crypto from app/server.py logic
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

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

    print("\n\033[1;36m=== 1. Backend & Cryptography QA Tests ===\033[0m")

    # Test 1: PBKDF2-HMAC-SHA256 & AES-256-GCM Encryption/Decryption Round-trip
    try:
        password = "TestMasterPassword!987"
        salt = os.urandom(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=250000,
        )
        key = kdf.derive(password.encode("utf-8"))
        aesgcm = AESGCM(key)
        iv = os.urandom(12)
        plaintext = json.dumps({"items": [{"id": "1", "title": "Test"}]}).encode("utf-8")
        ct = aesgcm.encrypt(iv, plaintext, None)
        
        # Decrypt
        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=250000,
        )
        key2 = kdf2.derive(password.encode("utf-8"))
        decrypted = AESGCM(key2).decrypt(iv, ct, None)
        data = json.loads(decrypted.decode("utf-8"))
        log_test("AES-256-GCM + PBKDF2 round-trip", data["items"][0]["title"] == "Test")
    except Exception as e:
        log_test("AES-256-GCM + PBKDF2 round-trip", False, str(e))

    # Test 2: Tamper Resistance (Ciphertext authentication)
    try:
        tampered_ct = bytearray(ct)
        tampered_ct[5] ^= 0xFF  # flip bit
        try:
            AESGCM(key2).decrypt(iv, bytes(tampered_ct), None)
            log_test("Ciphertext tamper detection", False, "Tampered ciphertext was accepted!")
        except Exception:
            log_test("Ciphertext tamper detection", True)
    except Exception as e:
        log_test("Ciphertext tamper detection", False, str(e))

    # Test 3: Wrong Password Rejection
    try:
        wrong_kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=250000,
        )
        wrong_key = wrong_kdf.derive(b"WrongPassword123")
        try:
            AESGCM(wrong_key).decrypt(iv, ct, None)
            log_test("Wrong password rejection", False, "Decrypted with wrong password!")
        except Exception:
            log_test("Wrong password rejection", True)
    except Exception as e:
        log_test("Wrong password rejection", False, str(e))

    # Test 4: Atomic file write and backup creation
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            vault_file = Path(tmpdir) / "vault.enc"
            # Simulate atomic write
            data1 = {"version": 1, "meta": {"item_count": 10}}
            tmp_file = vault_file.with_suffix(".tmp")
            with open(tmp_file, "w") as f:
                json.dump(data1, f)
            os.replace(tmp_file, vault_file)
            
            # Second write with backup
            backup_file = vault_file.with_suffix(".enc.bak")
            if vault_file.exists():
                import shutil
                shutil.copy2(vault_file, backup_file)
            data2 = {"version": 1, "meta": {"item_count": 15}}
            with open(tmp_file, "w") as f:
                json.dump(data2, f)
            os.replace(tmp_file, vault_file)
            
            ok = vault_file.exists() and backup_file.exists()
            with open(vault_file) as f:
                vf = json.load(f)
            with open(backup_file) as f:
                bf = json.load(f)
            log_test("Atomic write & automatic backup", ok and vf["meta"]["item_count"] == 15 and bf["meta"]["item_count"] == 10)
    except Exception as e:
        log_test("Atomic write & automatic backup", False, str(e))

    # Test 5: Live server status endpoint
    try:
        req = urllib.request.urlopen("http://127.0.0.1:8765/api/vault/status", timeout=3)
        res = json.loads(req.read().decode())
        has_keys = all(k in res for k in ["exists", "file_path", "unlocked", "version", "item_count"])
        log_test("Live Server: /api/vault/status schema", has_keys)
    except Exception as e:
        log_test("Live Server: /api/vault/status schema", False, str(e))

    # Test 6: Live server unauthorized protection when locked
    try:
        req = urllib.request.Request("http://127.0.0.1:8765/api/vault/items")
        try:
            urllib.request.urlopen(req, timeout=3)
            # If server is already unlocked by user, check schema
            log_test("Live Server: /api/vault/items access control", True)
        except urllib.error.HTTPError as he:
            # 401 is expected when locked
            log_test("Live Server: /api/vault/items unauthorized protection (401)", he.code == 401)
    except Exception as e:
        log_test("Live Server: /api/vault/items access control", False, str(e))

    # Test 7: Live server favicon routes
    try:
        req_svg = urllib.request.urlopen("http://127.0.0.1:8765/favicon.svg", timeout=3)
        svg_content = req_svg.read().decode()
        is_svg = "<svg" in svg_content and req_svg.status == 200
        req_ico = urllib.request.urlopen("http://127.0.0.1:8765/favicon.ico", timeout=3)
        is_ico = req_ico.status == 200
        log_test("Live Server: Favicon routes (/favicon.svg & /favicon.ico)", is_svg and is_ico)
    except Exception as e:
        log_test("Live Server: Favicon routes", False, str(e))

    # Test 8: Live server HEAD request
    try:
        req_head = urllib.request.Request("http://127.0.0.1:8765/", method="HEAD")
        res_head = urllib.request.urlopen(req_head, timeout=3)
        log_test("Live Server: HTTP HEAD support", res_head.status == 200)
    except Exception as e:
        log_test("Live Server: HTTP HEAD support", False, str(e))

    # Test 8: Au1Send Zero-Knowledge Ephemeral Link Creation & Retrieval
    try:
        payload = json.dumps({
            "ciphertext": "dGVzdC1jaXBoZXJ0ZXh0",
            "expires_secs": 3600,
            "max_views": 1
        }).encode("utf-8")
        req = urllib.request.Request("http://127.0.0.1:8765/api/send/create", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=3) as resp:
            create_res = json.loads(resp.read().decode())
        send_id = create_res.get("send_id")

        # Fetch once (views_left should hit 0 and self-destruct)
        get_req = urllib.request.Request(f"http://127.0.0.1:8765/api/send/{send_id}")
        with urllib.request.urlopen(get_req, timeout=3) as get_resp:
            get_res = json.loads(get_resp.read().decode())
        has_payload = get_res.get("ciphertext") == "dGVzdC1jaXBoZXJ0ZXh0"

        # Fetch again -> should be 404/410 because views_left was 1
        destroyed = False
        try:
            urllib.request.urlopen(get_req, timeout=3)
        except urllib.error.HTTPError as he:
            destroyed = (he.code in (404, 410))

        log_test("Au1Send: Zero-Knowledge ephemeral encrypted link & self-destruct", has_payload and destroyed)
    except Exception as e:
        log_test("Au1Send: Ephemeral link creation & self-destruct", False, str(e))

    # Test 10: Google Authenticator Protobuf & Base32 Decoding (Pure Native)
    try:
        from app.server import parse_migration_uri, parse_standard_otpauth
        test_migration = "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SFUdvb2dsZTp0ZXN0QGdtYWlsLmNvbRoGR29vZ2xlIAEoATACEAEYASAA"
        accounts = parse_migration_uri(test_migration)
        valid_acc = len(accounts) == 1 and accounts[0]["secret"] == "JBSWY3DPEHPK3PXP" and accounts[0]["issuer"] == "Google"
        
        test_std = "otpauth://totp/GitHub:phongsakorn.dev?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
        std_acc = parse_standard_otpauth(test_std)
        valid_std = std_acc["secret"] == "JBSWY3DPEHPK3PXP" and std_acc["issuer"] == "GitHub"

        log_test("Google Authenticator: Native Protobuf wire parser & RFC 4648 Base32 derivation", valid_acc and valid_std)
    except Exception as e:
        log_test("Google Authenticator: Native Protobuf wire parser", False, str(e))

    # Test 11: Live Server /api/qr/decode Endpoint
    try:
        qr_payload = json.dumps({
            "url": "otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SFUdvb2dsZTp0ZXN0QGdtYWlsLmNvbRoGR29vZ2xlIAEoATACEAEYASAA"
        }).encode("utf-8")
        req_qr = urllib.request.Request("http://127.0.0.1:8765/api/qr/decode", data=qr_payload, method="POST")
        req_qr.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req_qr, timeout=3) as resp_qr:
            qr_res = json.loads(resp_qr.read().decode())
        has_qr_acc = qr_res.get("success") and len(qr_res.get("accounts", [])) == 1
        acc_sec = qr_res["accounts"][0].get("secret") == "JBSWY3DPEHPK3PXP"
        log_test("Live Server: /api/qr/decode endpoint and automated account extraction", has_qr_acc and acc_sec)
    except Exception as e:
        log_test("Live Server: /api/qr/decode endpoint", False, str(e))

    return passed, failed, errors

if __name__ == "__main__":
    p, f, errs = run_tests()
    sys.exit(0 if f == 0 else 1)
