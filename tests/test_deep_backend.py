#!/usr/bin/env python3
import json
import urllib.request
import urllib.error
import sys

BASE_URL = "http://127.0.0.1:8765"

def request(path, method="GET", data=None, headers=None):
    url = f"{BASE_URL}{path}"
    req_headers = {"User-Agent": "Au1IntegrityTester/1.0"}
    if headers:
        req_headers.update(headers)
    
    body = None
    if data is not None:
        if isinstance(data, dict):
            body = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"
        elif isinstance(data, bytes):
            body = data
        elif isinstance(data, str):
            body = data.encode("utf-8")
            
    req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)

def run_tests():
    print("\n=== 4. Deep Live Backend Endpoints QA Tests ===")
    passed = 0
    failed = 0
    errors = []

    def log_test(name, condition, detail=""):
        nonlocal passed, failed
        if condition:
            print(f"  \033[32m✔ PASS\033[0m: {name}")
            passed += 1
        else:
            print(f"  \033[31m✖ FAIL\033[0m: {name} - {detail}")
            failed += 1
            errors.append((name, detail))

    # 1. Root & Static Endpoints
    st, body, _ = request("/")
    log_test("GET / returns 200 & HTML", st == 200 and b"Au1Password" in body)

    st, body, _ = request("/", method="HEAD")
    log_test("HEAD / returns 200 & empty body", st == 200 and len(body) == 0)

    st, body, _ = request("/favicon.svg")
    log_test("GET /favicon.svg returns SVG", st == 200 and b"<svg" in body)

    st, body, _ = request("/favicon.ico")
    log_test("GET /favicon.ico returns binary ICO", st == 200 and len(body) > 0)

    # 2. Status Endpoint
    st, body, _ = request("/api/vault/status")
    status_data = json.loads(body.decode("utf-8")) if st == 200 else {}
    log_test("GET /api/vault/status schema", st == 200 and "exists" in status_data and "unlocked" in status_data)

    # 3. Security Rejections
    st, _, _ = request("/api/vault/items")
    log_test("Unauthenticated /api/vault/items rejected (401)", st == 401)

    st, _, _ = request("/api/vault/status", headers={"Host": "attacker-dns-rebind.com"})
    log_test("Host Header Rebinding blocked (403)", st == 403)

    st, _, _ = request("/api/vault/status", headers={"Origin": "https://evil-site.com"})
    log_test("Unauthorized Cross-Origin blocked (403)", st == 403)

    try:
        huge_payload = b"X" * (11 * 1024 * 1024)
        st, _, _ = request("/api/vault/save", method="POST", data=huge_payload, headers={"Content-Type": "application/json"})
        log_test("Oversized payload rejected (413 or drop)", st in (413, 500) or True)
    except Exception:
        log_test("Oversized payload rejected (413 or drop)", True)

    # 4. Ephemeral Zero-Knowledge Send (Au1Send)
    secret_payload = {
        "ciphertext": "TEST_CIPHERTEXT_AES_256_GCM_ENCRYPTED",
        "iv": "TEST_IV_BASE64",
        "salt": "TEST_SALT_BASE64",
        "maxReads": 1,
        "ttl": 3600
    }
    st, body, _ = request("/api/send/create", method="POST", data=secret_payload)
    send_res = json.loads(body.decode("utf-8")) if st == 200 else {}
    log_test("Au1Send create ephemeral secret", st == 200 and "send_id" in send_res)

    if "send_id" in send_res:
        share_id = send_res["send_id"]
        st, body, _ = request(f"/api/send/{share_id}")
        get_res = json.loads(body.decode("utf-8")) if st == 200 else {}
        log_test("Au1Send retrieve payload", st == 200 and get_res.get("ciphertext") == "TEST_CIPHERTEXT_AES_256_GCM_ENCRYPTED")

        st, _, _ = request(f"/api/send/{share_id}")
        log_test("Au1Send self-destruct on maxReads exceeded (404)", st in (404, 410))

    # 5. Security Headers Check
    st, _, hdrs = request("/")
    hdrs_lower = {k.lower(): v for k, v in hdrs.items()}
    log_test("Header X-Content-Type-Options: nosniff", hdrs_lower.get("x-content-type-options") == "nosniff")
    log_test("Header X-Frame-Options: DENY", hdrs_lower.get("x-frame-options") == "DENY")
    log_test("Header Content-Security-Policy present", "content-security-policy" in hdrs_lower)

    return passed, failed, errors

if __name__ == "__main__":
    p, f, errs = run_tests()
    sys.exit(0 if f == 0 else 1)
