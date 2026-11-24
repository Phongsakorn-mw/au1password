#!/usr/bin/env python3
"""
QA Test Suite for Multi-User Registration, Authentication, and Isolated Vaults
"""
import json
import time
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8765"

def post_json(path, data, token=None):
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        data=json.dumps(data).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    return urllib.request.urlopen(req, timeout=5)

def get_json(path, token=None):
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{BASE_URL}{path}",
        headers=headers,
        method="GET"
    )
    return urllib.request.urlopen(req, timeout=5)

def run_tests():
    print("\n=== Multi-User & Isolated Vaults QA Tests ===")
    passed = 0
    failed = 0
    errors = []

    suffix = str(int(time.time() * 1000))[-6:]
    user_a = f"alice_{suffix}"
    pass_a = "CorrectPasswordA!123"
    user_b = f"bob_{suffix}"
    pass_b = "CorrectPasswordB!456"

    # Test 1: Register User A
    try:
        res = post_json("/api/auth/register", {"username": user_a, "password": pass_a})
        body = json.loads(res.read().decode())
        assert res.status == 200, f"Expected 200, got {res.status}"
        assert body.get("success") is True, "Registration response failed"
        assert "session_token" in body, "No session token returned"
        token_a = body["session_token"]
        print("  ✔ PASS: User registration and token issue")
        passed += 1
    except Exception as e:
        print(f"  ✖ FAIL: User registration ({e})")
        failed += 1
        errors.append(("User registration", str(e)))
        token_a = None

    # Test 2: Reject duplicate registration
    try:
        try:
            post_json("/api/auth/register", {"username": user_a, "password": "anypassword"})
            raise AssertionError("Duplicate registration should have failed with 409")
        except urllib.error.HTTPError as err:
            assert err.code == 409, f"Expected 409 for duplicate, got {err.code}"
        print("  ✔ PASS: Duplicate username registration rejection (409)")
        passed += 1
    except Exception as e:
        print(f"  ✖ FAIL: Duplicate registration rejection ({e})")
        failed += 1
        errors.append(("Duplicate registration rejection", str(e)))

    # Test 3: Register User B
    try:
        res = post_json("/api/auth/register", {"username": user_b, "password": pass_b})
        body = json.loads(res.read().decode())
        assert res.status == 200
        token_b = body["session_token"]
        print("  ✔ PASS: Independent second user registration")
        passed += 1
    except Exception as e:
        print(f"  ✖ FAIL: Independent second user registration ({e})")
        failed += 1
        errors.append(("Independent second user registration", str(e)))
        token_b = None

    # Test 4: Wrong password rejection on login
    try:
        try:
            post_json("/api/auth/login", {"username": user_a, "password": "WrongPassword"})
            raise AssertionError("Login with wrong password should fail with 401")
        except urllib.error.HTTPError as err:
            assert err.code == 401, f"Expected 401 for wrong password, got {err.code}"
        print("  ✔ PASS: Bad password login rejection (401)")
        passed += 1
    except Exception as e:
        print(f"  ✖ FAIL: Bad password login rejection ({e})")
        failed += 1
        errors.append(("Bad password login rejection", str(e)))

    # Test 5: Complete Data Isolation across User A & User B
    try:
        if token_a and token_b:
            item_a = {
                "id": f"item_a_{suffix}",
                "title": f"Secret Of Alice {suffix}",
                "username": "alice@vault.com",
                "password": "alice-secret-pass",
                "urls": ["https://alice.example.com"],
                "category": "logins",
                "notes": "Classified Alice Note",
                "created_at": time.time(),
                "updated_at": time.time()
            }
            item_b = {
                "id": f"item_b_{suffix}",
                "title": f"Secret Of Bob {suffix}",
                "username": "bob@vault.com",
                "password": "bob-secret-pass",
                "urls": ["https://bob.example.com"],
                "category": "logins",
                "notes": "Classified Bob Note",
                "created_at": time.time(),
                "updated_at": time.time()
            }

            post_json("/api/vault/items", {"items": [item_a]}, token=token_a)
            post_json("/api/vault/items", {"items": [item_b]}, token=token_b)

            # Check Alice's vault items
            res_a = get_json("/api/vault/items", token=token_a)
            items_a = json.loads(res_a.read().decode()).get("items", [])
            titles_a = [it["title"] for it in items_a]
            assert any(item_a["title"] in t for t in titles_a), "Alice's item missing from Alice vault"
            assert not any(item_b["title"] in t for t in titles_a), "Bob's item leaked into Alice vault!"

            # Check Bob's vault items
            res_b = get_json("/api/vault/items", token=token_b)
            items_b = json.loads(res_b.read().decode()).get("items", [])
            titles_b = [it["title"] for it in items_b]
            assert any(item_b["title"] in t for t in titles_b), "Bob's item missing from Bob vault"
            assert not any(item_a["title"] in t for t in titles_b), "Alice's item leaked into Bob vault!"

            print("  ✔ PASS: Complete zero-knowledge vault isolation between users")
            passed += 1
        else:
            raise RuntimeError("Missing tokens for isolation test")
    except Exception as e:
        print(f"  ✖ FAIL: Vault isolation between users ({e})")
        failed += 1
        errors.append(("Vault isolation", str(e)))

    # Test 6: Logout invalidation
    try:
        if token_a:
            post_json("/api/auth/logout", {}, token=token_a)
            # Requesting items with old token should now fail with 401
            try:
                get_json("/api/vault/items", token=token_a)
                raise AssertionError("Expected 401 after logout")
            except urllib.error.HTTPError as err:
                assert err.code == 401, f"Expected 401 after logout, got {err.code}"
            print("  ✔ PASS: Logout session token invalidation")
            passed += 1
    except Exception as e:
        print(f"  ✖ FAIL: Logout session token invalidation ({e})")
        failed += 1
        errors.append(("Logout session token invalidation", str(e)))

    return passed, failed, errors

if __name__ == "__main__":
    p, f, errs = run_tests()
    print(f"\nResult: {p} passed, {f} failed")
    if f > 0:
        exit(1)
