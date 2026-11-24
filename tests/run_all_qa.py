#!/usr/bin/env python3
"""
Au1Password Unified QA Runner & Verification Engine
"""
import sys
import time
from pathlib import Path

# Add tests directory to sys.path
sys.path.insert(0, str(Path(__file__).parent))

import socket
import subprocess
import test_backend
import test_security
import test_frontend
import test_deep_backend
import test_live_browser
import test_batch_delete
import test_multi_user

def is_port_open(host="127.0.0.1", port=8765):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False

def main():
    start_time = time.time()
    print("=" * 65)
    print("        AU1PASSWORD AUTOMATED QA & INTEGRITY SUITE        ")
    print("=" * 65)

    server_proc = None
    if not is_port_open():
        server_py = Path(__file__).resolve().parent.parent / "app" / "server.py"
        server_proc = subprocess.Popen(
            [sys.executable, str(server_py), "--headless"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        for _ in range(40):
            if is_port_open():
                break
            time.sleep(0.1)

    total_passed = 0
    total_failed = 0
    all_errors = []

    try:
        # 1. Run Backend Tests
        p1, f1, errs1 = test_backend.run_tests()
        total_passed += p1
        total_failed += f1
        all_errors.extend(errs1)

        # 2. Run Security Tests
        p2, f2, errs2 = test_security.run_tests()
        total_passed += p2
        total_failed += f2
        all_errors.extend(errs2)

        # 3. Run Frontend & Extension Tests
        p3, f3, errs3 = test_frontend.run_tests()
        total_passed += p3
        total_failed += f3
        all_errors.extend(errs3)

        # 4. Run Deep Live Backend Endpoints Tests
        p4, f4, errs4 = test_deep_backend.run_tests()
        total_passed += p4
        total_failed += f4
        all_errors.extend(errs4)

        # 5. Run Live Browser Interaction Tests
        p5, f5, errs5 = test_live_browser.run_tests()
        total_passed += p5
        total_failed += f5
        all_errors.extend(errs5)

        # 6. Run Multiple Selection & Batch Removal Tests
        p6, f6, errs6 = test_batch_delete.run_tests()
        total_passed += p6
        total_failed += f6
        all_errors.extend(errs6)

        # 7. Run Multi-User & Isolated Vaults Tests
        p7, f7, errs7 = test_multi_user.run_tests()
        total_passed += p7
        total_failed += f7
        all_errors.extend(errs7)

    finally:
        if server_proc:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=2)
            except Exception:
                server_proc.kill()

    elapsed = time.time() - start_time
    total_tests = total_passed + total_failed
    pass_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

    print("\n" + "=" * 65)
    print("                   QA AUDIT SUMMARY REPORT                ")
    print("=" * 65)
    print(f"  Total Test Cases : {total_tests}")
    print(f"  Passed           : \033[32m{total_passed}\033[0m")
    print(f"  Failed           : \033[31m{total_failed}\033[0m")
    print(f"  Pass Rate        : \033[1;32m{pass_rate:.1f}%\033[0m")
    print(f"  Execution Time   : {elapsed:.2f}s")
    print("=" * 65)

    if total_failed > 0:
        print("\n\033[1;31m✖ QA AUDIT FAILED. Remediation required for:\033[0m")
        for name, err in all_errors:
            print(f"  - {name}: {err}")
        sys.exit(1)
    else:
        print("\n\033[1;32m✔ ALL QA CHECKS PASSED PERFECTLY (100% SUCCESS)\033[0m")
        print("  Frontend, Backend, and Security integrity are verified.")
        sys.exit(0)

if __name__ == "__main__":
    main()
