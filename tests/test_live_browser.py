#!/usr/bin/env python3
import subprocess
import sys
from pathlib import Path

def run_tests():
    print("\n=== 5. Live Browser Engine (Chromium CDP) QA Tests ===")
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

    cdp_script = Path(__file__).parent.parent / "scratch" / "test_live_frontend_cdp.js"
    if not cdp_script.exists():
        log_test("CDP script existence", False, "Missing test_live_frontend_cdp.js")
        return passed, failed, errors

    try:
        proc = subprocess.run(
            ["node", str(cdp_script)],
            capture_output=True,
            text=True,
            timeout=25
        )
        lines = proc.stdout.splitlines()
        for line in lines:
            line_s = line.strip()
            if "✔ PASS:" in line_s:
                test_name = line_s.split("✔ PASS:")[1].strip()
                log_test(f"Browser UI: {test_name}", True)
            elif "✖ FAIL:" in line_s:
                test_name = line_s.split("✖ FAIL:")[1].strip()
                log_test(f"Browser UI: {test_name}", False, "Assertion failed in CDP session")

        if proc.returncode == 0:
            log_test("Browser Runtime: Zero console errors & exceptions", True)
        else:
            log_test("Browser Runtime: Zero console errors & exceptions", False, proc.stderr[:200])

    except Exception as e:
        log_test("Browser Automation Session", False, str(e))

    return passed, failed, errors

if __name__ == "__main__":
    p, f, errs = run_tests()
    sys.exit(0 if f == 0 else 1)
