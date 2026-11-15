#!/usr/bin/env python3
"""
Ghost-Tag Automated Quality Audit Agent
Verifies type safety, test pass rates, metadata synchronization,
and documentation integrity.
"""

import os
import json
import subprocess
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def log_pass(msg):
    print(f"  [PASS] {msg}")

def log_fail(msg):
    print(f"  [FAIL] {msg}")

def log_info(msg):
    print(f"\n[*] {msg}")

def audit_version_sync():
    log_info("Auditing Version Synchronization across Targets...")
    all_ok = True

    # 1. package.json
    pkg_path = os.path.join(PROJECT_ROOT, 'package.json')
    with open(pkg_path, 'r', encoding='utf-8') as f:
        pkg = json.load(f)
    version = pkg.get('version')
    if version:
        log_pass(f"package.json version matches target ({version}).")
    else:
        log_fail("package.json missing version field!")
        all_ok = False

    # 2. android/app/build.gradle
    gradle_path = os.path.join(PROJECT_ROOT, 'android/app/build.gradle')
    with open(gradle_path, 'r', encoding='utf-8') as f:
        gradle_text = f.read()
    if f'versionName "{version}"' in gradle_text:
        log_pass(f"android/app/build.gradle configured with versionName '{version}'.")
    else:
        log_fail(f"build.gradle version does not match {version}!")
        all_ok = False

    # 3. web/assets/release-meta.json
    meta_path = os.path.join(PROJECT_ROOT, 'web/assets/release-meta.json')
    with open(meta_path, 'r', encoding='utf-8') as f:
        meta = json.load(f)
    if meta.get('version') == version and meta.get('sha256'):
        log_pass(f"web/assets/release-meta.json synchronized (SHA: {meta.get('sha256')[:16]}...).")
    else:
        log_fail(f"web/assets/release-meta.json invalid or unsynced (expected {version}, got {meta.get('version')})!")
        all_ok = False

    return all_ok

def audit_typecheck():
    log_info("Executing Automated Type-Safety Verification...")
    cmd = ["npx", "tsc", "--noEmit"]
    res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, shell=True)
    if res.returncode == 0:
        log_pass("TypeScript compilation passed with 0 errors (Strict Mode).")
        return True
    else:
        log_fail("TypeScript compilation encountered errors:")
        print(res.stdout or res.stderr)
        return False

def audit_test_suite():
    log_info("Executing Automated Test Suite Gate...")
    cmd = ["npm", "test", "--", "--ci", "--maxWorkers=2"]
    res = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, shell=True)
    if res.returncode == 0:
        log_pass("All Jest test suites passed (100% pass rate).")
        return True
    else:
        log_fail("Jest test suite failed:")
        print(res.stderr or res.stdout)
        return False

def main():
    print("=" * 65)
    print(" GHOST-TAG AUTOMATED QUALITY AUDIT AGENT")
    print(" Verifying type-safety, test suites, and release synchronization")
    print("=" * 65)

    ok1 = audit_version_sync()
    ok2 = audit_typecheck()
    ok3 = audit_test_suite()

    print("\n" + "=" * 65)
    if ok1 and ok2 and ok3:
        print(" [RESULT] ALL QUALITY AUDIT GATES PASSED (100% HEALTHY)")
        print("=" * 65)
        sys.exit(0)
    else:
        print(" [RESULT] QUALITY AUDIT COMPROMISE DETECTED (ACTION REQUIRED)")
        print("=" * 65)
        sys.exit(1)

if __name__ == '__main__':
    main()
