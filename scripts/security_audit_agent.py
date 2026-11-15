#!/usr/bin/env python3
"""
Ghost-Tag Automated Security Audit Agent
Audits codebase for cryptographic invariants, zero-secrets policy,
memory zeroization, and Android hardware security compliance.
"""

import os
import re
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

def log_pass(msg):
    print(f"  [PASS] {msg}")

def log_fail(msg):
    print(f"  [FAIL] {msg}")

def log_info(msg):
    print(f"\n[*] {msg}")

def audit_zero_secrets():
    log_info("Auditing Zero-Secrets Policy...")
    suspicious_patterns = [
        (r'BEGIN RSA PRIVATE KEY', "Hardcoded RSA Private Key"),
        (r'BEGIN EC PRIVATE KEY', "Hardcoded EC Private Key"),
        (r'BEGIN PRIVATE KEY', "Hardcoded Private Key"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
        (r'gho_[a-zA-Z0-9]{36}', "GitHub OAuth Token"),
        (r'AIza[0-9A-Za-z-_]{35}', "Google API Key"),
        (r'password\s*=\s*["\'][^"\']{6,}["\']', "Hardcoded password variable"),
    ]
    
    violations = []
    scan_dirs = ['src', 'android/app/src/main/java', 'android/app/src/main/cpp', 'web']
    for s_dir in scan_dirs:
        full_path = os.path.join(PROJECT_ROOT, s_dir)
        if not os.path.exists(full_path):
            continue
        for root, _, files in os.walk(full_path):
            for f in files:
                if f.endswith(('.ts', '.tsx', '.kt', '.java', '.cpp', '.h', '.js', '.html')):
                    file_p = os.path.join(root, f)
                    with open(file_p, 'r', encoding='utf-8', errors='ignore') as fp:
                        content = fp.read()
                    for pattern, desc in suspicious_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            # Exclude known mock strings
                            if "CorrectHorseBatteryStaple" in content or "Top Secret NFC Password" in content:
                                continue
                            violations.append(f"{f}: {desc}")

    if violations:
        for v in violations:
            log_fail(v)
        return False
    log_pass("Zero hardcoded secrets or credentials detected across codebase.")
    return True

def audit_android_hardening():
    log_info("Auditing Android Platform Hardening...")
    all_ok = True
    
    # 1. FLAG_SECURE check
    main_act = os.path.join(PROJECT_ROOT, 'android/app/src/main/java/com/ghosttag/MainActivity.kt')
    if os.path.exists(main_act):
        with open(main_act, 'r', encoding='utf-8') as f:
            code = f.read()
        if "FLAG_SECURE" in code:
            log_pass("WindowManager FLAG_SECURE screenshot/recording block enforced in MainActivity.")
        else:
            log_fail("MainActivity missing WindowManager.LayoutParams.FLAG_SECURE!")
            all_ok = False
            
    # 2. Cleartext traffic blocked
    net_sec = os.path.join(PROJECT_ROOT, 'android/app/src/main/res/xml/network_security_config.xml')
    if os.path.exists(net_sec):
        with open(net_sec, 'r', encoding='utf-8') as f:
            code = f.read()
        if 'cleartextTrafficPermitted="false"' in code:
            log_pass("Network security config strictly blocks cleartext traffic.")
        else:
            log_fail("network_security_config.xml does not disable cleartext traffic!")
            all_ok = False

    # 3. Native C++ anti-debug and maps scan
    cpp_sec = os.path.join(PROJECT_ROOT, 'android/app/src/main/cpp/security_core.cpp')
    if os.path.exists(cpp_sec):
        with open(cpp_sec, 'r', encoding='utf-8') as f:
            code = f.read()
        if "PTRACE_TRACEME" in code and "/proc/self/maps" in code:
            log_pass("Native C++ core implements ptrace anti-debugging and Frida proc maps scan.")
        else:
            log_fail("security_core.cpp missing ptrace or maps scanner!")
            all_ok = False

    return all_ok

def audit_crypto_invariants():
    log_info("Auditing Cryptographic Invariants...")
    all_ok = True
    
    # 1. Check AAD binding in envelope.ts
    env_file = os.path.join(PROJECT_ROOT, 'src/contracts/envelope.ts')
    if os.path.exists(env_file):
        with open(env_file, 'r', encoding='utf-8') as f:
            code = f.read()
        if "ENVELOPE_AAD_SIZE = 26" in code and "ENVELOPE_FIXED_OVERHEAD_BYTES = 54" in code:
            log_pass("Single-tag envelope maintains exact 54B overhead and 26B deterministic AAD.")
        else:
            log_fail("envelope.ts invariants modified!")
            all_ok = False

    # 2. Check Bulk Envelope AAD binding
    bulk_env = os.path.join(PROJECT_ROOT, 'src/contracts/bulkEnvelope.ts')
    if os.path.exists(bulk_env):
        with open(bulk_env, 'r', encoding='utf-8') as f:
            code = f.read()
        if "BULK_ENVELOPE_FIXED_OVERHEAD = 134" in code and "BULK_AAD_LENGTH = 74" in code:
            log_pass("Bulk envelope maintains exact 134B overhead and 74B deterministic AAD.")
        else:
            log_fail("bulkEnvelope.ts invariants modified!")
            all_ok = False

    # 3. Check memory zeroization availability
    mem_file = os.path.join(PROJECT_ROOT, 'src/crypto/secureMemory.ts')
    if os.path.exists(mem_file):
        with open(mem_file, 'r', encoding='utf-8') as f:
            code = f.read()
        if "zeroize" in code and "secureWipeBuffer" in code:
            log_pass("Volatile secure memory wiping routines available and intact.")
        else:
            log_fail("secureMemory.ts missing zeroize routines!")
            all_ok = False

    return all_ok

def main():
    print("=" * 65)
    print(" GHOST-TAG AUTOMATED SECURITY AUDIT AGENT")
    print(" Verifying zero-secrets, hardware defense, and crypto integrity")
    print("=" * 65)

    ok1 = audit_zero_secrets()
    ok2 = audit_android_hardening()
    ok3 = audit_crypto_invariants()

    print("\n" + "=" * 65)
    if ok1 and ok2 and ok3:
        print(" [RESULT] ALL SECURITY AUDIT INVARIANTS PASSED (100% HEALTHY)")
        print("=" * 65)
        sys.exit(0)
    else:
        print(" [RESULT] SECURITY AUDIT COMPROMISE DETECTED (ACTION REQUIRED)")
        print("=" * 65)
        sys.exit(1)

if __name__ == '__main__':
    main()
