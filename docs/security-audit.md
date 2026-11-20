# Ghost-Tag v2.0.6 Security Audit Report

**Date**: 2026-11-20  
**Version**: 2.0.6  
**Status**: Security Hardened & Quality Verified (Pending Hardware & Production Credential Gates)

---

## Executive Summary

Ghost-Tag v2.0.6 has undergone end-to-end security hardening, static analysis remediation, dependency vulnerability auditing, and pipeline defense enforcement across all project layers. All identified CodeQL alerts (high-severity, warnings, and informational note alerts), Dependabot security alerts, and architectural security invariants have been systematically remediated and verified.

---

## Scope & Audited Components

| Component | Files Audited | Status |
|-----------|---------------|--------|
| Cryptographic Core | `src/crypto/*.ts` | Verified (Argon2id RFC 9106, AES-256-GCM, Cauchy RS, Zeroize) |
| NFC Hardware Abstraction | `src/nfc/*.ts` | Verified (Tag identification, NDEF read/write/verify, multi-pass wipe) |
| Vault & Key Management | `src/vault/*.ts` | Verified (Two-tier KEK/DEK hierarchy, BIP-39 recovery, MMKV encrypted storage) |
| Tag Operations Engine | `src/operations/*.ts` | Verified (Single/bulk write, state transitions, capacity guards) |
| System Contracts | `src/contracts/*.ts` | Verified (Type invariants, error codes, state machines) |
| Web Client Showcase | `web/app.js`, `web/supabase.js`, `web/crypto-simulator.js` | Verified (Syntax valid, AST verified, zero console errors, XSS mitigated) |
| Desktop Hardware Bridge | `desktop/src/apdu.js` | Verified (Clean APDU encapsulation, zero dead code) |
| Supabase Cloud Sync | `supabase/migrations/*`, `supabase/functions/recover-vault/*` | Verified (14 cryptographic and isolation invariants satisfied) |
| CI/CD Pipeline & Tooling | `.github/workflows/*.yml`, `.github/dependabot.yml` | Hardened (No debug keystore fallback, apksigner verification, audit gates) |

---

## CodeQL Alerts Triage & Resolution

### High-Severity Findings

1. **Alert #1: Polynomial Regular Expression on Uncontrolled Data (HIGH)**
   - **Location**: `src/cloud/supabaseClient.ts:63`
   - **Triage**: True positive. Unanchored polynomial regex on account identifiers could be exploited for ReDoS.
   - **Resolution**: Replaced regex with strict, linear-time RFC 4122 Variant 1 UUID validation (`/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i`).

2. **Alert #2: Insecure Randomness (HIGH)**
   - **Location**: `web/supabase.js:234`
   - **Triage**: True positive. `Math.random()` used in cryptographic account / identifier derivation paths.
   - **Resolution**: Replaced with CSPRNG `crypto.getRandomValues(new Uint8Array(16))`.

3. **Alert #3: Insecure Randomness (HIGH)**
   - **Location**: `web/supabase.js:266`
   - **Triage**: True positive. `Math.random()` used for salt generation in recovery mock fallback.
   - **Resolution**: Replaced with CSPRNG `crypto.getRandomValues(new Uint8Array(32))`.

4. **Alert #4: Potential File System Race Condition (HIGH)**
   - **Location**: `scripts/patch_dependencies.js:14`
   - **Triage**: True positive. Non-atomic file read-modify-write created a potential TOCTOU race condition in dependency patching.
   - **Resolution**: Implemented atomic file replacement via unique temporary file (`${targetFile}.${Date.now()}.${pid}.tmp`) followed by atomic rename (`fs.renameSync`).

### Quality & Correctness Warnings

5. **Alert #5: Useless Conditional (WARNING)**
   - **Location**: `src/operations/writeOperation.ts:73`
   - **Triage**: True positive. Redundant null check alongside type narrowing triggered `js/trivial-conditional`.
   - **Resolution**: Refactored input validation to explicit type checks (`typeof === 'string'` and `instanceof Uint8Array`). Throws `GhostTagErrorCode.INVALID_ENVELOPE` with `'Payload cannot be empty.'` for null/undefined/non-buffer inputs, and throws `GhostTagErrorCode.PAYLOAD_TOO_LARGE` with `'Payload cannot be empty.'` for empty strings or 0-length byte arrays.
   - **Verification**: Verified via `src/__tests__/operations.test.ts`.

6. **Alert #6: Syntax Error in Web Client (HIGH/SYNTAX)**
   - **Location**: `web/app.js:1168`
   - **Triage**: True positive. Orphaned `catch` block with no matching `try` block caused a parser `SyntaxError`.
   - **Resolution**: Removed the orphaned block; verified syntax cleanly with `node --check web/app.js` and dynamic AST execution in `src/__tests__/webSyntaxAndBuild.test.ts`.

7. **Alert #60: Client-Side Cross-Site Scripting (HIGH)**
   - **Location**: `web/app.js:818`
   - **Triage**: True positive. Direct template literal string interpolation of localStorage data into `list.innerHTML` flagged by CodeQL `js/xss`.
   - **Resolution**: Replaced `innerHTML` concatenation with direct DOM node construction using `document.createElement`, safe `textContent` assignments, and programmatic event listeners. Zero user-controlled string interpolation in HTML.

8. **Alert #61: Incomplete String Escaping (WARNING)**
   - **Location**: `tests/scan-unused.cjs:141`
   - **Triage**: Warning. Regex escaping replaced only `$` without escaping backslashes or other regex meta-characters.
   - **Resolution**: Replaced with standard comprehensive regex character escaping: `name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')`.

9. **Alert #62: Unused Local Variable (NOTE)**
   - **Location**: `web/app.js:506`
   - **Triage**: True positive. `for (const [key, cb] of this.callbacks.entries())` declared `key` which was never read.
   - **Resolution**: Replaced with `for (const cb of this.callbacks.values())`.

### Note Alerts: Unused Code & Cleanliness (Alerts #7–#57)

- **Locations**: Cleaned across `src/contracts/`, `src/crypto/`, `src/nfc/`, `src/operations/`, `src/vault/`, `src/ui/screens/`, `src/__tests__/`, `desktop/src/`, and `web/`.
- **Resolution**: Audited and deleted all unused imports, variables, unused constants, and obsolete flags. Verified with automated scanner `node tests/scan-unused.cjs` with 0 findings.

---

## Dependabot Alerts Triage & Resolution

1. **Alert #9: minimatch ReDoS via Globparts Amplification (MODERATE)**
   - **CVE**: GHSA-35jh-r3h4-6jhm
   - **Status**: Fixed and verified closed on GitHub Dependabot (`minimatch@11.0.9`).
   - **Resolution**: Overridden in `package.json` and updated in `package-lock.json`.

2. **Alert #8: deepmerge Prototype Poisoning (LOW)**
   - **Advisory**: GHSA-4j97-2927-5v6q (Withdrawn by GitHub Security Lab).
   - **Status**: Dismissed via GitHub API as `tolerable_risk`.
   - **Rationale**: `"Withdrawn advisory; dependency reviewed and no exploitable production path identified."` Defense-in-depth override `"deepmerge": "^4.3.1"` retained in `package.json`.

- **Current Dependabot Status**: 0 open alerts.

---

## Security Hardening Implemented

### 1. Android Release Pipeline Hardening
- **Eliminated Debug Keystore Fallback**: Removed all automatic debug keystore generation and fallback in `.github/workflows/android-build.yml` and `android/app/build.gradle`.
- **Enforced Build Mode Integrity**: If any of the four production signing secrets (`ANDROID_KEYSTORE_BASE64`, `ANDROID_KEYSTORE_PASSWORD`, `ANDROID_KEY_ALIAS`, `ANDROID_KEY_PASSWORD`) is missing in CI, the workflow produces only a smoke-test debug artifact labeled `DEBUG BUILD`, does not create a GitHub Release, and never misidentifies debug artifacts as releases.
- **Release Workflow Signature Gate**: In `.github/workflows/release.yml`, production release builds require all four secrets, dynamically locate `apksigner`, run `apksigner verify --verbose`, and actively grep certificates to reject any build signed by `CN=Android Debug`.

### 2. GitHub Security Hardening
- **Private Vulnerability Reporting**: Enabled on GitHub repository (`https://github.com/FROSTY-MUG/Ghost-Tag/security`).
- **Security Policy (`SECURITY.md`)**: Configured with private reporting instructions, 72-hour acknowledgement expectations, explicit boundaries, prohibition of secrets in reports, threat model matrix, and cryptographic invariants.
- **Automated Scanning Configurations**:
  - `.github/dependabot.yml`: Weekly Monday scans, grouped dev/react-native PRs, security ignore rules for addressed advisories.
  - `.github/workflows/codeql.yml`: Weekly scheduled and on-push scanning with `+security-and-quality` ruleset for JavaScript and TypeScript.

### 3. Supabase Cloud Sync & Recovery Security (14 Invariants)
1. **Account ID**: Enforces RFC 4122 Variant 1 UUID primary key validated via linear-time regex.
2. **Owner User ID**: Strictly `uuid not null` linked to Supabase Auth (`auth.uid() = owner_user_id`).
3. **Recovery Verifier**: 32-byte binary verifier (`bytea not null`) evaluated via `timingSafeEqual`.
4. **Recovery Salt**: 32-byte cryptographic salt (`bytea not null`) unique per account.
5. **Recovery KDF Version**: Explicit integer tracking KDF migration state (`default 1`).
6. **Encrypted Blob**: `bytea not null` storing only AES-256-GCM ciphertext envelope (never plaintext).
7. **Vault Version**: Integer tracking envelope schema version (`default 2`).
8. **Row-Level Security**: Enabled on `ghost_vaults`; owner-only access for authenticated users, explicitly denied for `anon`.
9. **Attempt Logging Table**: `ghost_recovery_attempts` with strict RLS denying all client access (`anon` and `authenticated`). Only the service-role Edge Function has access.
10. **Race-Condition Defense**: Transaction-level advisory lock (`pg_advisory_xact_lock(hashtext(account_id::text))`) serializes concurrent recovery requests per account.
11. **Layered Rate Limiting**: Sliding 15-minute window counting only failed attempts (`success = false`): max 25 per account, max 20 per user, max 100 per IP.
12. **IP Privacy**: Raw client IP is never stored; hashed with SHA-256 and platform secret `IP_HASH_SALT`.
13. **Constant-Time Verification**: `recover-vault` Edge Function utilizes `node:crypto`'s `timingSafeEqual` with a constant 32-byte dummy fallback to prevent timing-based account enumeration.
14. **Fail-Closed Execution**: Fails closed (HTTP 500) if `IP_HASH_SALT` or `SUPABASE_SERVICE_ROLE_KEY` is missing; enforces strict CORS whitelist (`frosty-mug.github.io`, localhost).

### 4. Secret Hygiene & Repository Sanitation
- **Git History & Tracked Files**: Scanned for private keys, keystores, `.env` files, passphrases, tokens, and seed words. 0 secrets present.
- **`.gitignore`**: Covers all private files, keystores (`*.keystore`, `*.jks`, `*.p12`), environment configs (`.env*`, except `.env.example`), and build outputs.
- **`.env.example`**: Committed with safe non-secret placeholders only (`SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_ANON_KEY`, `IP_HASH_SALT`).

---

## Threat Model Matrix

| Adversary Profile | Adversary Capabilities | Ghost-Tag Defensive Guarantee |
| :--- | :--- | :--- |
| **Physical Finder of Lost Tag** | Can tap, read, clone, or dump raw tag memory. | Cannot decrypt payload without user master passphrase or recovery secret. Sees only authenticated ciphertext envelope. |
| **RF Sniffer / Malicious Reader** | Can intercept raw NFC RF transactions in transit. | Sees only AES-256-GCM ciphertext, 12-byte random nonce, and 16-byte random key ID. Payloads remain confidential. |
| **Tampering / Active Modifier** | Can alter bits on the NFC tag chip or swap payloads. | Modifying ciphertext or header triggers immediate GCM authentication failure (`GCM_AUTH_FAILED`). |
| **Tag Cloner** | Can duplicate the exact byte contents of a tag to a secondary blank tag. | Ciphertext remains secure. Ghost-Tag verifies cryptographic authenticity but explicitly cannot prevent physical cloning of static data. |
| **Compromised Unlocked Phone** | Malware with root/screen capture running on active host OS. | **Non-goal**. Ghost-Tag cannot defend against a root-compromised host OS observing active process memory. |
| **Device Replacement / Loss** | User replaces their phone or deletes local vault. | Recoverable via 12-word BIP-39 recovery phrase through dedicated recovery envelope derivation. |

---

## Release-Readiness Blockers

1. **Supabase Cloud Deployment Gate**:
   - `Blocked: Supabase deployment requires SUPABASE_ACCESS_TOKEN and linked project ref.`
2. **Physical Hardware NFC Validation Gate**:
   - `Blocked: Physical NFC validation requires a supported Android device, physical NTAG213/215/216 tags, and optionally an ACS ACR122U USB reader for Ghost Bridge testing.`
3. **Official Release & Tag Policy**:
   - Release creation and git tag creation require explicit user approval.
