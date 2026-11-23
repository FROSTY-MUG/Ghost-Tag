# Ghost-Tag Project Status

**Version**: 2.1.0 (Ghost-Tag v2.1.0 is an unreleased local staging version.)  
**Last Updated**: 2026-11-23  
**Branch**: main  
**Status**: Local Staging — PR #24 & PR #25 Unmerged; Hardware Validation & Supabase Deployment Pending  
**Authoritative Reference**: [docs/CANONICAL-SPECIFICATION.md](docs/CANONICAL-SPECIFICATION.md)


---

## Release Checklist

### Cross-Platform Cryptographic Alignment & Quality Gates

| Item | Status | Verification Detail |
|------|--------|---------------------|
| Cross-Platform Compatibility Test Suite | ✅ Passed | 59 tests in `src/__tests__/crossPlatformCryptoCompatibility.test.ts` covering 30 verification points |
| Web Argon2id RFC 9106 Engine | ✅ Implemented | Vendored standalone WASM `web/vendor/argon2.umd.min.js` via `hash-wasm` ($m=32768$ KiB, $t=3$, $p=2$, $h=32$, $v=0x13$) |
| Canonical KDF Parameter Unification | ✅ Aligned | Android, Web, and Supabase use identical single-pass domain separation and Argon2id parameters |
| Wire Format & Envelope Layout | ✅ Aligned | Canonical `RECORD_TYPE_BULK_CHUNK` (`0x10`), Little-Endian integers, 26B/74B canonical AAD |
| Golden Reference Fixtures | ✅ Generated | `scripts/generate_compatibility_fixtures.js` outputs deterministic JSON/bin vectors |
| Committed Test Suite Integrity | ✅ Passed | 15/15 test suites passed (258/258 tests passing on `main`; 265 with PR #24; 280 with local PN532 serial tests) |
| TypeScript Strict Check | ✅ Passed | 0 errors via `npx tsc --noEmit` |
| CodeQL Alert #1 (polynomial ReDoS) | ✅ Fixed | Strict RFC 4122 UUID validation in `src/cloud/supabaseClient.ts:63` |
| CodeQL Alert #2 (insecure random) | ✅ Fixed | WebCrypto CSPRNG `crypto.getRandomValues` in `web/supabase.js:234` |
| CodeQL Alert #3 (insecure random) | ✅ Fixed | WebCrypto CSPRNG `crypto.getRandomValues` in `web/supabase.js:266` |
| CodeQL Alert #4 (TOCTOU race) | ✅ Fixed | Atomic temp file write and `renameSync` in `scripts/patch_dependencies.js:14` |
| CodeQL Alert #5 (useless conditional) | ✅ Fixed | Explicit type and length checks; rejects empty payloads in `src/operations/writeOperation.ts:73` |
| CodeQL Alert #6 (web/app.js syntax) | ✅ Fixed | Removed orphaned catch block; verified via `node --check` and AST test |
| CodeQL Alert #60 (client-side XSS) | ✅ Fixed | Replaced `innerHTML` with safe DOM `createElement`/`textContent` in `web/app.js:818` |
| CodeQL Alert #61 (regex escaping) | ✅ Fixed | Replaced regex escape with comprehensive meta-character escape in `tests/scan-unused.cjs:141` |
| CodeQL Alert #62 (unused variable) | ✅ Fixed | Replaced `.entries()` with `.values()` in `web/app.js:506` |
| CodeQL Note Alerts #7–#57 (unused code) | ✅ Cleaned | Removed unused imports, variables, constants across 10 directories; verified via `scan-unused.cjs` |
| Dependabot Alert #9 (minimatch DoS) | ✅ Fixed | Overridden to `minimatch@11.0.9`; verified closed on GitHub |
| Dependabot Alert #8 (deepmerge) | ✅ Dismissed | Dismissed as tolerable risk (withdrawn advisory); defense-in-depth override in `package.json` |
| Open Security Alerts (CodeQL / Dependabot) | ✅ 0 Open | Confirmed via GitHub Security APIs |
| Android release pipeline hardening | ✅ Hardened | Removed debug keystore fallback in `android-build.yml` and `build.gradle` |
| Production APK signature verification | ✅ Verified | Dynamic `apksigner verify` gate in `.github/workflows/release.yml` |
| Supabase 14 recovery security invariants | ✅ Verified | Zero-knowledge schema, atomic rate limiting, constant-time verification |
| Secret hygiene across repo and history | ✅ Clean | Scanned and confirmed 0 secrets tracked; `.gitignore` enforced |
| Sanitized documentation committed | ✅ Tracked | `docs/security-audit.md` and `PROJECT-STATUS.md` tracked in git |
| GitHub security configuration | ✅ Enabled | Private vulnerability reporting, `SECURITY.md`, `dependabot.yml`, `codeql.yml` |

---

## Cryptographic Engine Verification

| Component | Test Coverage | Status |
|-----------|---------------|--------|
| Argon2id KDF (RFC 9106) | Unit + Integration | ✅ Verified |
| AES-256-GCM Encrypt / Decrypt | Unit + Round-trip + Fuzzing | ✅ Verified |
| Key Wrapping (KEK $\rightarrow$ DEK) | Unit + Lifecycle | ✅ Verified |
| Recovery KEK Derivation (BIP-39) | Unit (12 & 24 words) | ✅ Verified |
| Envelope v1 Format (54B) | Unit + Serialization | ✅ Verified |
| Bulk Envelope v2 Format (134B) | Unit + Chunk Headers | ✅ Verified |
| Reed-Solomon Erasure Coding (Cauchy $GF(2^8)$) | Unit + Reconstruction | ✅ Verified |
| Secure Memory Zeroization (`secureWipeBuffer`) | Unit + Buffer Inspection | ✅ Verified |
| Timing-Safe Comparison (`timingSafeEqual`) | Unit + Edge Function | ✅ Verified |

---

## NFC Hardware Abstraction Verification

| Feature | Implementation | Status |
|---------|----------------|--------|
| Tag Identification (NTAG213/215/216, Ultralight/C/EV1) | `TagInfo.ts` | ✅ Verified |
| NDEF Read / Write / Verify | `TagReader`, `TagWriter` | ✅ Verified |
| Read-Back Verification Gate | `WriteOperation` | ✅ Verified |
| Multi-Pass Overwrite & Destructive Wipe | `TagWiper` | ✅ Verified |
| ACR122U APDU Bridge | `desktop/src/apdu.js` | ✅ Verified |
| Web NFC Hardware Interaction | `web/app.js` | ✅ Verified |
| Ghost Bridge WebSocket RPC | `web/app.js` | ✅ Verified |

---

## Vault Subsystem Verification

| Feature | Implementation | Status |
|---------|----------------|--------|
| Vault Creation / Unlock / Lock Lifecycle | `VaultManager` | ✅ Verified |
| DEK Lifecycle (Create / Rotate / Revoke) | `DEKManager` | ✅ Verified |
| 12-Word BIP-39 Recovery Management | `RecoveryManager` | ✅ Verified |
| Hash-Chained Tamper-Evident Audit Log | `AuditLog` | ✅ Verified |
| Manifest HMAC Authentication | `VaultManifest` | ✅ Verified |
| AES-256 Encrypted MMKV Database | `VaultDatabase` | ✅ Verified |
| Inactivity Auto-Lock Timer (5 minutes) | `VaultSession` | ✅ Verified |

---

## Supabase Cloud Sync Verification (Zero-Knowledge)

| Feature | Implementation | Status |
|---------|----------------|--------|
| Encrypted Vault Metadata Schema | `supabase/migrations/20261115_ghost_vaults.sql` | ✅ Verified |
| Hardened Vault Recovery Edge Function | `supabase/functions/recover-vault/index.ts` | ✅ Verified |
| PostgreSQL Advisory Lock Concurrency Defense | `check_and_record_recovery_attempt` RPC | ✅ Verified |
| Layered Sliding-Window Rate Limiting | 25 per-account, 20 per-user, 100 per-IP (15 min) | ✅ Verified |
| IP Privacy via Platform Salted Hash | SHA-256(`clientIp` + `IP_HASH_SALT`) | ✅ Verified |
| Constant-Time Verifier Verification | `node:crypto` `timingSafeEqual` + dummy fallback | ✅ Verified |
| Strict Row-Level Security (RLS) | Owner-only vault access; attempts private to service-role | ✅ Verified |

---

## Verification Gates (Local & CI)

| Gate | Execution Command | Result |
|------|-------------------|--------|
| Clean Dependency Installation | `npm ci` & `npm --prefix web ci` | Passed (0 errors) |
| ESLint Code Quality Gate | `npm run lint` | Passed (0 errors) |
| Strict TypeScript Compilation | `npm run typecheck` | Passed (0 errors) |
| Automated Jest Test Suite | `npm test` (16 suites, 280 tests) | Passed (100%) |
| PN532 Serial Transport & ESP32 SPI Firmware | `desktop/src/transports/` & `desktop/firmware/` | Implemented in Source (Covered by mocked protocol tests; pending real-device hardware validation) |
| Tag Capacity Calculation & Boundary Validation | `desktop/src/apdu.js`, `desktop/test/` | Canonical NTAG213 (144B), NTAG215 (504B), NTAG216 (888B) verified |
| iOS Cryptographic Foundation | Native Swift + Clibargon2 (`ios/`) | Implemented in Source (Pending macOS build & XCTest) |
| Web Legacy Recovery Migration Flow | `web/app.js`, `web/index.html` | Completed (Explicit User Consent) |
| Cross-Platform Reference Fixtures | `test-fixtures/` (JSON & `.bin`) | Verified & Embedded in iOS |
| Dependency Vulnerability Audit | `npm audit --audit-level=moderate` | Passed (0 vulnerabilities) |
| Web Production Bundle Build | `npm --prefix web run build` | Passed (Vite dist bundle) |
| Unused Declaration Scan | `node tests/scan-unused.cjs` | Passed (0 unused items) |
| Android Bundle Generation | Metro React Native bundle | Passed (index.android.bundle) |

---

## Explicit Operational Blockers & Status Disclosures

The following items are strictly bounded and cannot proceed without external credentials or physical devices:

1. **Supabase Cloud Live Deployment**:
   > **Blocked: Supabase Cloud: Undeployed. Schema and atomic migration RPC are implemented and covered by local tests, but have not been deployed to a live Supabase project or validated against a live database.**
2. **iOS Platform Status & Validation**:
   > **Blocked: Ghost-Tag on iOS does not currently implement NFC tag writing. Its CoreNFC integration is read-only. iOS tag-writing support, if added in the future, would require separate implementation, entitlement review, compatibility testing, and physical-device validation. The cryptographic foundation is implemented in source code, but remains pending macOS build validation, XCTest validation, cross-platform fixture validation, and physical iPhone NFC validation.**
3. **Android Platform Status & Validation**:
   > **Pending Physical Hardware Execution: Android NFC is implemented in source code and unit tested, but remains pending real-device NFC validation on physical Android hardware.**
4. **Ghost Bridge PC/SC (ACR122U) Status**:
   > **Pending Physical Hardware Execution: Ghost Bridge PC/SC transport is implemented in source code, but remains pending real-reader validation with an authentic physical ACS ACR122U reader and physical NTAG tags.**
5. **Ghost Bridge PN532 Serial Transport Status**:
   > **Pending Physical Hardware Execution: PN532 serial transport and ESP32 firmware are implemented in source code and covered by mocked protocol tests. PN532 remains pending real-device validation with a physical ESP32, PN532 module, and physical NTAG tag.**
6. **Web Legacy Recovery Migration Status**:
   > **Notice: Existing Web recovery records with recovery_kdf_version = 1 are recoverable only after successful migration using the original 12-word recovery phrase. Migration must be validated end-to-end before this claim is considered production-ready. The migration flow submits the canonical phrase-derived recovery_salt alongside the Argon2id verifier with legacy PBKDF2 proof of ownership, ensuring seamless cross-device recovery.**
7. **Official GitHub Release / Tagging Policy**:
   > Per release policy, release tags and official GitHub Releases are published strictly under maintainer approval. No release tag or GitHub Release is created.
