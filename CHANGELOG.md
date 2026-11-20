# Changelog

All notable changes to the Ghost-Tag project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.0.6] - 2026-11-20

### Added
- **AST and Build Integrity Test Suite**: Dedicated automated test (`src/__tests__/webSyntaxAndBuild.test.ts`) validating `web/app.js` syntax, module parsing, and Vite production bundle generation in CI.
- **Atomic Dependency Patching**: Secure atomic temporary file staging and descriptor replacement in `scripts/patch_dependencies.js` preventing TOCTOU file system race conditions.
- **Strict Execution-Time Keystore Enforcement**: Gradle task graph interceptor in `android/app/build.gradle` ensuring `:app:assembleRelease` and `:app:bundleRelease` fail immediately without production keystore credentials while preventing debug keystore leakage into release channels.

### Changed
- **CI / CD Signing Flow**: Android CI workflow (`.github/workflows/android-build.yml`) decoupled into distinct release (when secrets exist) and debug smoke test (when secrets absent) paths.
- **Dynamic APK Signer Verification**: Release workflow (`.github/workflows/release.yml`) dynamically discovers Android SDK `apksigner` to verify release APK signatures and rejects Android debug keys.
- **CodeQL Matrix**: Streamlined CodeQL configuration in `.github/workflows/codeql.yml` targeting `javascript-typescript`.

### Fixed
- **Web Client Syntax Error (CodeQL Alert #6)**: Removed orphaned `catch` block in `web/app.js:1168` restoring clean JavaScript AST parsing and zero-error web runtime execution.
- **Input Validation & Trivial Conditional (CodeQL Warning #5)**: Replaced redundant condition in `src/operations/writeOperation.ts:73` with explicit type narrowing (`typeof === 'string'` and `Uint8Array`), rejecting empty payloads.
- **DOM Cross-Site Scripting (CodeQL Alert #60)**: Refactored `renderScanHistory` in `web/app.js:818` to use safe DOM node construction (`document.createElement`, `textContent`) instead of untrusted HTML string concatenation.
- **Incomplete Regex Meta-Character Sanitization (CodeQL Alert #61)**: Updated `tests/scan-unused.cjs:141` with complete regular expression special character escaping `/[.*+?^${}()|[\]\\]/g`.
- **Unused Variable in Web Client (CodeQL Alert #62)**: Cleaned unused map key loop binding in `web/app.js:506`.
- **Polynomial Regular Expression ReDoS (CodeQL Alert #1)**: Replaced unanchored regex on account IDs in `src/cloud/supabaseClient.ts:63` with strict RFC 4122 UUID validation.
- **Insecure Randomness (CodeQL Alerts #2 & #3)**: Replaced `Math.random()` with WebCrypto CSPRNG `crypto.getRandomValues()` in `web/supabase.js:234` and `web/supabase.js:266`.

### Security
- **Zero Open CodeQL Alerts**: Remediated all open CodeQL alerts (#1, #2, #3, #4, #5, #6, #60, #61, #62, and informational alerts #7–#57) across the entire codebase.
- **Zero Open Dependabot Alerts**: Resolved high-severity DoS in `minimatch` (`GHSA-7r86-5chv-c4rg`) via scoped npm override to `minimatch@^11.0.9`, and formally evaluated and dismissed withdrawn advisory in `deepmerge` as tolerable risk.
- **Zero Secret Exposure**: Verified complete absence of hardcoded keys, credentials, or private certificates across tracked source and history.

### Dependencies
- Upgraded `minimatch` in `@typescript-eslint/typescript-estree` to `^11.0.9`.
- Verified `npm audit` reports 0 vulnerabilities.

### Removed
- Removed dead imports, unreferenced bindings, and obsolete constants across `src/`, `web/`, and `desktop/`.
- Removed debug keystore fallback logic for production builds.

### Known limitations
- Deployment blocked without production credentials: live Supabase deployment requires `SUPABASE_ACCESS_TOKEN` and linked project ref.
- Physical NFC validation requires supported Android device and physical NTAG213/215/216 tags or ACS ACR122U USB reader for Ghost Bridge.

---

## [2.0.5] - 2026-11-16

### Added
- **Hardened Zero-Knowledge Vault Recovery**: Supabase Edge Function `recover-vault` implementing constant-time verifier verification and atomic transactional PostgreSQL rate-limiting.
- **Layered & DoS-Resistant Rate Limiting**: Enforced limits across account (25 failed/15m), user (20 failed/15m), and hashed IP (100 failed/15m) thresholds; counts only failed attempts (`success = false`) to prevent malicious lockout of legitimate users.
- **Strict RPC Permission Lockdown**: Revoked `check_and_record_recovery_attempt` execution from `anon`, `authenticated`, and `public`; granted strictly to `service_role` with search path `pg_catalog, public`.
- **Uniform Opaque Error Responses**: Uniformly returns status-coded `{ "error": "RECOVERY_FAILED" }` across all failure paths (unauthorized, invalid input, rate limited, verifier mismatch).
- **Strict CORS Origin Enforcement**: Rejects non-whitelisted cross-origin calls with HTTP 403 `RECOVERY_FAILED`.
- **Explicit RLS Denials**: Dedicated denial policies on `ghost_recovery_attempts` preventing unauthorized client manipulation; service-role only execution.
- **Passphrase Manager & Vault Crypto Bridge**: `src/vault/passphraseManager.ts` and `src/vault/crypto.ts` for strict memory zeroization and local rate limiting.
- **Real USB NFC Reader Hardware Support**: Ghost Bridge desktop daemon (`127.0.0.1:41789`) bridging ACS ACR122U readers to web browsers.
- **Native 12-Word BIP-39 Recovery Engine**: Cross-platform 12-word mnemonic recovery phrase with 4-bit SHA-256 checksum and mandatory confirmation of words 4, 8, and 11.
- **Single Master Passphrase Vault Model**: Passphrase-anchored KEK derivation (Argon2id) with double cryptographic binding (outer GCM + inner chunk GCM with deterministic AAD).

### Changed
- **Decryption Flow**: Decryption requires no Ghost account, Supabase login, or recovery phrase; user taps Decrypt Now and scans chips.
- **Security Boundaries**: Qualified client-side defense boundaries stating clearly that: "Ghost-Tag includes optional runtime environment checks, but these do not prevent reverse engineering or protect data on a compromised or unlocked device."

### Fixed
- **Anti-Takeover Defense**: Remediated account takeover risk by decoupling public account identifiers from private recovery authentication secrets and verifiers.
- **Zero-Mock Policy**: Eliminated all synthetic, mock, or placeholder NFC results across UI and production code.
- **GitHub Actions Workflows**: Bound release signing secrets to job-level environment variables, eliminating silent fallback signing.

---

## [2.0.0] - 2026-11-10

### Added
- Core Cauchy-Vandermonde Reed-Solomon erasure coding engine over GF(2^8).
- RFC 9106 Argon2id memory-hard key derivation.
- AES-256-GCM binary envelopes (54B single / 134B bulk).
- Initial Android APK build configuration with native NDK C++ security module.
- Brutalist monochrome user interface.
