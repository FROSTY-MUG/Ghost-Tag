# Changelog

All notable changes to **Ghost-Tag** are documented in this file. The project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - Unreleased (Staging & Hardening Pass)

> **Release Honesty Notice**: Version `2.1.0` is currently unreleased staging software on `main`. The latest published GitHub Release remains **`v2.0.6`**. Live Supabase deployment and physical NFC hardware validation remain open release gates (see [`PROJECT-STATUS.md`](PROJECT-STATUS.md)).

### Security
- **Server-Generated Recovery Salt & Two-Stage Challenge-Proof Recovery (`supabase/migrations/20261126_v210_account_security_schema.sql`)**:
  - Replaced legacy deterministic phrase-derived `recovery_salt` with server-generated 32-byte CSPRNG `recovery_salt` during `account-auth` setup.
  - Added two-stage Argon2id (`m=32768, t=3, p=2, h=32, v=0x13`) recovery key derivation and interactive `76B` HMAC challenge-response verification (`recover-vault`) gated by Cloudflare Turnstile (`verify-captcha`).
  - Locked down legacy `ghost_vaults` direct client table access (`20261125_lockdown_ghost_vaults.sql`) and restricted `user_accounts` sensitive recovery fields to service-role Edge Functions (`rlsUserAccounts`, `rlsGhostVaults`).
- **Ghost Bridge Authentication & CodeQL Remediation (PR `#34`)**:
  - Eliminated CodeQL alerts `#75`, `#76` (`js/user-controlled-bypass`), and follow-up `#78` (`js/unvalidated-dynamic-method-call`) in `desktop/src/server.js`.
  - Added server-issued 24-byte CSPRNG `sessionToken` (`WeakMap` + `crypto.timingSafeEqual`) per WebSocket connection, allowlisted `actionHandlers` `Map` (`has()` + `typeof === 'function'`), payload bounds validation (`<= 8192` byte integers), strict Ghost NDEF MIME validation, and `'desktop/**'` workflow scanning in `.github/workflows/codeql.yml`.
- **Credential & Environment Hygiene (`scripts/`, PR `#34`)**:
  - Removed hardcoded fallback signing password `'ghosttag'` and user-specific JDK path in `scripts/package_release_apk.py` (`ANDROID_KEY_ALIAS` and `ANDROID_KEYSTORE_PASSWORD` now required, fail-closed).
  - Removed developer-specific path in `scripts/generate_android_branding.py`.

### Fixed & Changed
- **Eliminated Fake/Stub UI Behavior (`src/ui/screens/*.tsx`)**:
  - Removed fabricated `setTimeout` NFC reads/writes in `ReadTagScreen.tsx` and `WriteTagScreen.tsx`, wiring honest `ghostNfcManager` support/enable checks and NTAG21x v1 capacity limits (`52B` / `404B` / `784B`).
  - Removed hardcoded sample payloads/files (`holiday.mp4`, `report.pdf`, `notes.txt`, `SAMPLE_RECOVERY_WORDS`) from `BulkVaultCreationScreen.tsx`, `ReconstructionScreen.tsx`, and `PassphraseScreen.tsx`.
  - Synchronized `SettingsScreen.tsx` Argon2id profiles (`16 / 32 / 64 MiB`) with `DEFAULT_KDF_PARAMETERS_BY_TIER`, live `checkDeviceIntegrity()` queries, and honest Supabase endpoint probes.
  - Re-bundled `android/app/src/main/assets/index.android.bundle`.
- **NTAG21x Framing Math Alignment**: Corrected documentation and fallback constants (`web/app.js`, [`FAQ.md`](FAQ.md), `docs/`) to reflect framed Type 2 limits (`NTAG213` incompatible with v2 bulk `134B` header; `NTAG215` `326B`/`333B`; `NTAG216` `706B`/`717B`).
- **iOS Xcode & Dependency Sync**: Updated `ios/GhostTag.xcodeproj/project.pbxproj` to `MARKETING_VERSION = 2.1.0` / `CURRENT_PROJECT_VERSION = 7`; merged PR `#2` (`prettier` `2.8.8 -> 3.10.1`).
- **Documentation & Governance**: Moved `docs/FAQ.md` to root [`FAQ.md`](FAQ.md) with 70 cited Q&As, removed committed `file:///` local links, documented all 11 repository folders, and published explicit deferral plans for PRs `#25`, `#21`, and `#9`.

### Verified Test Suite (`main` after PR `#34`)
- `npm test -- --ci --maxWorkers=2`: `26/26 suites`, `347/347 tests` passing (`56.06% Stmts | 46.44% Branch | 54.67% Funcs | 57.16% Lines`).
- `npx jest desktop/test/pn532_serial.test.js`: `1/1 suite`, `22/22 tests` passing (combined `369 tests`).

---

## [v2.0.6] - 2026-11-20

### Security
- **Static Analysis & CodeQL Remediation**: Resolved open CodeQL security findings cleanly across client/server code.
- **ReDoS & Path Hardening**: Replaced polynomial URL sanitization patterns with bounded linear character scanning (`sanitizeUrlInput`).
- **CI Security Workflows**: Enforced TypeCheck, Jest suite, quality audit, and security audit agents as required status checks.

---

## [2.0.5] - 2026-11-16

### Added
- **Web Companion Client**: Minimal dark companion SPA (`web/`) with Web NFC support on Chrome Android, single-tag and bulk workflows.
- **Ghost Bridge Desktop Daemon**: Local loopback bridge (`127.0.0.1:41789`) connecting USB PC/SC NFC readers to browsers.
- **BIP-39 12-Word Canonical Standard**: Established 12-word English mnemonic across platforms, keeping 24-word local backward compatibility.
- **Historical Option A Cross-Platform Reference Vectors**: Deterministic test fixtures in `test-fixtures/recovery/recoveryVectors.json`.

---

## [2.0.0] - 2026-11-10

### Added
- Core Cauchy-Vandermonde Reed-Solomon erasure coding engine over $\mathrm{GF}(2^8)$.
- RFC 9106 Argon2id memory-hard key derivation (`DEFAULT_KDF_PARAMETERS_BY_TIER`).
- AES-256-GCM binary envelopes (`GTAG`: `54B` single v1 / `134B` bulk v2).
- Android React Native client with Kotlin `FLAG_SECURE` / `AndroidKeyStore` and native C++17 NDK security core.
