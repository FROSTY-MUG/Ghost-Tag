# Ghost-Tag Release Notes — `v2.1.0` (Unreleased Staging)

> **Important Release Honesty Notice**: **`v2.1.0` is currently UNRELEASED staging software.** No `v2.1.0` Git tag, GitHub Release, or npm package has been published. The latest published GitHub Release is **`v2.0.6`** ([release page](https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.6)). See [`PROJECT-STATUS.md`](PROJECT-STATUS.md) for open release gates.

---

## 1. Key Highlights in `v2.1.0` Staging

### Zero-Knowledge v2.1.0 Cloud Recovery & RLS Lockdown (`supabase/`)
- **Server-Random CSPRNG Recovery Salt**: `account-auth` provisions a 32-byte server-random CSPRNG `recovery_salt`, pairing two-stage Argon2id RFC 9106 derivation (`m=32768 KiB, t=3, p=2, h=32, v=0x13`) with Cloudflare Turnstile gating (`verify-captcha`).
- **Interactive Challenge-Proof Protocol**: `recover-vault` issues single-use `recovery_challenges` and verifies `76B` HMAC challenge proofs with constant-time checks, uniform anti-enumeration errors, and atomic advisory-locked 15-minute rate limits (`user_accounts`, `vault_metadata`, `recovery_challenges`).
- **Legacy `ghost_vaults` Lockdown**: Direct client table read/write access to `ghost_vaults` and sensitive recovery columns is revoked; metadata status uses `ghost_vault_status` view and authenticated Edge Functions (`20261125_lockdown_ghost_vaults.sql`, `20261126_v210_account_security_schema.sql`).
- **Historical Option A Test Fixtures Retained**: Deterministic `test-fixtures/recovery/recoveryVectors.json` remains in the repo solely for unit vector parity testing; live Supabase deployment remains pending operator configuration.

### Desktop Ghost Bridge & CodeQL Security Hardening (PR `#34`)
- Fixed CodeQL High alerts `#75`, `#76` (`js/user-controlled-bypass`), and follow-up `#78` (`js/unvalidated-dynamic-method-call`) in `desktop/src/server.js` cleanly without suppression comments.
- Enforced per-connection 24-byte CSPRNG `sessionToken` (`WeakMap` + `crypto.timingSafeEqual`), immutable `actionHandlers` `Map` lookup (`has()` + `typeof === 'function'`), bounded `envelopeBytes` integer checks (`<= 8192`), strict Ghost NDEF MIME allowlisting, and `'desktop/**'` workflow analysis in `.github/workflows/codeql.yml`.

### Mobile UI & Build Script Hardening (PR `#34`)
- Replaced fabricated UI `setTimeout` tag reads/writes and hardcoded sample files/mnemonics across `src/ui/screens/*.tsx` with real `ghostNfcManager`, `checkDeviceIntegrity()`, and `DEFAULT_KDF_PARAMETERS_BY_TIER` (`16 / 32 / 64 MiB`) checks; regenerated `android/app/src/main/assets/index.android.bundle`.
- Updated `ios/GhostTag.xcodeproj/project.pbxproj` to `MARKETING_VERSION = 2.1.0` (`CURRENT_PROJECT_VERSION = 7`).
- Removed hardcoded fallback keystore credentials (`'ghosttag'`) and user-specific paths from `scripts/package_release_apk.py` and `scripts/generate_android_branding.py`.

### Documentation & PR Triage Sync
- Relocated FAQ to root [`FAQ.md`](FAQ.md) (`70` evidence-cited Q&As), added missing folder documentation across all 11 project directories, fixed `NTAG213` (`0B` / incompatible with v2 bulk) and `NTAG215`/`NTAG216` (`326B`/`333B` and `706B`/`717B`) framed capacities, removed committed `file:///` links, and squashed PR `#2` (`prettier` `3.10.1`) alongside deferring PRs `#25` (`iOS Beta`), `#21` (`v2.2+`), and `#9` (`v2.2+`).

---

## 2. Verified Checks on Staging `main`
- `npm run typecheck`: `0` errors
- `npx tsc -p tsconfig.build.json --noEmit`: `0` errors
- `npm run lint`: `0` errors
- `npm test -- --ci --maxWorkers=2`: **26/26 suites, 347/347 tests passing** (`56.06% Stmts | 46.44% Branch | 54.67% Funcs | 57.16% Lines`)
- `npx jest desktop/test/pn532_serial.test.js`: **1/1 suite, 22/22 tests passing**
- `node desktop/test/bridge.test.js`: passing
- `node tests/scan-unused.cjs`: `0` unused top-level declarations
- `npm --prefix web run build`: built cleanly (`vite 6.4.6`)
- `npm audit --audit-level=moderate` & `npm --prefix web audit --audit-level=moderate`: `0` vulnerabilities

---

## 3. Staging Android Artifact (Local / Unpublished)
- **File**: `web/assets/Ghost-Tag-v2.1.0.apk` (`41,367,086 bytes` / `39.45 MB`, `versionCode 7`)
- **SHA-256**: `077ecdb3ec3c052b5c30ec52d884e56461209cf92eb0cc1fe93ddd8214723952` (`web/assets/Ghost-Tag-v2.1.0.apk.sha256`, `web/assets/release-meta.json`)
- **Status**: Android emulator launch verified (`Medium_Phone_API_37.0`); **not** yet tagged on GitHub Releases pending real physical Android NFC, ACR122U, ESP32/PN532, and live Supabase deployment validation.
