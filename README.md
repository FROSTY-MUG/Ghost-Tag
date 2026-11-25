<p align="center">
  <img src="web/assets/logo.svg" alt="Ghost-Tag Brutalist Logo" width="72" height="72" />
</p>

# Ghost-Tag (`v2.1.0` Staging)

> **Zero-knowledge, local-first NFC encryption across physical NTAG213, NTAG215, and NTAG216 tags — backed by Argon2id, AES-256-GCM, Cauchy Reed-Solomon over $\mathrm{GF}(2^8)$, native C++17 memory defense, and authenticated local desktop PC/SC + PN532 hardware bridges.**

> **Release Status Honesty Notice**: Latest published GitHub Release is **`v2.0.6`**. Version **`2.1.0`** is unreleased staging software whose source/CI hardening is verified, while physical NFC handset validation, physical ACR122U / ESP32-PN532 validation, live Supabase Edge Function deployment, npm publishing, and `v2.1.0` release tagging remain **pending**. See [`PROJECT-STATUS.md`](PROJECT-STATUS.md) and [`FAQ.md`](FAQ.md).

---

## Who Ghost-Tag Is For & Explicit Boundaries

### Intended Audience & Core Use Cases
- Privacy-conscious individuals, researchers, and engineers storing sensitive text notes, configuration secrets, or fragmented files onto physical NFC Forum Type 2 chips (`NTAG213` for compact `v1` records; `NTAG215` / `NTAG216` for multi-tag `v2` vaults with optional Reed-Solomon parity recovery).
- Users needing **offline-first encryption** where keys live exclusively in client memory and physical tags carry only authenticated binary ciphertext.

### What Ghost-Tag Does **Not** Do
- **Does not simulate or fake NFC hardware** in Android, Web, or Desktop runtime flows (`simulate_tag` is rejected cleanly across Ghost Bridge and UI clients).
- **Does not fit `v2` bulk chunks onto NTAG213** (`NTAG213` holds `v1` single-tag records up to `52B` mobile / `56B` bridge; `v2` bulk returns `0B` usable / `fits: false`).
- **Does not store passphrases, raw KEKs, DEKs, or decrypted plaintext** on disk logs or cloud tables; if both your passphrase and 12-word BIP-39 recovery phrase are lost, ciphertext cannot be recovered.
- **Does not protect an active root-compromised host OS**, guarantee silicon-level EEPROM forensic erasure, or currently support shipping iOS hardware writes (iOS PR `#25` is deferred to `iOS Beta`).
- **Cloud metadata sync requires explicit Supabase configuration and internet connectivity**; without Supabase credentials, all core local encryption, decryption, and NFC workflows remain 100% offline.

---

## Table of Contents
1. [Core Capabilities](#core-capabilities)
2. [Architecture, User Flow, Encryption & Recovery Diagrams](#architecture-user-flow-encryption--recovery-diagrams)
3. [Cryptographic Primitives & Key Hierarchy](#cryptographic-primitives--key-hierarchy)
4. [Binary Envelope Formats & NTAG21x Capacities](#binary-envelope-formats--ntag21x-capacities)
5. [Implemented vs. Proposed & Verification Matrix](#implemented-vs-proposed--verification-matrix)
6. [Cloud Metadata & v2.1.0 Challenge-Proof Recovery](#cloud-metadata--v210-challenge-proof-recovery)
7. [Known Security, Hardware, Recovery & Cloud Limitations](#known-security-hardware-recovery--cloud-limitations)
8. [Repository Map](#repository-map)
9. [Verification, Tests & Coverage](#verification-tests--coverage)
10. [Pull Request & Security Status](#pull-request--security-status)
11. [Quick Links & Vulnerability Reporting](#quick-links--vulnerability-reporting)

---

## Core Capabilities
- **Single-Tag Encrypted Vault (`v1`)**: Encrypts sensitive text/config/asset fragments using a compact **54-byte** Little-Endian binary envelope (`GTAG`, `0x01`, `26B` AAD) over `application/vnd.ghost.secure`. Fits `NTAG213`, `NTAG215`, and `NTAG216`.
- **Distributed Bulk Vaults (`v2`)**: Splits arbitrary encrypted files across sets of `NTAG215` / `NTAG216` tags using **134-byte** Little-Endian envelopes (`GTAG`, `0x02`, `RECORD_TYPE = 0x10`, `74B` AAD, full `32B` SHA-256 `CHUNK_HASH`) over `application/vnd.ghost.bulk`, protected by systematic **Cauchy-Vandermonde Reed-Solomon** parity shards over $\mathrm{GF}(2^8)$ (`0x11d`) and volatile **72-hour RAM cache** (`ChunkCacheManager`) for random-order scanning.
- **Native Android Hardening**: `MainActivity.kt` enforces `FLAG_SECURE`; `KeyStoreMasterKey.kt` anchors hardware TEE/StrongBox wrapping; `android/app/src/main/cpp/` implements `ptrace` anti-debug, `/proc/self/maps` hook detection, root checks, `mlock()` page locking, and 4-pass volatile zeroization with compiler memory barriers.
- **Zero Synthetic Data**: `Ghost Bridge` (`127.0.0.1:41789`), Web Companion, and React Native screens strictly refuse synthetic/simulated NFC events (`simulate_tag` returns an error) and bind hardware actions to per-connection CSPRNG `sessionToken` (`timingSafeEqual`).
- **Two-Stage Zero-Knowledge Cloud Recovery (`v2.1.0`)**: Opt-in Supabase recovery uses Cloudflare Turnstile (`verify-captcha`), server-generated 32-byte CSPRNG `recovery_salt` (`account-auth`), two-stage Argon2id (`m=32768, t=3, p=2, h=32, v=0x13`), and interactive `76B` HMAC challenge/proof verification (`recover-vault`) with locked-down RLS (`ghost_vaults` revoked from direct client access).

---

## Architecture, User Flow, Encryption & Recovery Diagrams

### 1. Subsystem Architecture & Two-Tier Key Hierarchy

```mermaid
flowchart TD
    UserPass["Master Passphrase (>= 16 chars)"] --> KDF["Argon2id RFC 9106 KEK Derivation (16 / 32 / 64 MiB)"]
    Bip39["12-Word BIP-39 Primary Phrase (24-word local compat)"] --> RecKDF["Recovery KEK / Auth Derivation"]
    KDF --> Wrap["AES-256-GCM Key Wrap (19B AAD)"]
    RecKDF --> Wrap
    Wrap --> DEK["Random 256-bit Data Encryption Key (DEK)"]
    DEK --> Single["v1 Single-Tag Envelope (54B overhead)"]
    DEK --> Bulk["v2 Bulk Distributed Vault (134B overhead + Cauchy RS GF(2^8))"]
    Single --> NFC["Physical Type 2 NFC Tags (NTAG213 / 215 / 216)"]
    Bulk --> NFC
    Ops["src/operations/ State Machines"] --> Security["src/security/ + Android C++ NDK (mlock / ptrace / 4-pass wipe)"]
```

### 2. Single-Tag v1 vs Bulk Distributed v2 NDEF Pipeline

```mermaid
flowchart LR
    Input["Plaintext Secret / File(s)"] --> Split{"Vault Mode"}
    Split -->|"Single Secret (v1)"| Env1["Pack 54B Header + 26B AAD (MAGIC='GTAG', v0x01) -> NDEF application/vnd.ghost.secure"]
    Env1 --> Tags1["Single Tag: NTAG213 (52B/56B), NTAG215 (404B/411B), NTAG216 (784B/795B)"]
    Split -->|"Bulk Files (v2)"| EncFile["AES-256-GCM Encrypt File + Manifest SHA-256"]
    EncFile --> RS["Cauchy Reed-Solomon Over GF(2^8) -> K Data + M Parity Shards"]
    RS --> Env2["Pack 134B Header + 74B AAD (0..73) + 32B CHUNK_HASH (74..105) -> NDEF application/vnd.ghost.bulk"]
    Env2 --> Tags2["Multiple Tags (NTAG215: 326B/333B, NTAG216: 706B/717B; NTAG213 Unsupported)"]
    Tags2 --> Recon["Random-Order Scan -> 72h Volatile RAM Cache -> Any K Shards Reconstruct"]
```

### 3. Opt-In v2.1.0 Turnstile & Challenge-Response Cloud Recovery

```mermaid
sequenceDiagram
    participant Client as Client (Android / Web WASM)
    participant Captcha as verify-captcha (Turnstile)
    participant Auth as account-auth Edge Function
    participant Recover as recover-vault Edge Function
    participant DB as Supabase PostgreSQL (RLS Locked)

    Client->>Captcha: Submit Turnstile widget token
    Captcha-->>Client: Short-lived HMAC verification token
    Client->>Auth: Request recovery account setup / server 32B CSPRNG recovery_salt
    Auth->>DB: Store salt + Argon2id verifier + encrypted_recovery_envelope (service role only)
    Client->>Recover: Request challenge (account_id + Turnstile token)
    Recover->>DB: Enforce atomic 15-min rate limits & record single-use challenge
    Recover-->>Client: Return challenge_id, nonce, server_timestamp, recovery_salt
    Note over Client: Client derives 2-stage Argon2id recovery_auth_secret (m=32768,t=3,p=2) & computes 76B HMAC proof
    Client->>Recover: Submit challenge_id + 76B recovery_proof
    Recover->>DB: Verify proof constant-time & consume challenge
    Recover-->>Client: Return encrypted_recovery_envelope (plaintext keys remain strictly client-side)
```

### 4. End-to-End User Flow (Local Offline & Opt-In Cloud)

```mermaid
flowchart TD
    Start["Launch App (Android / Web Companion)"] --> Choice{"Account State"}
    Choice -->|"New User"| Pass["Create >=16-Char Passphrase"]
    Pass --> Phrase["Generate 12-Word BIP-39 Phrase & Confirm 3 Words"]
    Phrase --> Ready["Vault Unlocked in Volatile Memory"]
    Choice -->|"Existing Local"| Unlock["Enter Passphrase -> Unwrap DEK via Argon2id"]
    Unlock --> Ready
    Choice -->|"New Device"| Rec["Enter 12-Word Recovery Phrase"]
    Rec --> Ready
    Ready --> Action{"Action"}
    Action -->|"Write v1 / v2"| Enc["Encrypt Chunks + Optional RS Parity -> Physical NFC Tap + Read-Back Verify"]
    Action -->|"Read / Decrypt"| Scan["Scan Tags in Any Order -> 72h Volatile RAM Cache -> Reconstruct & Decrypt"]
    Action -->|"Lock / Timeout"| Wipe["Zeroize Volatile Buffers (secureWipe / mlock Purge)"]
```

---
- **Symmetric AEAD**: AES-256-GCM with 12-byte (96-bit) CSPRNG nonces and 16-byte (128-bit) constant-time tags (`src/crypto/aesGcm.ts`).
- **Primary KDF Profiles (`DEFAULT_KDF_PARAMETERS_BY_TIER` in `src/contracts/keyHierarchy.ts`)**:
  - `LOW_END`: `16,384 KiB` (`16 MiB`), `t = 2`, `p = 1`, `v = 0x13`
  - `STANDARD` (default): `32,768 KiB` (`32 MiB`), `t = 3`, `p = 2`, `v = 0x13`
  - `HIGH_END`: `65,536 KiB` (`64 MiB`), `t = 4`, `p = 4`, `v = 0x13`
  - All primary KDF salts: `16 bytes` CSPRNG.
- **Recovery Derivation**:
  - Primary recovery phrase: **12-word BIP-39 English mnemonic** (`128` entropy + `4` checksum bits). Local `RecoveryManager` retains `24-word` local unwrapping compatibility.
  - Local `DEFAULT_RECOVERY_KDF_CONFIG`: `65,536 KiB`, `t = 5`, `p = 4`, `32B` salt.
  - Cross-platform v2.1.0 cloud recovery (`hash-wasm` WASM on Web / Edge Functions): `32,768 KiB` (`32 MiB`), `t = 3`, `p = 2`, `h = 32B`, `v = 0x13` over server-generated `32B` CSPRNG `recovery_salt`.
- **Memory & Log Hygiene**: 4-pass overwrite (`0xAA`, `0x55`, CSPRNG, `0x00` + C++ compiler barrier), constant-time `timingSafeEqual`, and log redaction (`SanitizedLogger`).

---

## Binary Envelope Formats & NTAG21x Capacities

All envelopes begin with 4-byte ASCII magic `"GTAG"` (`0x47, 0x54, 0x41, 0x47`) and Little-Endian integers:
- **v1 (`application/vnd.ghost.secure`)**: `54 bytes` fixed overhead (`26B` AAD + `12B` nonce + `16B` GCM tag).
- **v2 (`application/vnd.ghost.bulk`)**: `134 bytes` fixed overhead (`74B` AAD across offsets `0..73` + `32B` SHA-256 `CHUNK_HASH` across `74..105` + `12B` nonce + `16B` GCM tag). There is no Merkle tree.

| Tag IC | Total / User EEPROM | v1 Single-Tag Max Ciphertext (`TagInfo.ts` / `apdu.js`) | v2 Bulk Chunk Max Ciphertext (`TagInfo.ts` / `apdu.js`) | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | `180B` / `144B` | `52B` / `56B` | **Does Not Fit (`0B`)** | Insufficient framed capacity for `134B` v2 bulk header + NDEF MIME framing (`fits: false`). |
| **NTAG215** | `540B` / `504B` | `404B` / `411B` | `326B` / `333B` | Recommended baseline tag for v2 distributed vaults. |
| **NTAG216** | `924B` / `888B` | `784B` / `795B` | `706B` / `717B` | High-capacity tag minimizing tag count in bulk vaults. |

---

## Implemented vs. Proposed & Verification Matrix

| Surface / Capability | State | Transport / Offline Model | Test & Hardware Evidence |
| :--- | :--- | :--- | :--- |
| **Core Crypto, Envelopes & Cauchy RS (`src/`)** | Implemented | 100% Offline | Verified via Jest (`347/347` tests across `26` suites; NFC mocked via `__mocks__/react-native-nfc-manager.ts`). |
| **Android App (`android/`)** | Implemented | 100% Offline (opt-in Cloud Sync optional) | Gradle compiles cleanly (`:app:testDebugUnitTest NO-SOURCE`); emulator launch clean (`Medium_Phone_API_37.0`); **physical handset launch & NFC pending**. |
| **Web Companion (`web/`)** | Implemented | 100% Offline locally; Chrome WebNFC requires HTTPS | Vite `6.4.6` build & `0`-vuln audit pass; live GitHub Pages (`technical.html`, `#loadingScreen`, skeletons, `390x844` mobile) verified in Chrome; **physical Android Chrome WebNFC pending**. |
| **Desktop Ghost Bridge (`desktop/`)** | Implemented | Local loopback (`ws://127.0.0.1:41789`) | Standalone & `22` Jest PN532 serial tests pass with mock PC/SC & `MockSerialPort`; **physical ACR122U & ESP32/PN532 hardware pending**. |
| **Opt-In Cloud Recovery (`supabase/`)** | Staged in Git (Undeployed) | Internet required when opted in | Migrations `20261115`–`20261126` & `8` Edge Functions pass mocked Jest policy/RLS tests; **live hosted Supabase deploy pending**. |
| **iOS Target (`ios/`, PR `#25`)** | Deferred (`iOS Beta`) | Offline CoreNFC | `project.pbxproj` synced to `2.1.0` (build `7`); PR `#25` deferred pending macOS Xcode, entitlements, `.ipa` `os.walk` fix, and physical iPhone validation. |
| **Toolchain Upgrades (`#21` Vite 8, `#9` TS 7)** | Deferred (`v2.2+`) | Build-time only | Intentionally deferred until `@typescript-eslint` and Vite ESM plugin/config migration align cleanly. |

---

## Cloud Metadata & v2.1.0 Challenge-Proof Recovery
- Opt-in schema in [`supabase/`](supabase/README.md) introduces `user_accounts`, `vault_metadata`, `recovery_challenges`, and `ghost_vault_status` view, revoking direct client access to `ghost_vaults` and sensitive recovery columns.
- Legacy deterministic `Option A` test fixtures remain in [`test-fixtures/`](test-fixtures/README.md) exclusively for deterministic vector regression tests (`crossPlatformCryptoCompatibility.test.ts`).
- Live cloud project deployment has **not** yet been executed; Supabase policies and Edge Function handlers are verified via mocked policy/security Jest suites.

---

## Known Security, Hardware, Recovery & Cloud Limitations

- **Security Boundaries**: Client-side memory encryption, `mlock()`, `ptrace` probes, and `FLAG_SECURE` cannot protect secrets on a root-compromised or unlocked device, nor can static Type 2 NDEF payloads prevent physical UID-independent byte cloning (`AES-256-GCM` protects confidentiality and tamper detection only). See [`SECURITY.md`](SECURITY.md).
- **Hardware & RF Limits**: `NTAG213` (`144B` user memory) fits `v1` single-tag payloads only and **cannot fit** `134B` `v2` bulk chunks (`0B` usable / `fits: false`). Real RF verification on physical Android handsets, ACS ACR122U, ESP32/PN532, and iPhone CoreNFC remains open. Destructive overwrite cleans writable NDEF pages but cannot guarantee silicon-level forensic erasure.
- **Recovery Boundaries**: Cross-platform `v2.1.0` cloud recovery requires an exact 12-word English BIP-39 phrase (`24`-word phrases remain local-only offline unwrapping). If both local passphrase and recovery phrase are lost, ciphertext is unrecoverable.
- **Cloud Dependencies**: Live Supabase migrations and Edge Functions remain undeployed; until deployed and integration-tested, opt-in cloud backup/recovery runs offline (`Offline (Local Only)`) unless pointed at an operator-provisioned Supabase project. On the Supabase Free Tier (`ap-south-1` Mumbai target), email verification is **disabled** (built-in Auth email is capped at `2` emails/hour without custom SMTP, so Ghost-Tag uses the anonymous/phrase-based account flow), and automated daily backups / Point-in-Time Recovery (Pro/paid add-on) are unavailable without manual `supabase db dump` exports.

---

## Repository Map

| Directory | Documentation | Contents |
| :--- | :--- | :--- |
| Root `/` | [`README.md`](README.md) & [`FAQ.md`](FAQ.md) | Repository portal, diagrams, and 70 evidence-cited Q&As |
| `src/` | [`src/README.md`](src/README.md) | Shared TypeScript core, contracts, crypto, NFC, ops, security, vault, cloud, React Native UI |
| `android/` | [`android/README.md`](android/README.md) | Kotlin security modules, C++17 NDK core, Gradle build, adaptive branding |
| `desktop/` | [`desktop/README.md`](desktop/README.md) | Ghost Bridge WS/HTTP PC/SC server (`127.0.0.1:41789`), APDU framing, PN532/ESP32 firmware |
| `web/` | [`web/README.md`](web/README.md) | Vite MPA web showcase, WASM Argon2id, Turnstile, Web NFC + Ghost Bridge client |
| `supabase/` | [`supabase/README.md`](supabase/README.md) | PostgreSQL migrations, RLS hardening, and 8 Edge Functions (`verify-captcha`, `account-auth`, `recover-vault`, `sync-vault-metadata`, deletion workers) |
| `ios/` | [`ios/README.md`](ios/README.md) | Swift cryptographic foundation and deferred PR `#25` CoreNFC roadmap |
| `scripts/` | [`scripts/README.md`](scripts/README.md) | CI security/quality agents, APK packaging (env-var signed), branding asset generators |
| `tests/` | [`tests/README.md`](tests/README.md) | Static unused-code scanner (`scan-unused.cjs`) |
| `test-fixtures/` | [`test-fixtures/README.md`](test-fixtures/README.md) | Deterministic golden cross-platform crypto reference vectors |
| `docs/` | [`docs/README.md`](docs/README.md) | Engineering specs, ADRs (`0001`–`0004`), security audit log, and wiki chapters |
| `agents/` | [`agents/README.md`](agents/README.md) | Autonomous security, QA, crypto, and NFC verification role charters |

---

## Verification, Tests & Coverage

- **TypeScript Strict Mode**: `npm run typecheck` and `npx tsc -p tsconfig.build.json --noEmit` — **0 errors**.
- **Lint & Unused Scan**: `npm run lint` (`0` errors) and `node tests/scan-unused.cjs` — **passed**.
- **Default Jest Suite (`npm test -- --ci --maxWorkers=2`)**: **26 test suites / 347 tests passing**.
  - **Measured Coverage (`--coverage`)**: `56.06% Statements` | `46.44% Branches` | `54.67% Functions` | `57.16% Lines`.
- **PN532 Serial Suite (`npx jest desktop/test/pn532_serial.test.js`)**: **1 suite / 22 tests passing** (combined **369 tests across 27 suites**).
- **Web Build & Security Audits**: `npm --prefix web run build` passes; `npm audit --audit-level=moderate` and `npm --prefix web audit --audit-level=moderate` report **0 vulnerabilities**.
- **Audit Agents**: `python scripts/security_audit_agent.py` & `python scripts/quality_audit_agent.py` pass cleanly.

---

## Pull Request & Security Status
- **Merged**: PR `#24` (`bulk-scanning-v2`), PR `#2` (`prettier` `3.10.1`), PR `#34` (CodeQL `#75`/`#76`/`#78` fix, `desktop/**` CodeQL workflow trigger, UI stub elimination, script credential cleanup, Xcode version sync), PR `#35` (FAQ relocation & doc sync), PR `#40` (CodeQL note `#79` fix), PR `#41` (`web/technical.html` `v1`/`v2` capacity table).
- **Deferred (`Keep open / defer`)**: PR `#25` (`ios/ghost-tag-support` -> `iOS Beta`, Issue `#38`), PR `#21` (`vite` `8.3.8` in `/web` -> `v2.2+`, Issue `#39`), PR `#9` (`typescript` `7.0.2` -> `v2.2+`, Issue `#39`).
- **Code Scanning**: Open CodeQL, Dependabot, and secret-scanning alerts are `0`.

---

## Quick Links & Vulnerability Reporting
- **Report a Security Vulnerability**: Do **not** open a public issue or paste secrets; follow private coordinated disclosure via [GitHub Security Advisories](https://github.com/FROSTY-MUG/Ghost-Tag/security/advisories/new) (`72-hour` acknowledgement SLA — see [`SECURITY.md`](SECURITY.md)).
- [`FAQ.md`](FAQ.md) — 70 evidence-cited Q&As
- [`PROJECT-STATUS.md`](PROJECT-STATUS.md) — Component verification & release blocker matrix
- [`CHANGELOG.md`](CHANGELOG.md) & [`RELEASE-NOTES.md`](RELEASE-NOTES.md) — Version history & `v2.1.0` staging summary
- [`SECURITY.md`](SECURITY.md) & [`SUPPORT.md`](SUPPORT.md) — Threat disclosure policy & support channels
- [`CONTRIBUTING.md`](CONTRIBUTING.md) & [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — PR workflow & branch protection rules
- [`AGENT.md`](AGENT.md) & [`agents/`](agents/README.md) — Autonomous agent roles and verification contracts
