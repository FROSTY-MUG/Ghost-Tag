# GHOST-TAG v2.0.5: PERSISTENT PROJECT STATE & CONVERSATION MEMORY

> **CRITICAL AGENT INSTRUCTION FOR ALL FUTURE SESSIONS**:
> This document is the canonical, permanent record of Ghost-Tag v2.0.5. Whenever you start a new chat or continue this project, **read this file first**. It encapsulates all architectural decisions, security invariants, hardware specifications, directory structures, cryptographic schemas, and verified CI states.
>
> **Core Promise**:
> ```
> Encrypted NFC storage.
> Create. Encrypt. Scan. Decrypt.
> ```

---

## 1. Executive Summary & Product Definition

Ghost-Tag is a hardware-anchored, zero-knowledge encrypted NFC storage system designed for physical zero-trust data persistence. It allows users to write encrypted text, files, photos, videos, and private links across one or more physical NFC tags (NTAG213, NTAG215, NTAG216), and later scan them in any order to decrypt the complete content using a single user passphrase.

### Target Platforms
1. **Android APK (Primary Full Client)**:
   - Native transceiver access (NFC-A, ISO 14443-3A, Type 2 Tag).
   - NDK C++ security layer (`security_core.cpp`) enforcing anti-debugging (`ptrace`), anti-tamper, and memory sanitization.
   - Screen capture protection (`FLAG_SECURE`).
   - Argon2id key derivation ($m=64\,\text{MB}, t=3, p=4$).
2. **Web Client (Lightweight Companion)**:
   - Deployed on GitHub Pages at `https://frosty-mug.github.io/Ghost-Tag/`.
   - Browser client running pure Vanilla JS/HTML5 with Web NFC (`NDEFReader`) on supported Android browsers.
   - Zero-secrets in-memory session with pure blob-based viewing and downloading.
3. **Ghost Bridge Desktop Daemon (`/desktop`)**:
   - Node.js native PC/SC USB daemon binding strictly to `127.0.0.1:41789`.
   - Bridges hardware **ACS ACR122U USB NFC Readers** to web browsers on laptops and workstations.
   - Real-time WebSocket event streaming and physical block write read-back verification.

---

## 2. Strict Non-Negotiable Invariants

Any agent or contributor modifying this codebase must adhere to these rules without exception:

1. **Zero Mock / Synthetic NFC Data**:
   - Never generate random tag UIDs (`Math.random()`), placeholder capacities, synthetic scan counts, or simulated write delays.
   - If physical hardware is absent, the system must display the exact hardware status.
2. **Hardware Status Truth Table**:
   - **Laptop without Ghost Bridge or USB reader**: `NO USB NFC READER DETECTED` (with download links for Ghost Bridge and Android APK).
   - **Laptop with Ghost Bridge and USB reader, no tag on antenna**: `NO NFC TAG DETECTED`.
   - **Mobile without Web NFC hardware**: `NO NFC READER DETECTED`.
   - **Android with NFC disabled**: `NFC IS TURNED OFF`.
   - **Unsupported tag (e.g. unformatted MIFARE Classic)**: `THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA`.
   - **iOS Safari**: `iOS is not supported yet` (Web NFC is unsupported by Apple on iOS Safari).
3. **Mandatory Account Creation**:
   - A user must create or restore a local Ghost account before encrypting or decrypting.
   - Identity is anchored to a standard **12-word BIP-39 recovery phrase** ($128\text{ bits entropy} + 4\text{ bits checksum}$).
   - `accountId = SHA-256(12-word recovery phrase || "ghost-account-id")`.
4. **Single Passphrase**:
   - The same master passphrase encrypts and decrypts vaults across Android and Web.
5. **Double Cryptographic Binding**:
   - Outer layer: AES-256-GCM + 32-byte SHA-256 digest over the complete payload.
   - Inner chunk layer: AES-256-GCM + 32-byte SHA-256 digest over each individual tag chunk with 74-byte deterministic Little-Endian AAD.
6. **Volatile Session Memory Only**:
   - Zero persistent chunk caching (strictly no 72-hour cache). All raw chunks and plaintexts are zeroized on tab close or manual clear.
7. **Cloud Role (Supabase Sync)**:
   - Optional, offline-first default.
   - Supabase stores **strictly encrypted vault metadata** (`wrappedDek`, `salt`, `formatVersion`).
   - Zero plaintext, zero keys, zero recovery phrases, zero passphrases, and zero NFC chunk payloads ever reach the cloud.
8. **No Forbidden Features**:
   - Strictly no tag cloning, no MIFARE cracking, no NFC emulation, no tag locking, and no "Tag Doctor" features.

---

## 3. Complete Repository Structure

```
ghost-tag/
├── .github/
│   └── workflows/
│       ├── ci.yml                    # Jest unit/integration tests (143/143 passing)
│       ├── agent-quality-gate.yml    # Version sync, strict typecheck, test gate
│       ├── agent-security-audit.yml  # Zero-secrets, FLAG_SECURE, crypto audit
│       ├── deploy-pages.yml          # Automated GitHub Pages deployment pipeline
│       ├── android-build.yml         # Matrix release APK build across 4 ABIs
│       └── release.yml               # Automated GitHub Release generation
├── android/                          # Native Android Studio Project
│   ├── app/
│   │   ├── build.gradle              # Gradle 9 compatible, NDK CMake links, release signing
│   │   ├── src/main/
│   │   │   ├── AndroidManifest.xml   # NFC intents, FLAG_SECURE, cleartextBlocked
│   │   │   ├── cpp/security_core.cpp # NDK anti-ptrace, anti-Frida, memory wiping
│   │   │   ├── java/com/ghosttag/    # MainActivity, SecurityBridgeModule (Kotlin)
│   │   │   └── res/                  # App drawables, mipmaps, styles
│   │   └── proguard-rules.pro        # Obfuscation and security hardening
│   └── build.gradle                  # Top-level Gradle configuration
├── desktop/                          # Ghost Bridge Companion for PC/SC USB Readers
│   ├── bin/ghost-bridge.js           # CLI entry point (`./bin/ghost-bridge.js --port 41789`)
│   ├── src/
│   │   ├── apdu.js                   # ACR122U APDUs, block read/write, TLV NDEF builder
│   │   ├── server.js                 # WebSocket & HTTP RPC server on 127.0.0.1:41789
│   │   └── index.js                  # Module exports
│   ├── test/bridge.test.js           # Standalone & Jest compatible protocol tests
│   ├── package.json                  # ghost-bridge@2.0.5 dependencies
│   └── README.md                     # Hardware guide, OS driver setup, protocol docs
├── docs/
│   ├── wiki/                         # All 18 Full Documentation Wiki Chapters
│   │   ├── Home.md                   # Wiki index & sitemap
│   │   ├── Getting-Started.md        # Concepts and setup
│   │   ├── Android-Installation.md   # APK install & SHA-256 verification
│   │   ├── Web-App.md                # GitHub Pages web companion guide
│   │   ├── Ghost-Bridge.md           # Desktop ACR122U USB reader daemon
│   │   ├── Creating-an-Account.md    # Anonymous identity & local accounts
│   │   ├── Recovery-Phrase.md        # 12-word BIP-39 mnemonic mechanics
│   │   ├── Encrypt.md                # Payload packaging and chunking
│   │   ├── Decrypt.md                # Scanning in any order & reassembly
│   │   ├── Batch-Write.md            # Multi-tag batch distribution
│   │   ├── Batch-Read.md             # Multi-tag order-independent recovery
│   │   ├── NFC-Compatibility.md      # NTAG213, NTAG215, NTAG216 specs
│   │   ├── Security-Model.md         # Zero-knowledge, KEK/DEK, Argon2id/PBKDF2
│   │   ├── Technical-Format.md       # Canonical GTAG Little-Endian envelope
│   │   ├── Recovery.md               # Cross-platform account restoration
│   │   ├── Troubleshooting.md        # Hardware alignment & driver remedies
│   │   ├── Contributing.md           # Architecture standards & PR guidelines
│   │   └── Roadmap.md                # Future iOS app, Reed-Solomon redundancy
│   ├── architecture.md               # Monorepo architecture & data flow
│   ├── cryptography.md               # Mathematical crypto proofs & key schedule
│   ├── GHOST_TAG_SYSTEM_MANUAL.md    # Comprehensive system manual
│   └── PROJECT_STATE_MEMORY.md       # THIS FILE (Permanent state memory)
├── scripts/                          # Automation, Auditing & Packaging Agents
│   ├── patch_dependencies.js         # Gradle 9 & jcenter to mavenCentral patcher
│   ├── security_audit_agent.py       # Automated security invariant scanner
│   ├── quality_audit_agent.py        # Automated quality gate checker
│   └── package_release_apk.py        # Release APK packager & SHA-256 generator
├── src/                              # TypeScript Core Cryptographic Library
│   ├── contracts/                    # Type definitions (bulkEnvelope, bulkVault, errors)
│   ├── crypto/                       # aesGcm, argon2, bulkEnvelope, fileEncryption, random
│   ├── nfc/                          # bulkNdefBuilder, transceive, tagInspection
│   ├── vault/                        # bulkVaultManager, manifest coordinator
│   └── __tests__/                    # 12 Jest test suites (143 unit/integration tests)
├── web/                              # GitHub Pages Web Client
│   ├── index.html                    # Dark brutalist UI, hardware notice banners, modals
│   ├── styles.css                    # Ambient ghost hero styling, responsive design
│   ├── app.js                        # Zero-mock engine, GhostBridge client, Web NFC, crypto
│   ├── wordlist.js                   # Standard 2048-word BIP-39 English dictionary
│   ├── supabase.js                   # Anonymous zero-knowledge metadata sync client
│   ├── technical.html                # Technical, Security, Privacy, and Source specifications
│   └── public/assets/                # ghost-hero.jpg, favicons, release metadata
├── CHANGELOG.md                      # Complete v2.0.5 release history
├── package.json                      # @frosty-mug/ghost-tag@2.0.5
├── README.md                         # Public repository front page
└── SECURITY.md                       # Threat model, vulnerability disclosure & invariant policy
```

---

## 4. Cryptographic Binary Envelope Specification (`GTAG`)

All Ghost records on NFC tags use the NDEF MIME Media type:
`application/vnd.ghost.bulk`

### 4.1 Fixed 134-Byte Envelope Layout (Little-Endian)
```
Offset  Size  Field                  Type / Description
---------------------------------------------------------------------------------------
0x00    4B    MAGIC                  0x47, 0x54, 0x41, 0x47 ("GTAG")
0x04    1B    FORMAT_VERSION         0x02
0x05    1B    RECORD_TYPE            0x10 (Bulk Chunk) / 0x01 (Single Tag)
0x06    16B   VAULT_ID               128-bit CSPRNG Vault Identifier
0x16    16B   FILE_ID                128-bit CSPRNG File/Payload Identifier
0x26    16B   KEY_ID                 128-bit CSPRNG Key Identifier
0x36    4B    GLOBAL_CHUNK_INDEX     uint32 (Little-Endian)
0x3A    4B    TOTAL_VAULT_CHUNKS     uint32 (Little-Endian)
0x3E    4B    FILE_CHUNK_INDEX       uint32 (Little-Endian)
0x42    4B    TOTAL_FILE_CHUNKS      uint32 (Little-Endian)
0x46    4B    CHUNK_CIPHERTEXT_LEN   uint32 (Little-Endian) = N
0x4A    32B   CHUNK_HASH             SHA-256 digest of CHUNK_CIPHERTEXT
0x6A    12B   NONCE (IV)             96-bit CSPRNG AES-GCM Initialization Vector
0x76    NB    CHUNK_CIPHERTEXT       Encrypted chunk payload
0x76+N  16B   GCM_TAG                128-bit AES-GCM Authentication Tag
---------------------------------------------------------------------------------------
Total Fixed Overhead: 134 Bytes
Additional Authenticated Data (AAD): Bytes 0x00 through 0x49 (74 Bytes deterministic)
```

### 4.2 Usable Ghost Payload per Tag
$$\text{Usable Payload} = \text{Tag Writable EEPROM} - 134\text{ Bytes}$$
- **NTAG213** (144B writable): 10 Bytes (Used only for tiny keys/seeds)
- **NTAG215** (504B writable): **370 Bytes** per tag
- **NTAG216** (888B writable): **754 Bytes** per tag

### 4.3 Self-Contained Encrypted Payload Format
When multiple entries (Text, File, Photo, Video, URL) are staged:
1. Entries are serialized:
   `[{ type, name, mime, size, dataB64 }]` -> UTF-8 JSON bytes.
2. Encrypted with AES-256-GCM using derived KEK:
   `{ iv: fileNonce [12B], ciphertext [NB], tag: fileGcmTag [16B] }`.
3. Packaged into a self-contained blob:
   `salt [32B] || fileNonce [12B] || fileGcmTag [16B] || ciphertext [NB]`.
4. Split into chunks fitting available tag capacities.
5. Reassembly collects chunks in any order, sorts by index 0..N-1, unpacks salt/nonce/tag, derives KEK from user's passphrase, and authenticates before presenting plaintext.

---

## 5. Verification & Test Suite Gates

Every commit is gated by automated CI suites. Current verification status:

| Suite | Status | Details |
| :--- | :--- | :--- |
| **Jest Unit & Integration Tests** | **143 / 143 PASS (100%)** | 12 test suites covering crypto, envelopes, vault, NFC, deletion, Supabase sync, and desktop bridge. |
| **TypeScript Compilation** | **0 Errors (Strict Mode)** | Full static type check across monorepo (`npx tsc --noEmit`). |
| **Automated Security Audit** | **100% HEALTHY** | Zero secrets, FLAG_SECURE verified, NDK ptrace anti-debug verified, deterministic AAD verified. |
| **Automated Quality Audit** | **100% HEALTHY** | Version sync (2.0.5), Gradle sync, release metadata verified. |
| **Desktop Standalone Tests** | **PASS** | `node desktop/test/bridge.test.js` passes APDU construction, NDEF MIME serialization, and HTTP schema. |
| **GitHub Actions Runs** | **ALL GREEN** | Run `43788842875` (CI), Run `43788842868` (Quality), Run `43788842824` (Security), Run `43788842817` (Pages). |

---

## 6. How to Resume Work in a New Conversation

When starting a fresh turn or new chat:

1. **Verify Workspace State**:
   ```bash
   git status
   npm test
   npx tsc --noEmit
   ```
2. **Remember the Non-Negotiable Invariants**:
   - Zero synthetic/simulated NFC data. Real transceivers only.
   - When no hardware is present, display:
     - `NO USB NFC READER DETECTED` (on laptop without bridge)
     - `NO NFC TAG DETECTED` (on reader without card)
     - `NO NFC READER DETECTED` (on mobile without Web NFC)
     - `NFC IS TURNED OFF` (when disabled in settings)
     - `THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA` (when incompatible)
   - Account creation is mandatory before encryption or decryption.
   - Passphrase derivation uses PBKDF2 (Web) and Argon2id (Android).
   - Volatile in-memory sessions only (no 72-hour chunk cache).
3. **Ghost Bridge Daemon (`/desktop`)**:
   - Binds strictly to `127.0.0.1:41789`.
   - Used for ACR122U USB readers on laptops.
4. **All 18 Wiki Pages**:
   - Located in `docs/wiki/`. Maintain index in `docs/wiki/Home.md`.

This file is permanent. Keep it updated whenever architectural changes or releases occur.
