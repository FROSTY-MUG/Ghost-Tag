# Ghost-Tag Canonical Technical Specification

**Specification Version**: 2.1.0  
**Status**: CANONICAL SOURCE OF TRUTH  
**Last Updated**: 2026-11-23  

---

## Notice of Authority & Supersession
This document is the **single authoritative cryptographic, wire-format, envelope, and architectural specification** for the Ghost-Tag ecosystem across all target platforms (Android, Web, Desktop Ghost Bridge, and iOS foundation).

All other specifications, architecture briefs, envelope summaries, or user guides must align with this document. In the event of any conflict between this document and any other document in the repository:
1. This document takes absolute precedence.
2. Any document with conflicting specifications is deemed **HISTORICAL** or **SUPERSEDED**.

---

## 1. Root Identity & Recovery Phrase

### 1.1 Canonical Format: 12-Word BIP-39
The canonical recovery credential for Ghost-Tag accounts is a **12-word BIP-39 mnemonic phrase** in standard English:
- **Entropy Size**: 128 bits (16 bytes) generated strictly via a cryptographically secure pseudorandom number generator (CSPRNG: `crypto.getRandomValues()` on Web, `SecureRandom` on Android, `SecRandomCopyBytes` on iOS).
- **Checksum**: The first 4 bits of the SHA-256 hash of the 128-bit entropy ($\frac{128}{32} = 4\text{ bits}$).
- **Total Bitstream**: $128\text{ bits entropy} + 4\text{ bits checksum} = 132\text{ bits}$.
- **Word Encoding**: Divided into 12 groups of 11 bits each ($12 \times 11 = 132\text{ bits}$). Each 11-bit integer ($0 \le i < 2048$) maps to a word in the standard English BIP-39 wordlist.
- **Confirmation Requirement**: On creation, users must confirm words **4, 8, and 11** (1-based indexing) before account activation.

### 1.2 Status of 24-Word Recovery Phrases
- **Historical / Expert Mode**: The underlying TypeScript `RecoveryManager` engine retains legacy support for generating and decoding 256-bit entropy (24-word) phrases for offline local-only emergency key unwrapping.
- **Interoperability Rule**: **Cross-platform recovery, Web client, iOS foundation, and Supabase cloud metadata recovery strictly require 12 words.** 24-word phrases cannot be used for Supabase cloud vault restoration.

---

## 2. Cryptographic Key Derivation Hierarchy

```
                             [12-Word BIP-39 Phrase]
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           ▼                            ▼                            ▼
[account_id (RFC 4122 v4)]   [recovery_auth_secret]          [recovery_salt]
   SHA-256 + UUID format       SHA-256 (32 raw bytes)       SHA-256 (32 raw bytes)
                                        │                            │
                                        └─────────────┬──────────────┘
                                                      ▼
                                            [recovery_verifier]
                                            Argon2id RFC 9106
                                        (64 lowercase hex chars)
```

### 2.1 Account Identity (`account_id`)
- **Formula**:
### Historical Option A Reference Vectors vs Production v2.1.0 Salt Architecture
- **Deterministic Test Fixtures (`test-fixtures/recovery/recoveryVectors.json`, Option A)**: Retained in source tests (`crossPlatformCryptoCompatibility.test.ts`) to validate deterministic vector generation (`SHA-256("ghost-account-id-v2.0.5:" || cleanPhrase)`, `SHA-256("ghost-recovery-auth-v2.0.5:" || cleanPhrase)`, `SHA-256("ghost-recovery-salt-v2.0.5:" || cleanPhrase)` + Argon2id).
- **Production v2.1.0 Supabase Protocol (`supabase/functions/account-auth/`, `recover-vault/`)**: Generates a **server-random 32-byte CSPRNG `recovery_salt`** during account setup, derives `recovery_auth_secret` and `recovery_verifier` via two-stage Argon2id (`m = 32768 KiB, t = 3, p = 2, h = 32B, v = 0x13`), and authenticates recovery via Turnstile-gated `76B` HMAC challenge-proof verification (`src/__tests__/recoveryChallengeProof.test.ts`).
- **Normalization**: `cleanPhrase` trims leading/trailing whitespace, converts all words to lowercase, and joins words with single ASCII spaces (`0x20`).
- **Formatting**: RFC 4122 version 4 UUID with bit adjustments:
  - Byte 6: `(byte[6] & 0x0f) | 0x40` (Version 4)
  - Byte 8: `(byte[8] & 0x3f) | 0x80` (Variant 1)
- **Output**: 36-character canonical lowercase string (`xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx`).

### 2.2 Recovery Auth Secret (`recovery_auth_secret`)
- **Formula**:
  $$\text{recovery\_auth\_secret} = \text{SHA-256}\left(\text{"ghost-recovery-auth-v2.0.5:"} \mathbin{\Vert} \text{cleanPhrase}\right)$$
- **Output**: Exactly 32 raw bytes.
- **Zero-Leakage Constraint**: **NEVER transmitted over the network and NEVER stored in persistent storage or Supabase.** Used solely as the ephemeral password input to derive `recovery_verifier`.

### 2.3 Deterministic Recovery Salt (`recovery_salt`)
- **Formula**:
  $$\text{recovery\_salt} = \text{SHA-256}\left(\text{"ghost-recovery-salt-v2.0.5:"} \mathbin{\Vert} \text{cleanPhrase}\right)$$
- **Output**: Exactly 32 raw bytes.
- **Design Rationale**: Derived deterministically from the 12-word phrase to eliminate salt distribution circularity during out-of-band recovery on brand-new devices.

### 2.4 Recovery Verifier (`recovery_verifier`)
- **Algorithm**: **Argon2id RFC 9106** ($v = 0x13$).
- **Inputs**:
  - `password`: Hexadecimal representation of `recovery_auth_secret` (64 lowercase ASCII characters, UTF-8 encoded).
  - `salt`: `recovery_salt` (32 raw bytes).
- **Argon2id Parameters**:
  - Memory cost ($m$): $32768\text{ KiB}$ ($32\text{ MiB}$)
  - Time cost ($t$): $3\text{ iterations}$
  - Parallelism ($p$): $2\text{ lanes}$
  - Hash length: $32\text{ bytes}$
  - Version: $0x13$
- **Output**: Exactly 64 lowercase hexadecimal characters representing the 32-byte digest.
- **Storage**: Stored in Supabase `ghost_vaults.recovery_verifier` as a zero-knowledge authentication token.

### 2.5 Master Passphrase & Key Encryption Key (KEK)
- **Master Passphrase**: User-selected passphrase, minimum 16 characters enforced at input.
- **Zero-Persistence Policy**: Master passphrases exist strictly in volatile RAM and are never written to disk or transmitted.
- **KEK Derivation**:
  - **Android (Native)**: Derived via Argon2id ($m = 65536\text{ KiB}$, $t = 3$, $p = 4$, 16-byte random salt stored in local MMKV vault header).
  - **Web Companion**: Derived via Web Crypto API `PBKDF2-SHA-256` with 100,000 iterations and 16-byte random salt stored in local manifest / storage.
  - **iOS Foundation**: Designed for native Argon2id via `Clibargon2`.
- **Physical NFC Tag vs Cloud Key Storage**:
  - **Physical NFC Tags**: Store data encrypted with the 256-bit Data Encryption Key (DEK). Physical tags store ONLY the 16-byte `KEY_ID` and DEK-encrypted ciphertext. Physical tags **NEVER** store wrapped DEKs, KEKs, KDF salts, or KDF algorithm parameters.
  - **Local Storage**: Wrapped DEKs (`wrapDEK(dek, kek, keyId)`) and KEK salts are stored in local platform storage (MMKV on Android, `localStorage` on Web).
  - **Interoperability Separation**:
    1. **Recovery Credential Interoperability**: 100% interoperable across Android, Web, and iOS. All platforms share the identical 12-word BIP-39 phrase $\rightarrow$ `account_id` $\rightarrow$ `recovery_auth_secret` $\rightarrow$ deterministic `recovery_salt` $\rightarrow$ Argon2id `recovery_verifier` ($m=32768\text{ KiB}, t=3, p=2$).
    2. **Binary Envelope Wire Interoperability**: 100% compatible. Envelopes (54B v1 and 134B v2) can be parsed and decrypted by any platform **when given the raw 32-byte DEK**.
    3. **End-to-End Passphrase NFC Tag Decryption**: **NOT INTEROPERABLE** between Android and Web without shared DEK exchange. A tag written on Android cannot be decrypted on Web using only a passphrase because physical tags do not contain the DEK or salt, and Android and Web use different KDFs (Argon2id vs PBKDF2) to derive the KEK.

---

## 3. Physical NFC Envelope Formats

### 3.1 Ghost v1 Single-Tag Binary Envelope (Fixed Overhead: 54 Bytes)

Used when encrypted content fits entirely within one physical NFC tag.

#### Wire Layout (Little-Endian)
```
Offset (Bytes)   Field Name          Size (Bytes)   Description
--------------------------------------------------------------------------------------------------
00 .. 03         MAGIC               4 bytes        ASCII "GTAG" (0x47, 0x54, 0x41, 0x47)
04               FORMAT_VERSION      1 byte         0x01 (Version 1)
05               PURPOSE             1 byte         Payload purpose enum (0x01 - 0xFF)
06 .. 21         KEY_ID              16 bytes       128-bit unique Data Encryption Key ID
22 .. 33         NONCE               12 bytes       96-bit AES-256-GCM Initialization Vector
34 .. 37         CIPHERTEXT_LENGTH   4 bytes        uint32 Little-Endian payload length (N)
38 .. (38+N-1)   CIPHERTEXT          N bytes        AES-256-GCM encrypted payload
(38+N) .. (53+N) GCM_TAG             16 bytes       128-bit AES-GCM authentication tag
--------------------------------------------------------------------------------------------------
Total Fixed Overhead: 54 bytes
Total Envelope Size:  54 + N bytes
```

#### v1 Additional Authenticated Data (AAD) — Exact 26 Bytes
$$\text{AAD}_{v1} = \text{MAGIC (4B)} \mathbin{\Vert} \text{FORMAT\_VERSION (1B)} \mathbin{\Vert} \text{PURPOSE (1B)} \mathbin{\Vert} \text{KEY\_ID (16B)} \mathbin{\Vert} \text{CIPHERTEXT\_LENGTH (4B LE)}$$
- **Byte Range**: Bytes `00 .. 25` of the envelope.

---

### 3.2 Ghost v2 Bulk Distributed Binary Envelope (Fixed Overhead: 134 Bytes)

Used when files are partitioned across multiple NFC tags with optional Cauchy Reed-Solomon erasure coding.

#### Wire Layout (Little-Endian)
```
Offset (Bytes)   Field Name                 Size (Bytes)   Description
--------------------------------------------------------------------------------------------------
00 .. 03         MAGIC                      4 bytes        ASCII "GTAG" (0x47, 0x54, 0x41, 0x47)
04               FORMAT_VERSION             1 byte         0x02 (Version 2)
05               RECORD_TYPE                1 byte         0x10 (BULK_CHUNK)
06 .. 21         VAULT_ID                   16 bytes       128-bit bulk vault UUID
22 .. 37         FILE_ID                    16 bytes       128-bit file UUID
38 .. 53         KEY_ID                     16 bytes       128-bit Data Encryption Key UUID
54 .. 57         GLOBAL_CHUNK_INDEX         4 bytes        uint32 LE index across entire vault
58 .. 61         TOTAL_VAULT_CHUNKS         4 bytes        uint32 LE total chunks in vault
62 .. 65         FILE_CHUNK_INDEX           4 bytes        uint32 LE index within this file
66 .. 69         TOTAL_FILE_CHUNKS          4 bytes        uint32 LE total chunks for file (K+M)
70 .. 73         CHUNK_CIPHERTEXT_LENGTH    4 bytes        uint32 LE length of ciphertext (N)
74 .. 105        CHUNK_HASH                 32 bytes       SHA-256 digest of CHUNK_CIPHERTEXT
106 .. 117       NONCE                      12 bytes       96-bit AES-256-GCM Initialization Vector
118 .. (117+N)   CHUNK_CIPHERTEXT           N bytes        AES-256-GCM chunk ciphertext payload
(118+N) .. (133+N) GCM_TAG                  16 bytes       128-bit AES-GCM authentication tag
--------------------------------------------------------------------------------------------------
Total Fixed Overhead: 134 bytes
Total Envelope Size:  134 + N bytes
```

#### v2 Additional Authenticated Data (AAD) — Exact 74 Bytes
$$\begin{aligned}
\text{AAD}_{v2} = &\ \text{MAGIC (4B)} \mathbin{\Vert} \text{FORMAT\_VERSION (1B)} \mathbin{\Vert} \text{RECORD\_TYPE (1B)} \\
&\mathbin{\Vert} \text{VAULT\_ID (16B)} \mathbin{\Vert} \text{FILE\_ID (16B)} \mathbin{\Vert} \text{KEY\_ID (16B)} \\
&\mathbin{\Vert} \text{GLOBAL\_CHUNK\_INDEX (4B LE)} \mathbin{\Vert} \text{TOTAL\_VAULT\_CHUNKS (4B LE)} \\
&\mathbin{\Vert} \text{FILE\_CHUNK\_INDEX (4B LE)} \mathbin{\Vert} \text{TOTAL\_FILE\_CHUNKS (4B LE)} \\
&\mathbin{\Vert} \text{CHUNK\_CIPHERTEXT\_LENGTH (4B LE)}
\end{aligned}$$
- **Byte Range**: Bytes `00 .. 73` of the envelope.
- **Boundaries**: Strictly terminates at byte 73. Does **not** include `CHUNK_HASH`, `NONCE`, `CHUNK_CIPHERTEXT`, or `GCM_TAG`.

#### Chunk Hash Clarification
- **Hash Algorithm**: Full 32-byte (256-bit) SHA-256 digest. **It is NOT truncated to 16 bytes.**
- **Hash Input**: Computed strictly over the $N$ bytes of `CHUNK_CIPHERTEXT` (bytes `118 .. 117+N`).
- **Validation Role**: Independent pre-authentication integrity check. Verified before caching or matrix reassembly. Tampered chunks fail hash verification immediately with `CHUNK_HASH_MISMATCH`.

---

## 4. NDEF Framing & NFC Tag Storage

### 4.1 MIME Types
- **Single-Tag Vaults (v1)**: `application/vnd.ghost.secure`
- **Bulk Distributed Vaults (v2)**: `application/vnd.ghost.bulk`

### 4.2 NDEF Record Structure
Both envelope types are wrapped inside a standard NFC Forum NDEF MIME record:
- **Header Flags**: `MB=1`, `ME=1`, `CF=0`, `SR=1` (for payloads $< 256\text{B}$) or `SR=0`, `IL=0`, `TNF=0x02` (MIME Media).
- **Type Length**: `0x1c` (28 bytes) for `application/vnd.ghost.secure` or `0x1a` (26 bytes) for `application/vnd.ghost.bulk`.
- **Payload Length**: Exact envelope size ($54 + N$ or $134 + N$).
- **Payload**: Raw binary envelope bytes starting with `GTAG`.

### 4.3 Type 2 Tag Layout & Capacity Table
Encapsulated inside an NFC Forum Type 2 NDEF Message TLV (`0x03` [len] [payload] `0xFE`).

| Tag Model | IC Type | Total EEPROM | Usable NDEF Capacity | Single-Tag Usable Payload ($N$) | Bulk-Tag Usable Payload ($N$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **NTAG213** | NXP NTAG213 | 180 Bytes | 144 Bytes | `52B` (`TagInfo.ts`) / `56B` (`apdu.js`) | **Incompatible (`0B`, `fits: false`)** |
| **NTAG215** | NXP NTAG215 | 540 Bytes | 504 Bytes | `404B` (`TagInfo.ts`) / `411B` (`apdu.js`) | `326B` (`TagInfo.ts`) / `333B` (`apdu.js`) |
| **NTAG216** | NXP NTAG216 | 924 Bytes | 888 Bytes | `784B` (`TagInfo.ts`) / `795B` (`apdu.js`) | `706B` (`TagInfo.ts`) / `717B` (`apdu.js`) |

---

## 5. Chunk Cache Architecture

1. **Storage Medium**: **Volatile in-memory `Map` only.** There is **NO disk persistence**, NO SQLite storage, and NO AsyncStorage persistence of scanned chunks.
2. **Payload Protection**: Chunks stored in RAM are stored in their **raw encrypted ciphertext format** (`Uint8Array`) as read from the NFC chip.
3. **72-Hour TTL**: Each cached chunk record is assigned `expiresAt = Date.now() + 259200000` (72 hours). Chunks exceeding this time are purged by `purgeExpiredChunks()`.
4. **App Restart / Process Exit**: When the application process terminates, the in-memory cache is immediately destroyed.
5. **Data Loss Safety**: Cache expiration or clearance does **NOT** cause data loss because original data resides permanently on the physical NFC tags.

---

## 6. Cauchy Reed-Solomon Erasure Coding

1. **Galois Field**: $\mathrm{GF}(2^8)$ with primitive irreducible polynomial $p(x) = x^8 + x^4 + x^3 + x^2 + 1$ (`0x11d`).
2. **Generator Matrix**: Cauchy matrix construction:
   $$A_{i,j} = \frac{1}{x_i \oplus y_j}$$
   where $x_i$ and $y_j$ are disjoint subsets of $\mathrm{GF}(2^8)$.
3. **Reconstruction Rule**: Any $K$ unique chunks out of $K + M$ total shards can reconstruct the original ciphertext.
4. **Padding & Truncation**: When chunk sizes are not exact multiples of $K$, original lengths are tracked in `BulkFileRecord.chunkOriginalLengths` and trimmed to `ciphertextSizeBytes`.

---

## 7. Supabase Cloud Sync & Zero-Knowledge Protocol

### 7.1 Opt-in Zero-Knowledge Metadata Storage
- Cloud synchronization is **strictly opt-in**. The system operates 100% offline by default.
- When enabled, Supabase stores **strictly encrypted vault metadata** (`encrypted_metadata`).
- Plaintext files, passphrases, recovery phrases, and Data Encryption Keys are **NEVER** sent to Supabase.

### 7.2 Production v2.1.0 Challenge-Response Recovery (`POST /functions/v1/recover-vault`)
- **Precondition**: Caller passes Cloudflare Turnstile (`POST /functions/v1/verify-captcha`), receiving a short-lived HMAC verification token.
- **Step 1 (Challenge Request)**: Client requests a recovery challenge for `account_id`. Server enforces atomic 15-minute sliding-window rate limits (via PostgreSQL `pg_advisory_xact_lock`, account/user/hashed-IP quotas) and returns single-use `{ challenge_id, nonce, server_timestamp, recovery_salt }` (or uniform anti-enumeration output).
- **Step 2 (Proof Verification)**: Client derives `recovery_auth_secret` and submits `{ account_id, challenge_id, recovery_proof (76B HMAC-SHA256 proof) }`. Edge Function validates the proof in constant time via service-role access and returns `encrypted_recovery_envelope`.
- **Table Lockdown**: Direct client read/write access to legacy `ghost_vaults` and sensitive `user_accounts` recovery columns is revoked; metadata status is restricted via `ghost_vault_status` and hardened RLS (`supabase/migrations/20261125_lockdown_ghost_vaults.sql`, `20261126_v210_account_security_schema.sql`).
- **Cloud Deployment Status**: Verified by Jest policy/security suites; live remote Supabase deployment remains pending.

---

## 8. Platform Support & Hardware Validation Status

| Platform / Subsystem | Implementation Status | Hardware Testing Status | Security / Readiness Status |
| :--- | :--- | :--- | :--- |
| **Android APK** | Full React Native + C++17 NDK | Emulator launch clean (`Medium_Phone_API_37.0`); **physical NFC pending** | Active Primary Staging Client (`v2.1.0` unreleased) |
| **Web Companion** | Vite MPA + WASM Argon2id + Web NFC | Chromium SPA showcase verified; **physical Android Chrome Web NFC pending** | Active Companion Client |
| **Desktop Ghost Bridge** | Node.js Daemon + PC/SC + PN532 Serial | Unit/WS `sessionToken` + PN532 protocol tests pass; **physical ACR122U / ESP32-PN532 pending** | Hardened (`CodeQL` alerts `#75/#76/#78` fixed) |
| **iOS Client** | Swift Cryptographic Foundation (`2.1.0`, build `7`) | PR `#25` deferred (`iOS Beta`); pending macOS build & iPhone CoreNFC test | Foundation Code / Deferred Beta |

---

## 9. Test Suite Baselines

- **Default Jest Suite (`npm test -- --ci --maxWorkers=2`)**: **26/26 suites, 347/347 tests passing** (`56.06% Stmts | 46.44% Branch | 54.67% Funcs | 57.16% Lines`).
- **PN532 Serial Protocol Suite (`npx jest desktop/test/pn532_serial.test.js`)**: **1/1 suite, 22/22 tests passing** (combined **369 tests across 27 suites**).
