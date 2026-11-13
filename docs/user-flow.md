# Ghost-Tag End-to-End User & Operational Flow

This guide details the complete user experience and behind-the-scenes state transitions for every workflow in Ghost-Tag.

---

## 1. Onboarding & Threat Model Disclosure Flow

When launching Ghost-Tag for the first time:

1. **Disclosure Screen**:
   - The user is presented with the honest security model:
     - *What Ghost-Tag is*: Offline encrypted NFC vault for sensitive fragments.
     - *What Ghost-Tag is not*: Not a cloner, not a Proxmark replacement, cannot prevent physical tag copying or compromised OS attacks.
   - User must acknowledge: *"If both passphrase and recovery phrase are lost, data is permanently unrecoverable."*
2. **Master Passphrase Setup**:
   - Minimum 16 characters enforced.
   - Live entropy estimation encouraging long passphrases over complex single words.
   - Confirmation entry ensures no typographical errors.
3. **Hardware KDF Calibration**:
   - Ghost-Tag runs `benchmarkDevice()` to select the optimal Argon2id memory and iteration work factors targeting 500–1,000 ms unlock latency.
4. **24-Word Recovery Phrase Generation**:
   - 256 bits of CSPRNG entropy are encoded into 24 BIP39 words.
   - Displayed once with a strict instruction to write it down offline.
   - User confirms random words (e.g., Word #4, #12, #19) to ensure paper recording.
   - Recovery envelope is compiled and secured in local storage.

---

## 2. Daily Unlock Flow

```
[UI] User opens Ghost-Tag -> Prompts for Passphrase
  |
[Argon2id] Derives ephemeral KEK (500 - 1000ms)
  |
[Vault] Manifest HMAC verified & test DEK unwrap attempted
  |-- Success -> VaultSession opened (auto-locks in 5 min)
  |-- Failure -> Throws PASSPHRASE_INVALID (no details leaked)
```

1. User enters master passphrase.
2. Argon2id derives the ephemeral 256-bit KEK using stored salt and calibrated parameters.
3. Vault unwrap test succeeds $\rightarrow$ Transitions to Scanner Screen.
4. **Auto-Lock**: If the device is idle for 5 minutes or the user switches apps (AppState enters background), the session locks and volatile KEK buffers are immediately zeroized.

---

## 3. Tag Scan & Decrypt Flow

```
[Terminal Status Progression]
[SCAN] TAG DETECTED: NTAG215 (UID: 04:A1:B2:...)
[TECH] ISO 14443-3A / Type 2 Confirmed
[NDEF] Reading NDEF message blocks...
[PARSE] GHOST-TAG ENVELOPE FOUND (v1, NOTE, KeyID: 8f9b2c...)
[KEY] Resolving DEK from Vault... ACTIVE
[CRYPTO] AES-256-GCM Verified (Tag Authentic)
[RESULT] Decryption Successful!
```

1. User taps NFC tag against phone back.
2. Android foreground dispatch captures tag intent.
3. `TagReader` extracts the `application/vnd.ghost.secure` NDEF record.
4. `parseEnvelope()` verifies `GTAG` magic and schema version `0x01`.
5. Key ID (`16B`) is checked against local vault:
   - If vault is locked $\rightarrow$ prompts for passphrase unlock.
   - If key belongs to another vault $\rightarrow$ displays `KEY_NOT_FOUND`.
6. Ephemeral KEK unwraps the target DEK.
7. AES-256-GCM authenticates AAD and decrypts ciphertext.
8. Plaintext is rendered to secure viewing buffer.
9. **Ephemeral Zeroization**: DEK buffer is zeroized immediately. Plaintext view auto-blurs when app loses focus.

---

## 4. Tag Write & Read-Back Verification Flow

```
[Terminal Status Progression]
[WRITE] Preparing payload (84 bytes)...
[TAG] Tag Detected: NTAG215 (Available: 404 bytes)
[CAPACITY] Capacity Verified (84B < 404B)
[CRYPTO] AES-256-GCM Encrypted (DEK Generated & Wrapped)
[NFC] Transmitting NDEF blocks... Complete
[VERIFY] Initiating independent read-back...
[VERIFY] Comparing GCM tag & payload bytes... Match!
[RESULT] WRITE_VERIFIED
```

1. User selects purpose (`NOTE`, `CREDENTIAL`, `CONFIG`, `ASSET_ID`) and enters payload.
2. Editor displays real-time capacity indicator.
3. User confirms write and holds tag against the phone.
4. `TagWriter` generates fresh DEK (or selects active key), fresh 12B nonce, and constructs canonical envelope.
5. NDEF message is transmitted to tag memory.
6. **Mandatory Read-Back**: `verifyWrite()` re-reads the entire NDEF container from the physical tag and verifies byte-for-byte matching of key ID, nonce, ciphertext, and GCM tag.
7. Only after verification succeeds is `WRITE_VERIFIED` displayed. If communication dropped midway, `WRITE_UNVERIFIED` is flagged.

---

## 5. Destructive Tag Sanitization (Wipe) Flow

```
[Terminal Status Progression]
[WIPE] Safety Check: NTAG215 Writable User Pages 4 .. 129
[WIPE] Pass 1: Writing zeros (0x00) across 126 user pages...
[WIPE] Pass 2: Overwriting with CSPRNG random entropy...
[WIPE] Pass 3: Formatting blank NDEF container (0x03 0x00 0xFE)...
[VERIFY] Reading back user memory... Verified clean.
[RESULT] WIPE_COMPLETE
```

1. User navigates to Wipe Screen.
2. Screen displays the mandatory honesty disclaimer:
   > *"This operation overwrites writable user memory and verifies the result. It does not guarantee recovery-proof erasure at the silicon level."*
3. User must confirm twice (or type "WIPE").
4. Tag is tapped:
   - Pages 0–3 (UID, Lock bits, Capability Container) and configuration pages are preserved.
   - All user data pages (Pages 4–129 on NTAG215) are overwritten with zeros, then CSPRNG entropy.
   - Blank NDEF container is restored.
5. If transmission is interrupted during write, `WIPE_PARTIAL` is reported and no empty container is written, alerting the user to residue.

---

## 6. Emergency Recovery Flow

1. User installs Ghost-Tag on a new or replaced phone.
2. Selects "Recover Vault from 24-Word Phrase".
3. Enters the 24 BIP39 recovery words.
4. Checksum is verified.
5. Argon2id derives the dedicated Recovery KEK using the recovery envelope parameters.
6. Recovery copies of all DEKs are unwrapped.
7. User sets a new master passphrase.
---

## 7. Bulk Scanning v2: Multi-File Creation & Extra-Tag Exclusion Flow

```
[Terminal Status Progression]
[VAULT] Creating Bulk Vault: "Ops-Offline-Archive"
[FILES] 3 files selected via SAF (1 PDF, 1 Video, 1 JSON) - Total: 3.8 MB
[CALC] Encrypted size: 3,984,812 bytes
[TAGS] Tag family: NTAG215 (Usable chunk payload: 370B)
[ERASURE] Adding 10% Reed-Solomon redundancy (K=108, M=11)
[REQUIREMENT] Total tags required: 119 physical NFC tags
[PROMPT] "Only 119 tags are required. Please set aside any surplus tags."
[WRITE-SEQ] Tag 1/119 written & verified -> Tag 2/119 -> ... -> Tag 119/119
[RESULT] BULK_VAULT_READY
```

1. **File Selection**: User selects one or more arbitrary files (documents, images, videos, archives) using Android's Storage Access Framework (`ACTION_OPEN_DOCUMENT`).
2. **Encrypted Size & Tag Calculation**:
   - Total encrypted bytes are calculated including envelope overhead (134 bytes per chunk).
   - Ghost-Tag computes the required number of physical tags based on target tag family (e.g., NTAG215).
3. **Extra-Tag Exclusion Rule**:
   - If the user possesses 130 tags but only 119 are needed, the app instructs: *"Only 119 tags are required. Please set aside the other 11 tags. Scan the 119 required tags one by one."*
   - Ghost-Tag strictly refuses to write to surplus tags.
4. **Sequential Write Phase**:
   - The user taps blank compatible tags one by one.
   - For each tag: writes bulk envelope (`application/vnd.ghost.bulk`), immediately executes read-back verification, and logs progress to the crash-resilient write journal.
   - Once all required tags are written, the vault transitions to ready state.

---

## 8. Bulk Scanning v2: Random-Order Tag Scanning, 72h Cache & Reconstruction

```
[Terminal Status Progression]
[SCAN] Tag detected: Chunk #42 of 119 (File: recovery.pdf, 370B)
[CACHE] Chunk #42 authenticated & cached in offline MMKV storage
[COUNTDOWN] Cache TTL: 71h 59m remaining (Auto-purge on expiry)
[PROGRESS] Collected 94 of 108 required data chunks (87%)
...
[SCAN] Tag detected: Chunk #112 (Parity M-4) -> Solves missing chunk #14!
[RECON] All K=108 chunks available (102 original + 6 RS reconstructed)
[CRYPTO] Concatenating ciphertext -> SHA-256 matches manifest!
[DECRYPT] AES-256-GCM full-file decryption complete.
[SAF] Exported to Download/recovery.pdf -> In-memory buffers wiped.
```

1. **Random-Order Scanning**:
   - User scans physical tags in any random, arbitrary order.
   - Ghost-Tag extracts the chunk envelope, authenticates the 74-byte AAD, and checks for duplicates.
   - Duplicate tags are rejected without state mutation.
2. **72-Hour Encrypted Offline Cache**:
   - Chunks are stored in local encrypted MMKV storage with a strict 72-hour Time-To-Live (TTL).
   - Real-time countdown timer is displayed; if 72 hours elapse without completion, cached chunks are purged (`CACHE_EXPIRED`).
3. **Reconstruction Engine**:
   - Once at least $K$ valid chunks are collected for a file, Cauchy Reed-Solomon decoding solves for any missing or damaged tags using parity chunks.
   - Ciphertext chunks are concatenated and verified against the file's SHA-256 manifest hash.
   - Full file is decrypted via AES-256-GCM under the vault DEK.
4. **SAF Export & Disposable Zeroization**:
   - Original file is saved via Android Storage Access Framework (`ACTION_CREATE_DOCUMENT`).
   - Plaintext memory buffers are immediately scrubbed using 4-pass `secureWipeBuffer()`.

