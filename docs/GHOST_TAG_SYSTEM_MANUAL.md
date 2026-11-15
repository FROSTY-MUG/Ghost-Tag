# GHOST-TAG SYSTEM & CROSS-PLATFORM FALLBACK MANUAL

> **Authoritative Operational Reference, Cryptographic Specification, Platform Boundaries, and Architecture Guide**  
> *Permanent fallback document for Ghost-Tag design, cross-platform interoperability, and implementation constraints.*

---

## 1. Executive Summary & The Realistic Cross-Platform Rule

Ghost-Tag is designed as an **offline encrypted NFC file-vault and data storage system**. To maintain architectural integrity and avoid impossible hardware promises, the system strictly separates three client implementations:

1. **The Android APK** (Primary full-featured writer, vault, and background manager).
2. **The Web Companion App** (Lightweight cross-platform reader and emergency recovery client).
3. **The iOS Native App** (Core NFC mobile client using native Swift/SwiftUI).
4. **The Desktop App** (Tauri + Rust PC/SC USB-reader recovery and bulk-management client).

They share the **exact same encrypted NFC binary interchange format**, but **they cannot all have the same NFC permissions or hardware capabilities**.

### The Realistic Cross-Platform Rule
> **A tag written by the Android APK can be read by the web app or iOS app only if that platform supports NDEF reading, the user has the correct passphrase/key material, and the tag has enough accessible NDEF data.**

- **Web NFC Reality**: Web NFC in Google Chrome on Android (v89+) supports NDEF reading and writing, requires HTTPS, and is strictly limited to NDEF records; it does not guarantee raw-tag access or support on every browser.
- **iOS Reality**: iOS Safari does **not** provide the Web NFC API. A website cannot reliably replace an iOS native app for NFC reading or writing on an iPhone. Apple requires a native app utilizing the `Core NFC` framework (`NFCNDEFReaderSession`).

---

## 2. Product Definition: What Ghost-Tag Is and Is Not

### 2.1 What Ghost-Tag Is
Ghost-Tag lets a user store sensitive information on NFC tags in strongly encrypted form. The tag can be read by anyone with an NFC reader, but the stored payload is authenticated ciphertext. Without the user's master passphrase or recovery phrase, any reader observes only meaningless encrypted bytes.

**Supported Capabilities:**
- Small single-tag records (Recovery notes, credentials, configurations, asset IDs).
- Large binary files split across physical NFC tags.
- Arbitrary file types: text (`.txt`, `.md`, `.json`, `.csv`), images (`.jpg`, `.png`, `.webp`, `.heic`), videos (`.mp4`, `.mov`, `.webm`), audio (`.mp3`, `.wav`), documents (`.pdf`, `.docx`, `.xlsx`), archives (`.zip`, `.7z`), or any binary stream.
- Multiple files in one bulk vault.
- Random-order physical scanning of tags.
- Temporary encrypted caching with strict 72-hour TTL.
- In-app viewing and scoped export via Storage Access Framework (SAF).
- Disaster recovery on any new device through a 24-word BIP39 recovery phrase.

### 2.2 What Ghost-Tag Is NOT (Strict Non-Goals)
To preserve technical credibility and ethical boundaries, Ghost-Tag **never claims**:
- A replacement for hardware protocol tools like Proxmark3 or Flipper Zero.
- An NFC cloner, protocol sniffer, or card emulation utility.
- A universal RFID hacking or penetration-testing tool.
- A cloud synchronization or cloud storage service.
- A system that prevents physical tag copying, cloning, or deletion (if an adversary clones a tag, they duplicate ciphertext they cannot decrypt).
- A system that protects plaintext data on a compromised, rooted, or unlocked phone.
- A public-key infrastructure (PKI) or multi-user sharing service in the MVP.
- A system that provides silicon-level forensic erasure across all flash geometries.

---

## 3. Real-World Use Cases & Core Purposes

### 3.1 Targeted Scenarios
Ghost-Tag is engineered for personal offline encrypted storage:
- **Student**: Carrying encrypted study notes or research data physically.
- **Developer**: Carrying an air-gapped server recovery key or WireGuard profile.
- **Individual**: Carrying emergency medical contacts or family instructions physically.
- **Small Business**: Storing confidential asset, hardware, or inventory serial numbers.
- **Photographer**: Carrying encrypted project metadata or client contracts.
- **Backup Enthusiast**: Storing an encrypted archive split across a set of physical NFC tags.
- **Physical "Encrypted USB Stick" Alternative**: Using cheap, battery-less, physical NFC tags as confidential offline storage.

### 3.2 Core Purposes Matrix

| Purpose | What Ghost-Tag Does |
| :--- | :--- |
| **Confidential Storage** | Encrypts file data with AES-256-GCM before writing to NFC tags. |
| **Integrity Protection** | Detects modified, corrupted, or tampered ciphertext via 16-byte GCM tags and SHA-256 chunk hashes. |
| **Offline Access** | Operates 100% offline without servers, telemetry, or network access. |
| **Portable Storage** | Stores encrypted fragments on ubiquitous physical NFC tags (NTAG21x, MIFARE Ultralight). |
| **Large-File Support** | Splits encrypted files into chunks distributed across multiple physical tags. |
| **Random-Order Recovery** | Reassembles chunks regardless of physical scanning sequence. |
| **Cross-Platform Interoperability** | Uses a unified Little-Endian NDEF interchange format readable across Android, Web, and iOS. |
| **Disaster Recovery** | Allows recovery of vault keys on a new device using a 24-word BIP39 recovery phrase. |
| **Temporary Cache** | Prevents rescanning recently scanned tags using a 72-hour TTL offline cache. |
| **Secure Export** | Allows users to save reassembled files to storage via scoped SAF picker. |

---

## 4. End-to-End User Operational Flows

### 4.1 First-Time Setup
```
1. Install Ghost-Tag (APK / Native App)
2. Create Master Passphrase (minimum 16 characters)
3. Generate and record 24-word BIP39 Recovery Phrase offline (paper/steel)
4. Confirm Recovery Phrase words
5. Create Vault
6. Add files or text records
7. Select target NFC tags
8. Write encrypted chunks to tags
9. Keep physical tags safe
```
*Rule*: The passphrase is the primary root secret; the recovery phrase is the emergency backup. Neither is ever persisted in plaintext or sent over any network.

### 4.2 Writing a Bulk File Vault (With Extra-Tag Exclusion)
```
1. Open Ghost-Tag -> Select "New Bulk Vault"
2. Choose one or more files via SAF picker
3. App calculates total encrypted size (including 134-byte chunk overhead)
4. App detects usable NFC capacity per tag:
   usable_capacity = tag_user_memory - TLV_overhead - record_overhead - envelope_overhead - safety_margin
5. App calculates required tag count: required_tags = ceil(total_encrypted_size / usable_capacity)
6. App prompts user with tag requirements and Extra-Tag Exclusion Rule:
   "Only 86 tags are required. Please set aside the other 14 tags. Scan 86 blank compatible tags one by one."
7. User confirms. App strictly refuses to write to surplus tags.
8. User taps blank compatible tags one by one.
9. App writes one encrypted chunk per tag.
10. App reads each tag back and verifies GCM tag and SHA-256 chunk hash.
11. App marks the bulk vault as complete and ready.
```

### 4.3 Reading and Scanning Tags (Random-Order Reassembly)
```
1. Open Ghost-Tag -> Select "Scan Bulk Vault"
2. Tap tags one by one in ANY random physical order
3. App reads each encrypted chunk via foreground NFC dispatch
4. App parses 134-byte envelope, verifies AAD, and checks for duplicates
5. App stores validated chunks in local encrypted cache (72-hour TTL)
6. Real-time counter tracks collected vs required chunks
7. When K chunks are collected (or solved via Cauchy Reed-Solomon), app concatenates ciphertext
8. App verifies SHA-256 against vault manifest
9. App decrypts file using Vault DEK
10. User previews or exports reconstructed file
```

### 4.4 Viewing, Exporting, and Disposable Zeroization
- **Text**: In-app secure text viewer or file export.
- **Image**: In-app viewer or file export.
- **Video**: In-app player or file export.
- **PDF**: In-app viewer or scoped system document viewer.
- **ZIP / Binary**: Export only via SAF picker.
- *Cleanup Rule*: The app immediately zeroes out temporary plaintext buffers and deletes temporary decrypted cache files after viewing or export unless explicitly retained by the user.

---

## 5. Universal Interchange Format: Shared Binary Specification

Every platform (Android, Web, iOS, Desktop) **must** implement this identical specification.

```
NFC TAG
  └── NDEF Message
        └── NDEF MIME Record: "application/vnd.ghost.bulk" (or "application/vnd.ghost.secure")
              └── Payload: Little-Endian Encrypted Binary Envelope
```

### 5.1 NDEF MIME Types
- Bulk Distributed Vaults: `application/vnd.ghost.bulk`
- Single-Tag Envelopes: `application/vnd.ghost.secure`

### 5.2 Bulk Binary Envelope Wire Format (v2 — 134 Bytes Fixed Overhead)
All integer fields are encoded in **Little-Endian (LE)** byte order:

| Offset (Bytes) | Field Name | Type / Size | Description |
| :--- | :--- | :--- | :--- |
| `00..03` | `MAGIC` | 4 bytes (ASCII) | Fixed ASCII `"GTAG"` (`0x47, 0x54, 0x41, 0x47`) |
| `04` | `FORMAT_VERSION` | `uint8` (1 byte) | Format version (starts at `0x01`) |
| `05` | `RECORD_TYPE` | `uint8` (1 byte) | `0x01`=Data Chunk, `0x02`=Parity Chunk (Reed-Solomon) |
| `06..21` | `VAULT_ID` | 16 bytes | 128-bit UUID of the parent Bulk Vault |
| `22..37` | `FILE_ID` | 16 bytes | 128-bit UUID of the specific file |
| `38..53` | `KEY_ID` | 16 bytes | 128-bit DEK identifier |
| `54..57` | `GLOBAL_CHUNK_INDEX`| `uint32` LE (4B) | Global chunk index across entire vault |
| `58..61` | `TOTAL_VAULT_CHUNKS`| `uint32` LE (4B) | Total number of chunks in entire vault |
| `62..65` | `FILE_CHUNK_INDEX` | `uint32` LE (4B) | Chunk index within this specific file |
| `66..69` | `TOTAL_FILE_CHUNKS` | `uint32` LE (4B) | Total chunks comprising this specific file |
| `70..73` | `CIPHERTEXT_LENGTH` | `uint32` LE (4B) | Length of ciphertext in bytes ($C$) |
| `74..105`| `CHUNK_HASH` | 32 bytes | SHA-256 hash of this chunk's ciphertext |
| `106..117`| `NONCE` | 12 bytes | 96-bit AES-256-GCM CSPRNG IV (never reused) |
| `118..118+C-1`| `CHUNK_CIPHERTEXT` | $C$ bytes | AES-256-GCM encrypted chunk payload |
| `118+C..118+C+15`| `GCM_TAG` | 16 bytes | 128-bit AES-256-GCM authentication tag |

$$\text{Fixed Overhead} = 134 \text{ bytes}$$

### 5.3 Additional Authenticated Data (AAD) Binding
To prevent cross-vault splicing, chunk swapping, or truncation, the AES-GCM tag authenticates **74 bytes of AAD**:
$$\text{AAD} = \text{MAGIC (4B)} \;||\; \text{VERSION (1B)} \;||\; \text{RECORD\_TYPE (1B)} \;||\; \text{VAULT\_ID (16B)} \;||\; \text{FILE\_ID (16B)} \;||\; \text{KEY\_ID (16B)} \;||\; \text{GLOBAL\_INDEX (4B)} \;||\; \text{TOTAL\_VAULT (4B)} \;||\; \text{FILE\_INDEX (4B)} \;||\; \text{TOTAL\_FILE (4B)} \;||\; \text{LENGTH (4B)}$$

### 5.4 Compatibility & Rejection Rule
A client must reject unknown future versions rather than guessing:
```text
if (envelope.format_version > CURRENT_SUPPORTED_VERSION) {
    throw new GhostTagError("This tag uses a newer Ghost-Tag format. Please update the application.");
}
```

---

## 6. Cryptographic Architecture & Key Hierarchy

```
User Master Passphrase (>= 16 characters)
   │
   ▼
Argon2id (RFC 9106: 128-bit salt, 64MB memory, 3 iterations, 4 threads)
   │
   ▼
Key-Encryption Key (KEK) [256-bit, Volatile Memory Only]
   │
   ├──► Wrapped Vault DEK (AES-256-GCM under KEK, 12B nonce, AAD bound)
   │       └── Unwraps to DEK [256-bit random bytes] ──► Encrypts File Ciphertexts
   │
   └──► Recovery Wrapped Vault DEK
           └── Wrapped under Recovery KEK (Argon2id derived from 24-Word BIP39 Secret)
```

### 6.1 Cryptographic Standards
- **Symmetric Cipher**: AES-256 in Galois/Counter Mode (GCM).
- **IV / Nonce**: 96-bit (12 bytes) from a cryptographically secure pseudo-random number generator (CSPRNG). Never reused under the same key.
- **Authentication Tag**: 128-bit (16 bytes) GCM tag.
- **Password KDF**: Argon2id (RFC 9106) with unique 16-byte random salt per vault.
- **Payload & Chunk Hashes**: SHA-256 (32 bytes).
- **Key Zeroization**: All volatile key buffers are overwritten with `0x00` immediately after use with compiler memory barriers (`asm volatile("" : : "r"(ptr) : "memory")`).

---

## 7. Platform Implementations & NFC Realities

```
                         ┌──────────────────────────┐
                         │   Ghost-Tag NFC Tags     │
                         │  Encrypted NDEF Chunks   │
                         └────────────┬─────────────┘
                                      │
         ┌────────────────────────────┼────────────────────────────┐
         ▼                            ▼                            ▼
┌──────────────────┐        ┌──────────────────┐        ┌──────────────────┐
│   Android APK    │        │  iOS Native App  │        │  Ghost-Tag Web   │
├──────────────────┤        ├──────────────────┤        ├──────────────────┤
│ • Full NFC R/W   │        │ • Core NFC       │        │ • Browser client │
│ • Primary Vault  │        │ • Swift / UIKit  │        │ • Chrome Android │
│ • Foreground     │        │ • NFCNDEFSession │        │   Web NFC only   │
│   dispatch       │        │ • Keychain / TEE │        │ • Companion view │
└──────────────────┘        └──────────────────┘        └──────────────────┘
```

### 7.1 Android APK (Primary Client & Full Writer)
- **Role**: Primary full-featured writer, vault manager, and bulk scanner.
- **Capabilities**: Full NFC reading and writing, foreground dispatch (`enableForegroundDispatch`), bulk multi-tag sharding, 72h offline cache, native C++ security core (`ptrace` anti-debug, `mlock` page locking, Frida detection), `FLAG_SECURE` window protection, hardware-backed KeyStore TEE.
- **Distribution**: Direct APK installation, signed GitHub releases, optional Play Store.

### 7.2 Web App (Universal Companion & Reader)
- **Role**: Lightweight companion. Reads and decrypts tags on supported browsers; acts as viewer, exporter, and emergency recovery tool.
- **Web NFC Support Matrix**:

| Browser / Platform | NFC Read | NFC Write | Recommended Role |
| :--- | :--- | :--- | :--- |
| **Android Chrome (v89+)** | Yes (if device has NFC) | Yes (if device has NFC) | Web NFC Companion Client |
| **Android Firefox** | Not Guaranteed | Not Guaranteed | Show unsupported capability warning |
| **iOS Safari / Chrome** | **No** (No Web NFC API) | **No** (No Web NFC API) | Recovery, preview, export only |
| **Desktop Chrome / Safari** | Usually No Hardware | Usually No Hardware | Recovery, preview, export only |

- **Browser Detection Pattern**:
```javascript
if (!('NDEFReader' in window)) {
    displayBanner("This browser does not support Web NFC. On iPhone, use the Ghost-Tag iOS app. On Android, use Chrome or the native APK.");
}
```
- **Web Security Model**: The web app must **never** become the primary long-term key vault. It stores encrypted chunks in IndexedDB (72h TTL) and requires the passphrase fresh in each session. Plaintext or raw keys are never written to `localStorage` or `IndexedDB`.

### 7.3 iOS Native App (Apple Core NFC Client)
- **Role**: iPhone equivalent of the Android APK. Must be a native Swift/SwiftUI application using `Core NFC` (`NFCNDEFReaderSession`).
- **NFC Session Architecture**:
  - Must initialize session with `invalidateAfterFirstRead = false` to allow non-stop bulk scanning across multiple tags.
  - Queries tag status via `queryNDEFStatus` before writing to verify read/write permission and capacity.
  - Writes records via `writeNDEF`.
- **iOS Constraints**: User-initiated only (modal system sheet); no background tag dispatch; raw protocol access is restricted; iPhone must support NFC reading (`NFCNDEFReaderSession.readingAvailable`).
- **Distribution Options**:
  - Free Apple ID + Xcode: Personal testing (7-day provisioning).
  - Paid Apple Developer Program + Xcode: Long-term personal native installation.
  - TestFlight / Ad Hoc / App Store.

### 7.4 Desktop App (Tauri + Rust PC/SC)
- **Role**: Bulk-vault manager, file importer/exporter, and USB NFC reader client.
- **Stack**: Tauri frontend + Rust backend using the `pcsc` crate for PC/SC smart-card readers (e.g., ACR122U).

---

## 8. Cross-Platform Data Flows

```
[Flow 1: Android Writes -> Web Reads]
Android APK (Encrypted chunks written to tags)
  └── User taps tag to phone running Chrome on Android
        └── Web App reads NDEF record via Web NFC
              └── Enters Passphrase -> Reconstructs -> Decrypts -> Downloads

[Flow 2: Web Writes -> Android Reads]
Web App on Android Chrome (Encrypts file & writes NDEF tags)
  └── User opens Android APK
        └── Android APK foreground dispatch scans tags
              └── Reassembles Cauchy RS matrix -> Decrypts -> Views in-app

[Flow 3: Android Writes -> iOS Reads]
Android APK (Encrypted chunks written to tags)
  └── User opens iOS Ghost-Tag app -> Core NFC session
        └── Scans tags -> Caches chunks -> Reconstructs -> Exports via Share Sheet

[Flow 4: iOS Writes -> Android Reads]
iOS Ghost-Tag app (Writes encrypted NDEF chunks via writeNDEF)
  └── User opens Android APK
        └── Android APK scans tags -> Verifies GCM auth tags -> Decrypts file
```

---

## 9. Required Cross-Platform Verification Test Matrix

Every production release must be validated against this test matrix:

| Writer Client | Reader Client | Expected Result |
| :--- | :--- | :--- |
| **Android APK** | **Android APK** | Full read, random-order reassemble, decrypt |
| **Android APK** | **Web App (Android Chrome)** | Full read via Web NFC, decrypt, download |
| **Android APK** | **iOS App (Core NFC)** | Full read, reassemble, decrypt, export |
| **Android APK** | **Desktop App (ACR122U)** | Full read via PC/SC, decrypt, save |
| **Web App (Android Chrome)** | **Android APK** | Full read, reassemble, decrypt |
| **Web App (Android Chrome)** | **iOS App (Core NFC)** | Full read, reassemble, decrypt |
| **iOS App (Core NFC)** | **Android APK** | Full read, reassemble, decrypt |
| **iOS App (Core NFC)** | **Web App (Android Chrome)** | Full read via Web NFC, decrypt |
| **Desktop App (Tauri/Rust)** | **Android APK** | Full read, reassemble, decrypt |
| **Desktop App (Tauri/Rust)** | **Web App (Android Chrome)** | Full read via Web NFC, decrypt |

### Edge Cases & Negative Tests
1. **Wrong Passphrase**: Throws `PASSPHRASE_INVALID`. Zero plaintext or key leaked.
2. **Missing Tag (No Redundancy)**: Reassembly halted; identifies missing chunk index.
3. **Missing Tag (With Reed-Solomon Redundancy)**: Solves missing chunks via Cauchy matrix over $\text{GF}(2^8)$ and recovers file.
4. **Corrupted Tag**: AES-256-GCM authentication fails immediately (`AEAD_TAG_MISMATCH`). Corrupted tag rejected.
5. **Duplicate Tag**: Rejected cleanly without state mutation or counter increment.
6. **Foreign Tag**: Non-Ghost-Tag NDEF records ignored (`NOT_GHOST_TAG_ENVELOPE`).
7. **Cache Expiry**: Cached chunks older than 72 hours are purged automatically (`CACHE_EXPIRED`).
8. **Interrupted Scan**: Cached chunks remain valid in encrypted storage; user can resume scanning hours or days later.

---

## 10. Implementation Roadmap & Staged Phases

1. **Phase 1: Android MVP (Completed & Stable)**:
   - Signed Android Release APK (`ghost-tag-v2.0.0.apk`).
   - Single-tag v1 vault (54B envelope) and Bulk v2 vault (134B envelope).
   - Arbitrary binary file support, SAF picker, random-order scanning, 72h cache.
   - Native C++ security core (`ptrace`, `mlock`, Frida scan), `FLAG_SECURE`, KeyStore TEE.
2. **Phase 2: Web Companion (Completed & Active)**:
   - Responsive cyber-brutalist web showcase at `web/`.
   - In-browser WebCrypto AES-GCM engine, Cauchy Reed-Solomon simulator over $\text{GF}(2^8)$.
   - Hardware Web NFC API integration for Chrome on Android.
   - IndexedDB encrypted caching and clear browser-capability disclosures.
3. **Phase 3: iOS Native App**:
   - Native Swift/SwiftUI app using `Core NFC` (`NFCNDEFReaderSession`).
   - `invalidateAfterFirstRead = false` bulk scanning.
   - iOS Keychain and Face ID biometric unlock.
4. **Phase 4: Desktop Companion**:
   - Tauri + Rust application with PC/SC reader support (ACR122U).

---

## 11. User-Facing Core Axiom
> **"Ghost-Tag tags are cross-platform. Android and iPhone native apps can read and write them. The website can read and write them only in browsers that support Web NFC; on iPhone, use the native Ghost-Tag app for NFC."**
