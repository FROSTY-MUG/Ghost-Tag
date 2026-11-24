# Ghost-Tag Security Architecture & Cryptographic Threat Model

Ghost-Tag is engineered around a zero-trust, zero-telemetry, offline-first security paradigm. This document details the cryptographic specifications, key derivation, memory hygiene, and adversary threat boundaries.

---

## 1. Zero-Secrets Policy

1. **Local-First & Zero-Knowledge Architecture**: Ghost-Tag operates offline by default and never requires network connectivity. When optional Supabase cloud sync is configured, it stores strictly an authenticated, encrypted vault metadata blob. Passphrases, recovery phrases, keys, unencrypted files, and NFC payloads are never transmitted.
2. **Volatile Key Lifecycle**: Key-Encryption Keys (KEKs) and Data-Encryption Keys (DEKs) are instantiated in ephemeral runtime memory and wiped upon vault locking or session termination.
3. **No Unencrypted Persistence**: Local vault metadata (stored in browser `localStorage` or Android MMKV) holds only salts, wrapped keys, and nonces. A lost or inspected host device reveals no plaintext without the master passphrase.

---

## 2. Cryptographic Algorithms & Invariants

### 2.1 Authenticated Encryption
- **Algorithm**: AES-256-GCM (Galois/Counter Mode).
- **Key Length**: 256 bits (32 bytes).
- **IV / Nonce**: 96 bits (12 bytes) sourced from a cryptographically secure random number generator (`crypto.getRandomValues()` on Web, `SecureRandom` on Android).
- **Authentication Tag**: 128 bits (16 bytes) verified prior to any plaintext release.
- **Additional Authenticated Data (AAD)**: 26 bytes including envelope magic, format version, purpose byte, key identifier, and Little-Endian length field.

### 2.2 Key Derivation Function (KDF)
- **Web & Mobile Canonical KDF**: Argon2id (RFC 9106, version `0x13`) with memory cost $m=32768\,\text{KiB}$ ($32\,\text{MB}$), iteration count $t=3$, parallelism $p=2$, 32-byte key output, and CSPRNG salt (`argon2.umd.min.js` on Web; native Argon2id module on Android).

---

## 3. Adversarial Threat Model

```
+-----------------------------------+-----------------------------------+-----------------------------------+
| Adversary                         | Adversary Capability              | Ghost-Tag Defense / Invariant     |
+-----------------------------------+-----------------------------------+-----------------------------------+
| Physical Tag Finder               | Can scan tag with any NFC phone   | Sees only authenticated ciphertext|
|                                   | or Proxmark3.                     | bytes. Cannot decrypt without KEK.|
+-----------------------------------+-----------------------------------+-----------------------------------+
| RF Frame Sniffer                  | Intercepts wireless NFC frames    | Eavesdrops only 12B IV, 16B tag,  |
|                                   | during active transmission.       | and ciphertext envelope.          |
+-----------------------------------+-----------------------------------+-----------------------------------+
| Malicious Overwriter / Tamperer   | Alters arbitrary bytes on EEPROM  | AES-256-GCM authentication tag    |
|                                   | or flips bits in payload.         | fails; corrupted data is rejected.|
+-----------------------------------+-----------------------------------+-----------------------------------+
| Tag Cloner                        | Clones entire EEPROM to blank tag | Ciphertext clone remains unreadable|
|                                   | or emulator (e.g. Flipper Zero).  | without master credentials.       |
+-----------------------------------+-----------------------------------+-----------------------------------+
| Compromised Host Operating System | Root keylogger or live memory     | Out of scope. Physical host OS    |
|                                   | inspection tool.                  | compromise cannot be mitigated.   |
+-----------------------------------+-----------------------------------+-----------------------------------+
```

---

## 4. Elimination of Scanned-Chunk Cache

In accordance with Ghost-Tag security invariants, scanned chunks reside exclusively in volatile session memory during an active read/decrypt session:
- No chunks or plaintext fragments are persisted to IndexedDB, MMKV, `localStorage`, or disk caches.
- Volatile session memory is scrubbed immediately upon session completion or when the user invokes `Clear Temporary Data`.
- The elimination of persistent chunk caching prevents physical forensics or shared browser profiles from recovering historical ciphertext fragments.
