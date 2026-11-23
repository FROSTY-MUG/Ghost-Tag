# Security Model & Cryptography

Ghost-Tag is architected around a strict zero-knowledge, zero-leakage threat model.

---

## 1. Cryptographic Primitives

| Primitive | Specification | Purpose |
| :--- | :--- | :--- |
| **Symmetric Cipher** | AES-256-GCM | Encrypts chunks and wrapped DEKs with AEAD authentication |
| **Nonce Generation** | 96-bit (12 bytes) CSPRNG | Unique nonce per chunk; strictly never reused |
| **Integrity Digest** | SHA-256 (32 bytes) | Verifies ciphertext chunks and full reassembled files |
| **Recovery Verifier (Canonical)** | Argon2id RFC 9106 ($m=32768$ KiB, $t=3$, $p=2$) | Memory-hard zero-knowledge recovery credential across Android, Web, and iOS (`recovery_kdf_version = 2`) |
| **Recovery Verifier (Legacy Web)** | PBKDF2-HMAC-SHA256 (10,000 iterations) | Historical recovery verifier (`recovery_kdf_version = 1`), migratable to Argon2id |
| **Local Passphrase KEK (Native)** | Argon2id RFC 9106 ($m=65536$ KiB, $t=3$, $p=4$) | Local storage key wrapping on Android native |
| **Local Passphrase KEK (Web)** | PBKDF2-HMAC-SHA256 (100,000 iterations) | Local WebCrypto storage key wrapping on Web Companion |
| **Seed Phrase Standard** | BIP-39 English | 128-bit entropy mapped to 12 words with 4-bit checksum |


---

## 2. Key Hierarchy

```text
Master Passphrase (User input, never stored)
       │
       ▼  (Argon2id or PBKDF2)
Key Encryption Key (KEK - 256 bits, in-memory only)
       │
       ▼  (Unwraps via AES-256-GCM)
Data Encryption Key (DEK - 256 bits, in-memory only)
       │
       ▼  (Encrypts chunks with unique 12B nonces)
Encrypted NFC Tag Chunks (AES-256-GCM + 16B Auth Tag)
```

---

## 3. Threat Model & Countermeasures

### Physical Tag Theft
An attacker who finds or steals your NFC tags sees only high-entropy encrypted blobs wrapped in `application/vnd.ghost.bulk`. Without your master passphrase, brute-forcing AES-256-GCM is mathematically impossible.

### Cloud Compromise (Supabase)
Supabase acts solely as an encrypted metadata synchronization relay. It stores only:
- `account_id` (UUID derived from one-way SHA-256)
- `encrypted_vault_blob` (AES-256-GCM encrypted metadata)
- `vault_version` and timestamps

The cloud server never receives or stores:
- Passphrases
- Recovery phrases
- KEK or DEK keys
- Plaintext file names, contents, or URLs
- Scanned NFC chunks

### Tag Replay & Swapping Attacks
Every chunk envelope includes:
- `vault_id` (16 bytes)
- `file_id` (16 bytes)
- `global_chunk_index` (4 bytes LE)
- Authenticated Additional Data (AAD) covering the entire header

If an attacker tries to replace Tag 3 with a tag from another vault, the AAD verification fails and the chunk is immediately rejected.

---

## 4. Elimination of Scanned-Chunk Cache

In Ghost-Tag v2.0.5, **no scanned-chunk cache exists**:
- Chunks reside strictly in volatile memory during an active scanning session.
- No chunks are written to `localStorage`, `IndexedDB`, cookies, or disk caches.
- Memory is zeroed upon session completion or user dismissal.
