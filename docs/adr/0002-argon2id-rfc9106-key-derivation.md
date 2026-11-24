# ADR 0002: RFC 9106 Argon2id for Key Derivation

## Status
**Accepted** (2026-11-13)

## Context
A physical NFC tag can be tapped and dumped in seconds by anyone with a standard smartphone. 
If user passphrases were derived with fast hashing functions (MD5, SHA-256) or memory-light algorithms (standard PBKDF2), an adversary who dumps the ciphertext could mount high-speed GPU or ASIC dictionary attacks at billions of hashes per second.

## Decision
We enforce RFC 9106 Argon2id as the canonical Key Derivation Function (KDF) across native vault KEK profiles (`16 MiB` Low-End, `32 MiB` Standard, `64 MiB` High-End) and cross-platform recovery auth/verifier derivation (`m = 32,768 KiB`, `t = 3`, `p = 2` on Android, Supabase Edge Functions, and Web offline WASM via `hash-wasm`; local Web KEK fallback uses WebCrypto PBKDF2-HMAC-SHA256 where WASM KEK is not enabled):
- **Algorithm**: Argon2id (hybrid mode combining data-independent memory access for side-channel resistance and data-dependent memory access for tradeoff resistance).
- **Parameters**: 64 MB minimum memory cost, 3 iterations, 4 parallel threads, 256-bit random salt.
- Dedicated hardware-isolated native implementation with platform fallback.

## Consequences
### Positive
- Defeats GPU and ASIC cracking rigs by exhausting on-chip memory caches.
- RFC 9106 compliance ensures interoperability and rigorous cryptographic review.
- Constant-time resistance to timing attacks.

### Negative
- Derivation takes ~200-600ms on mobile devices during unlock.
- Requires 64 MB of RAM allocation during derivation.
