# Ghost-Tag Security Model (`v2.1.0`)

## 1. Cryptographic Primitives & Key Derivation

| Component | Algorithm & Parameters | Scope |
| :--- | :--- | :--- |
| **Primary Vault KEK (Native)** | Argon2id RFC 9106 (`16 MiB` Low-End, `32 MiB` Standard, `64 MiB` High-End; `16B` CSPRNG salt) | Derives 256-bit KEK from Master Passphrase |
| **Cloud Recovery Auth / Verifier** | Two-stage Argon2id (`m=32768 KiB`, `t=3`, `p=2`, `h=32B`, `v=0x13`) + server CSPRNG `32B` `recovery_salt` | Android, Edge Functions, and Web offline WASM (`hash-wasm`) |
| **Local Recovery KEK** | Argon2id RFC 9106 (`65536 KiB`, `t=5`, `p=4`, `32B` salt) | Unwraps local recovery DEK envelope (`RecoveryManager`) |
| **Authenticated Encryption** | AES-256-GCM (`12B` CSPRNG nonce, `16B` constant-time tag) | Payload encryption & 19B-AAD DEK key wrapping |
| **Erasure Coding** | Cauchy-Vandermonde Reed-Solomon over $\mathrm{GF}(2^8)$ (`0x11d`) | Tolerates up to $M$ missing/damaged bulk tags |

## 2. Volatile Chunk Cache vs Zero Disk Leakage
- `ChunkCacheManager` caches **encrypted** chunk ciphertext in a volatile in-memory `Map` (never plaintext SQLite/disk) with a strict `72-hour` (`259,200,000 ms`) TTL.
- Native Android security layers (`FLAG_SECURE`, `AndroidKeyStore` TEE/StrongBox, C++ `mlock()`, `ptrace` anti-debug, `/proc/self/maps` hook scan, and 4-pass memory wipe with compiler barriers) defend active volatile keys.

## 3. Supabase RLS Lockdown & Challenge-Proof Recovery
- Direct client access to `ghost_vaults` and sensitive `user_accounts` columns is revoked (`20261125_lockdown_ghost_vaults.sql`, `20261126_v210_account_security_schema.sql`).
- `recover-vault` enforces Cloudflare Turnstile verification (`verify-captcha`), atomic 15-minute advisory-locked rate limits, anti-enumeration uniform error shapes, and `76B` HMAC challenge/proof checks.

See [`../../SECURITY.md`](../../SECURITY.md) and [`../../FAQ.md`](../../FAQ.md).
