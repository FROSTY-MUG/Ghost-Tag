# Ghost-Tag Cryptographic Reference Fixtures (`test-fixtures/`)

## 1. Purpose
Deterministic binary and JSON reference test vectors enabling cross-platform verification across TypeScript (`src/`), Web (`web/`), Desktop (`desktop/`), and iOS Swift scaffolding (`ios/`). Regenerated offline via [`../scripts/generate_compatibility_fixtures.js`](../scripts/generate_compatibility_fixtures.js).

## 2. Fixture Inventory

| Path | Protocol Scope | Key Invariants Tested |
| :--- | :--- | :--- |
| [`crypto/aesGcmVectors.json`](crypto/aesGcmVectors.json) | Symmetric AEAD | NIST SP 800-38D AES-256-GCM test vectors with 12B IV and 16B tag |
| [`envelopes/v1EnvelopeVectors.json`](envelopes/v1EnvelopeVectors.json) & [`envelopes/v1-reference.bin`](envelopes/v1-reference.bin) | Single-Tag `v1` | `GTAG` magic, version `0x01`, `54B` fixed overhead, `26B` AAD |
| [`envelopes/v2BulkEnvelopeVectors.json`](envelopes/v2BulkEnvelopeVectors.json) & [`envelopes/v2-bulk-reference.bin`](envelopes/v2-bulk-reference.bin) | Bulk Distributed `v2` | `GTAG` magic, version `0x02`, `RECORD_TYPE = 0x10`, `134B` overhead, `74B` AAD (`0..73`), `32B` SHA-256 `CHUNK_HASH` (`74..105`) |
| [`recovery/recoveryVectors.json`](recovery/recoveryVectors.json) | Cross-Platform Compatibility Vectors | Historical deterministic `Option A` reference vectors (`account_id`, `recovery_auth_secret`, `recovery_salt`, Argon2id `recovery_verifier` with `m=32768, t=3, p=2, h=32, v=0x13`) |

## 3. Historical Option A Vectors vs Production v2.1.0 Protocol
- [`recovery/recoveryVectors.json`](recovery/recoveryVectors.json) captures **deterministic historical v2.0.5 Option A fixtures** so `crossPlatformCryptoCompatibility.test.ts` can verify byte-identical Argon2id and binary envelope parity across TypeScript and WebAssembly.
- **Production v2.1.0 Supabase recovery** does **not** use phrase-derived salts: [`../supabase/functions/account-auth/`](../supabase/functions/account-auth/index.ts) generates a **server-random 32-byte CSPRNG `recovery_salt`**, derives keys with two-stage Argon2id, and verifies interactive **`76B` HMAC challenge proofs** (`recover-vault`) tested in [`../src/__tests__/recoveryChallengeProof.test.ts`](../src/__tests__/recoveryChallengeProof.test.ts).

See [`../FAQ.md`](../FAQ.md) and [`../docs/CANONICAL-SPECIFICATION.md`](../docs/CANONICAL-SPECIFICATION.md) for full derivations.
