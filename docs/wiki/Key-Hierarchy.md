# Key Hierarchy

Ghost-Tag separates authentication, local encryption, and optional cloud recovery keys so no single credential exposes plaintext across boundaries.

## Key Layers
1. **User Passphrase (`>= 16` chars)**: Never stored on disk or transmitted to servers.
2. **Argon2id Master Key**: Derived deterministically from passphrase + CSPRNG salt (`src/crypto/argon2.ts`).
3. **Per-Envelope Data Key / Nonce**: Fresh 12-byte IV per AES-256-GCM encryption operation (`src/crypto/fileEncryption.ts`).
4. **Recovery Phrase (12-word BIP-39 canonical; 24-word local compat)**: Used to derive recovery keys independently of device storage (`src/vault/recoveryManager.ts`).
5. **Cloud Recovery Verifier (`v2.1.0` staging)**: Two-stage Argon2id + server-generated 32-byte `recovery_salt` (`supabase/functions/_shared/recoveryCrypto.ts`).

## Canonical Sources
- [docs/cryptography.md](../cryptography.md)
- [src/vault/recoveryManager.ts](../../src/vault/recoveryManager.ts)
- [supabase/functions/_shared/recoveryCrypto.ts](../../supabase/functions/_shared/recoveryCrypto.ts)
