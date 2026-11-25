# Threat Model

Ghost-Tag is designed under the assumption that physical NFC tags, local network links, and cloud metadata storage may be inspected by untrusted parties.

## Protected Assets
- **Plaintext Payloads**: Encrypted locally via AES-256-GCM before leaving client memory ([src/crypto/fileEncryption.ts](../../src/crypto/fileEncryption.ts)).
- **User Passphrase & Master Key**: Derived locally via Argon2id (`t=4`, `m=65536`, `p=2` canonical tier) and never transmitted ([src/crypto/argon2.ts](../../src/crypto/argon2.ts)).
- **Cloud Recovery Verifier**: In `v2.1.0` staging, `ghost_vaults` direct client access is revoked (`20261125_lockdown_ghost_vaults.sql`) and `recover-vault` uses a single-use `76B` HMAC challenge/proof flow ([supabase/functions/_shared/recoverVaultHandler.ts](../../supabase/functions/_shared/recoverVaultHandler.ts)).

## Out-of-Scope / Residual Risks
- **Compromised Client Device**: A rooted/compromised OS or keylogger active during passphrase entry can capture plaintext or passphrases.
- **Physical Tag Destruction / Loss**: Losing more than `M` tags in a `K`-of-`K+M` bulk vault prevents reconstruction.
- **Unverified Hardware Paths**: Physical Android NFC, ACR122U, ESP32/PN532, and live Supabase deployment remain open validation gates ([PROJECT-STATUS.md](../../PROJECT-STATUS.md)).

## Canonical Sources
- [docs/security.md](../security.md)
- [docs/security-hardening.md](../security-hardening.md)
- [docs/security-audit.md](../security-audit.md)
