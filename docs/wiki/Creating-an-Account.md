# Creating an Account (`v2.1.0`)

Ghost-Tag operates **100% offline by default**. Account setup establishes your local key hierarchy and Master Passphrase:

1. **Master Passphrase (`>= 16` chars)**: Derives an ephemeral 256-bit KEK via RFC 9106 Argon2id (`16 / 32 / 64 MiB` profiles in `DEFAULT_KDF_PARAMETERS_BY_TIER` on native clients, with WebCrypto PBKDF2 local KEK compatibility where configured).
2. **Canonical 12-Word BIP-39 Recovery Phrase**: `128` bits of CSPRNG entropy + `4`-bit SHA-256 checksum encoded across the English 2,048-word BIP-39 dictionary (`24-word` phrases are retained for legacy local unwrapping compatibility only).
3. **Random 256-Bit DEKs**: Generated locally to encrypt payloads via AES-256-GCM and wrapped under the passphrase KEK (and optionally recovery KEK).
4. **Opt-In Cloud Metadata Backup (`v2.1.0`)**: When explicitly enabled and Supabase is deployed, `account-auth` validates Cloudflare Turnstile (`verify-captcha`), generates a server-random **32-byte CSPRNG `recovery_salt`**, and stores only the client's two-stage Argon2id `recovery_verifier` (`m=32768, t=3, p=2`) and encrypted `encrypted_recovery_envelope`. Plaintext passphrases, BIP-39 words, and unwrapped DEKs never leave the device.

See [Recovery Phrase](Recovery-Phrase) and [Recovery](Recovery).
