# Recovery Phrase Specification (`v2.1.0`)

- **Canonical Standard**: **12-Word BIP-39 English Mnemonic** (`128` bits entropy + `4` bits SHA-256 checksum = `132` bits).
- **Local Legacy Compatibility**: Offline `RecoveryManager` retains decoding/unwrapping support for 24-word (`256`-bit) phrases, whereas cross-platform and cloud recovery require **12 words**.

## Key Derivation & Salt Architecture
- **Production `v2.1.0` Cloud Recovery**:
  - `recovery_salt` is a **server-generated 32-byte CSPRNG value** created during `account-auth` provisioning (not derived from the mnemonic).
  - Clients compute two-stage RFC 9106 Argon2id (`m = 32768 KiB`, `t = 3`, `p = 2`, `h = 32B`, `v = 0x13`) using the server salt and prove knowledge interactively via a `76B` HMAC challenge/proof protocol in `recover-vault`.
- **Historical `Option A` Cross-Platform Vectors (`test-fixtures/recovery/recoveryVectors.json`)**:
  - Legacy v2.0.5 deterministic vector tests use `SHA-256("ghost-account-id-v2.0.5:" || normalized_phrase)` and `SHA-256("ghost-recovery-salt-v2.0.5:" || normalized_phrase)` for unit parity testing.

Never share, screenshot, or paste your recovery phrase online. Store offline on paper or steel.
