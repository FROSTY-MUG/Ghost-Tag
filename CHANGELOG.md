# Changelog

All notable changes to the Ghost-Tag project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.5] - 2026-11-16

### Added
- **Hardened Zero-Knowledge Vault Recovery**: Supabase Edge Function `recover-vault` implementing constant-time verifier verification and layered rate-limiting.
- **Layered Rate Limiting**: Enforced limits across account (5/15m), user (20/15m), hashed IP (100/15m), and global (500/15m) thresholds.
- **Explicit RLS Denials**: Dedicated denial policies on `ghost_recovery_attempts` preventing unauthorized client manipulation; service-role only execution.
- **Passphrase Manager & Vault Crypto Bridge**: `src/vault/passphraseManager.ts` and `src/vault/crypto.ts` for strict memory zeroization and local rate limiting.
- **Real USB NFC Reader Hardware Support**: Ghost Bridge desktop daemon (`127.0.0.1:41789`) bridging ACS ACR122U readers to web browsers.
- **Native 12-Word BIP-39 Recovery Engine**: Cross-platform 12-word mnemonic recovery phrase with 4-bit SHA-256 checksum and mandatory confirmation of words 4, 8, and 11.
- **Single Master Passphrase Vault Model**: Passphrase-anchored KEK derivation (Argon2id) with double cryptographic binding (outer GCM + inner chunk GCM with deterministic AAD).

### Changed
- **Decryption Flow**: Decryption requires no Ghost account, Supabase login, or recovery phrase; user taps Decrypt Now and scans chips.
- **Security Boundaries**: Qualified client-side defense boundaries stating clearly that runtime environment checks do not prevent reverse engineering or protect data on a compromised or unlocked device.

### Fixed
- **Anti-Takeover Defense**: Remediated account takeover risk by decoupling public account identifiers from private recovery authentication secrets and verifiers.
- **Zero-Mock Policy**: Eliminated all synthetic, mock, or placeholder NFC results across UI and production code.
- **GitHub Actions Workflows**: Bound release signing secrets to job-level environment variables, eliminating silent fallback signing.

---

## [2.0.0] - 2026-11-10

### Added
- Core Cauchy-Vandermonde Reed-Solomon erasure coding engine over GF(2^8).
- RFC 9106 Argon2id memory-hard key derivation.
- AES-256-GCM binary envelopes (54B single / 134B bulk).
- Initial Android APK build configuration with native NDK C++ security module.
- Brutalist monochrome user interface.
