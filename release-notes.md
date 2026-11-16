# Ghost-Tag v2.0.5 Release Notes

Ghost-Tag is a hardware-anchored, offline-first encrypted NFC distributed file vault system for Android, laptops (via Ghost Bridge), and web browsers.

## Core Highlights

* **12-Word BIP-39 Recovery Engine**: Cross-platform 12-word mnemonic recovery phrase with 4-bit SHA-256 checksum and mandatory confirmation of words 4, 8, and 11.
* **Separated Root Secrets**: Account identity is anchored to the recovery phrase; vault encryption/decryption is anchored to user-selected master passphrases.
* **Decryption Requires No Account**: Anyone with the master passphrase can scan and decrypt valid Ghost-Tag chips immediately without signing in or registering.
* **Mixed Tag Sharding & Systematic Erasure Coding**: Automatically splits arbitrary files (text, images, PDFs, videos, URLs) across NTAG213, NTAG215, and NTAG216 tags with Cauchy-Vandermonde Reed-Solomon over $\text{GF}(2^8)$.
* **Mandatory Read-Back Verification**: Every write operation reads back the tag, verifies the 16-byte AES-GCM authentication tag, and checks the 32-byte SHA-256 ciphertext hash before marking complete.
* **Ghost Bridge Desktop Companion**: Native Node.js PC/SC daemon (`127.0.0.1:41789`) enabling hardware ACS ACR122U USB NFC readers on laptops and workstations.
* **Hardened Zero-Knowledge Cloud Backup**: Supabase stores strictly encrypted metadata blobs with constant-time recovery verifier authentication and rate limiting.

## Verification & Integrity

* **Test Suite**: 13 test suites, **169 unit and integration tests passing (verified)**.
* **TypeScript Compilation**: 0 errors (`npx tsc --noEmit` in strict mode).
* **Automated Audits**: Quality Audit and Security Audit agents passing 100%.
* **APK SHA-256 Checksum**: Attached to official GitHub Releases.
