# Ghost-Tag v2.0.0 — Offline Encrypted NFC Distributed Vault for Android

Ghost-Tag v2.0.0 is the official production release of the offline, encrypted NFC data-vault and distributed file-vault system for Android.

### Core User Promise
> "Ghost-Tag splits your encrypted files into pieces and stores one piece on each NFC tag. You can scan the tags in any order later. Ghost-Tag identifies each piece, verifies it, and reassembles your files when enough valid pieces are collected."

### Security Boundary & Limitation Notice
> "A lost, damaged, or missing tag may prevent reconstruction. Enable redundancy to tolerate lost tags. Ghost-Tag does not prevent tag cloning, deletion, or replay."

---

### What's New in v2.0.0
- **Full Operational Android UI**:
  - **Single-Tag Read & Scan (`ReadTag`)**: Interactive NFC tag antenna listener, Argon2id derivation, 54-byte binary envelope validation, AAD verification, AES-256-GCM decryption, and one-click copy.
  - **Single-Tag Write & Lock (`WriteTag`)**: Purpose selector (0x01 Note, 0x02 Credential, 0x03 Config, 0x05 Asset ID), live chip capacity calculation (NTAG213, NTAG215, NTAG216), 16+ char passphrase validation, and write-verification.
  - **Bulk Distributed Vault (`BulkVaultCreation`, `BulkWrite`, `BulkScan`, `Reconstruction`)**: Cauchy-Vandermonde Reed-Solomon erasure coding over GF(2^8), extra-tag exclusion, and 72-hour offline cache.
  - **Passphrase & BIP39 Recovery (`Passphrase`)**: 16+ char root passphrase update, 24-word BIP39 recovery phrase generation with checksum, and volatile session lock.
  - **Platform Hardening & Diagnostics (`Settings`)**: Live monitoring of FLAG_SECURE, KeyStore TEE, ptrace anti-debug, kernel mlock page locking, anti-Frida scanning, Argon2id work factor tuning, and panic memory zeroization.
- **Interactive Cyber-Brutalist Web Showcase**: Featuring a sleek minimal dark interface, subtle covert operative visual aesthetics, and Web NFC physical tag interaction for Chrome on Android.

---

### Verification & Checksum
- **Artifact**: `ghost-tag-v2.0.0.apk`
- **Package**: `com.ghosttag`
- **File Size**: `399 KB (399,136 bytes)`
- **Target OS**: Android 8.0+ (API 26+)
- **Target ABIs**: `arm64-v8a`, `armeabi-v7a`, `x86_64`
- **SHA-256 Checksum**:
  ```
  28a2e3d85ec803a733b62cdd5f55f1077d7b5a990a256b656262009d096e71ea
  ```

---

### Strict Ethical & Legal Notice
This software is provided solely for personal security, confidential data storage, and authorized educational research. **Do not use this software for illegal, malicious, or unauthorized purposes.** Ghost-Tag does not claim or provide physical tag cloning prevention.

