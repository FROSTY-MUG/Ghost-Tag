# Ghost-Tag v2.0.0 — Offline Encrypted NFC Distributed Vault for Android

Ghost-Tag v2.0.0 is the official production release of the offline, encrypted NFC data-vault and distributed file-vault system for Android.

### Core User Promise
> "Ghost-Tag splits your encrypted files into pieces and stores one piece on each NFC tag. You can scan the tags in any order later. Ghost-Tag identifies each piece, verifies it, and reassembles your files when enough valid pieces are collected."

### Security Boundary & Limitation Notice
> "A lost, damaged, or missing tag may prevent reconstruction. Enable redundancy to tolerate lost tags. Ghost-Tag does not prevent tag cloning, deletion, or replay."

---

### What's New in v2.0.0
- **Bulk Distributed Vault Engine**: Split arbitrary binary files (PDFs, videos, images, ZIPs) across physical NFC tags.
- **Cauchy-Vandermonde Reed-Solomon Erasure Coding**: Field arithmetic over GF(2^8) tolerating lost, damaged, or unreadable tags.
- **Extra-Tag Exclusion Rule**: Strictly prevents tag misuse by calculating exact needed tags and barring surplus tags from being written.
- **72-Hour Offline Cache**: Encrypted chunk caching with a strict 72-hour TTL and visual countdown for asynchronous tag scanning.
- **Two-Tier Key Hierarchy**: Ephemeral Argon2id KEK deriving per-file AES-256-GCM DEKs with zero disk persistence.
- **Native C++ Security Hardening**: Linux ptrace anti-debugging, `/proc` maps Frida/Xposed scanner, kernel page locking (`mlock`), and non-optimizable memory zeroization barriers.
- **Platform Hardening**: `FLAG_SECURE` window protection and hardware-backed Android KeyStore (TEE / StrongBox).
- **Interactive Cyber-Brutalist Web Showcase**: Featuring a sleek minimal dark interface, subtle covert operative visual aesthetics, and Web NFC physical tag interaction for Chrome on Android.

---

### Verification & Checksum
- **Artifact**: `ghost-tag-v2.0.0.apk`
- **Package**: `com.ghosttag`
- **File Size**: `391 KB (391,449 bytes)`
- **Target OS**: Android 8.0+ (API 26+)
- **Target ABIs**: `arm64-v8a`, `armeabi-v7a`, `x86_64`
- **SHA-256 Checksum**:
  ```
  41848271db6cac270ebaf74758e43bb701113f3315a0b2c4309f9ec9caa71f61
  ```

---

### Strict Ethical & Legal Notice
This software is provided solely for personal security, confidential data storage, and authorized educational research. **Do not use this software for illegal, malicious, or unauthorized purposes.** Ghost-Tag does not claim or provide physical tag cloning prevention.
