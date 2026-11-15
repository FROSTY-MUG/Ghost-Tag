# Ghost-Tag Product Roadmap

Planned developments and upcoming milestones for Ghost-Tag.

---

## 1. Version 2.0.5 (Current Release)
- Minimal, dark, Apple-like brutalist user interface.
- Mandatory anonymous account initialization with 12-word BIP-39 English recovery phrases.
- Zero-knowledge Supabase encrypted metadata sync.
- Elimination of scanned-chunk cache (volatile in-memory sessions only).
- Multi-entry support: Text, File, Photo, Video, and encrypted URLs.
- Single unified Decrypt workflow with out-of-order scanning.
- Android safe individual entry deletion with explicit corruption warnings.
- Unified `/technical` documentation page covering Technical, Security, Privacy, and Source.

---

## 2. Version 2.1 (Upcoming)
- **Native iOS Client**: Full native iOS app using Apple's CoreNFC framework to bring full reading and writing capabilities to iPhones.
- **Reed-Solomon Parity Redundancy**: Automatic generation of erasure recovery chunks (e.g. 8 data tags + 2 parity tags) so a vault can be reconstructed even if 2 physical tags are lost or destroyed.
- **Hardware Security Key Integration**: Option to require a FIDO2 / WebAuthn hardware key (e.g. YubiKey) to unlock local master passphrases.

---

## 3. Future Explorations
- **Type 4 Tag Support (DESFire EV3)**: High-security encrypted hardware handshakes for specialized enterprise deployments.
- **Offline QR Code Vault Bridging**: Optical air-gapped backup exchange for devices without NFC hardware.
