# Ghost-Tag iOS Subsystem

## Overview
Ghost-Tag iOS is designed to provide read-only NFC scanning and zero-knowledge vault restoration on Apple iOS devices.

---

## 1. Current Implementation Status

> [!IMPORTANT]
> **Staging & Development Status**:
> - **PR #25**: Remains unmerged on branch `pr-25` pending explicit maintainer approval.
> - **Read-Only Scope**: iOS support is **strictly Read-Only**. Tag writing is completely unimplemented on iOS.
> - **Cryptographic Foundation**: BIP-39 recovery mnemonic, Argon2id KEK derivation (via `Clibargon2`), AES-256-GCM decryption, and canonical envelope parsing (v1 54B and v2 134B) are implemented in native Swift.
> - **Hardware Validation**: Real CoreNFC scanning remains **unverified on physical hardware** pending access to a macOS compilation host and an attached physical iPhone.

---

## 2. CoreNFC Entitlement & Configuration

- **Entitlement File**: `ios/GhostTag/GhostTag.entitlements`
  - Formats: `TAG` (ISO 14443 Type 2 APDU queries) and `NDEF` (MIME record extraction).
- **Target Linkage**: `CoreNFC.framework` linked in `GhostTag.xcodeproj`.
- **Usage Description**: Configured in `ios/GhostTag/Info.plist`:
  `NFCReaderUsageDescription`: `"Ghost-Tag uses NFC to scan and reconstruct encrypted vaults from physical tags."`

---

## 3. Building & Packaging

Packaging the iOS application into a release `.ipa` requires an Apple macOS host with Xcode Command Line Tools:

```bash
# Must be executed on macOS:
python3 scripts/package_release_ipa.py
```

On non-macOS host environments (Windows / Linux), the script safely halts with exit code `1`.
