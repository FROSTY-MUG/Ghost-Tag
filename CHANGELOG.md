# Changelog

All notable changes to the Ghost-Tag project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.0.5] - 2026-11-15

### Added
- **Minimal Brutalist Web Client**: Deployed on GitHub Pages (`https://frosty-mug.github.io/Ghost-Tag/`) featuring ambient heavily blurred ghost backdrop, instant initial loading splash, and zero technical panels on landing.
- **Explicit Stop and Pause Flow**:
  - Bulk Tag Scanning: Visible `[Stop Scanning]` button that halts scan loop, preserves in-memory tags, displays total usable Ghost storage, and exposes `[Continue]`, `[Resume Scanning]`, and `[Cancel]`.
  - Bulk Tag Writing: Visible `[Stop Writing]` button that safely pauses in-flight operations, preserves written/remaining counts, and exposes `[Resume Writing]` and `[Cancel Session]`.
  - Decrypt Scanning: Visible `[Stop Scanning]` button that halts scanning and displays `[Decrypt Now]`, `[Resume Scanning]`, and `[Cancel]`.
- **12-Word BIP-39 English Cross-Platform Recovery**:
  - Generates 12-word recovery phrase from 128-bit CSPRNG entropy with 4-bit SHA-256 checksum (132 bits total).
  - 3-word verification requirement (words 4, 8, 11) before vault initialization.
  - Recovery phrase import allowing vault reconstruction across Android APK and Web client.
- **Unified `[ Decrypt Now ]` Flow**: Automatic envelope inspection, version verification, and missing chunk reporting (`X / Y collected, Z missing`).
- **IndexedDB 72-Hour Ephemeral Cache**: Automatically caches scanned ciphertext chunks for up to 72 hours with expiration timers and manual cache purge.
- **Mixed NFC Tag Capacity Engine**: Automatic detection and calculation for mixed NTAG213, NTAG215, NTAG216 tags; instructs user to set aside surplus tags when fewer tags are required than scanned.
- **Deep-Link Structure**: Dedicated routes for `/app/scan`, `/app/write`, `/app/bulk`, `/app/decrypt`, `/app/recovery`, and `/app/settings`.
- **Android APK Release v2.0.5**: Signed release binary `Ghost-Tag-v2.0.5.apk` (SHA-256: `28a2e3d85ec803a733b62cdd5f55f1077d7b5a990a256b656262009d096e71ea`) attached to GitHub Releases.

### Changed
- Web NFC engine upgraded with resilient fallback simulation mode for desktop testing.
- UI styling enhanced with brutalist dark palette (`#080808`, `#121212`, `#00ff66`), interactive button states (`:hover`, `:active`, `:focus-visible`, `:disabled`), and smooth CSS transitions.

### Fixed
- Fixed wordlist regex extraction ensuring all 2,048 BIP-39 English words are cleanly loaded.
- Fixed responsive layout wrapping on small mobile screens (<360px).

---

## [2.0.0] - 2026-11-10

### Added
- **Cauchy Reed-Solomon Erasure Coding**: Added $(N, K)$ matrix erasure coding over Galois Field $\text{GF}(2^8)$ allowing vault reconstruction even if up to $M$ physical tags are lost or corrupted.
- **Argon2id RFC 9106 Key Derivation**: Added memory-hard key derivation ($m=64\,\text{MB}, t=3, p=4$) for Android Keystore master keys.
- **Chunked File Vault Storage**: Support for arbitrary binary files (images, PDFs, ZIPs, videos) sliced into NDEF chunks across multiple NFC chips.
- **Native Memory Scrubbing**: JNI/NDK native C++ memory zeroing routines using `memset_s` to scrub keys and passphrases immediately after derivation.

### Changed
- Updated NDEF MIME types to canonical `application/vnd.ghost.secure` (single-tag) and `application/vnd.ghost.bulk` (multi-tag).
- Migrated local metadata persistence to encrypted MMKV storage.

---

## [1.0.0] - 2026-10-20

### Added
- Initial release of Ghost-Tag offline encrypted NFC vault for Android.
- Single-tag text and small file encryption using AES-256-GCM.
- Automatic NTAG213 / NTAG215 / NTAG216 detection.
- Read-back verification and authentication tag checking.
- Offline-only architecture with zero network permissions.
