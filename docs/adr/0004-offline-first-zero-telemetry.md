# ADR 0004: Offline-First Zero-Telemetry Architecture

## Status
**Accepted** (2026-11-13)

## Context
Many modern mobile applications incorporate telemetry SDKs, cloud sync features, remote crash reporters (e.g. Firebase Crashlytics, Sentry), or analytics trackers (Google Analytics, Mixpanel). 
In an encrypted vault system, any outbound network connection creates an exfiltration vector and metadata leakage risk (IP address, scan timestamps, payload sizes).

## Decision
Ghost-Tag adopts an absolute **Zero-Telemetry, Offline-First** architecture:
1. **Zero Network Permissions Required**: The Android application does not request `android.permission.INTERNET`.
2. **Zero Third-Party Trackers**: No analytics, crash reporters, ad networks, or telemetry libraries are bundled in the binary.
3. **Local-Only Operation**: All cryptography, key derivation, erasure coding, and NFC interactions execute exclusively on the local CPU and hardware NFC controller.
4. **No Cloud Dependency**: Key recovery relies strictly on an offline 24-word BIP39 mnemonic phrase written down by the user.

## Consequences
### Positive
- Total immunity from network-based data breaches, cloud outages, or remote surveillance.
- Cryptographic keys and file contents cannot leak over network sockets.
- Complete operational privacy.

### Negative
- Users are solely responsible for backing up their 24-word recovery phrase.
- No automated cloud backups or cross-device push synchronization.
