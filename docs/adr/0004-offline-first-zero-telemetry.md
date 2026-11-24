# ADR 0004: Offline-First Zero-Telemetry Architecture

## Status
**Accepted** (2026-11-13)

## Context
Many modern mobile applications incorporate telemetry SDKs, cloud sync features, remote crash reporters (e.g. Firebase Crashlytics, Sentry), or analytics trackers (Google Analytics, Mixpanel). 
In an encrypted vault system, any outbound network connection creates an exfiltration vector and metadata leakage risk (IP address, scan timestamps, payload sizes).

## Decision
Ghost-Tag adopts an absolute **Zero-Telemetry, Offline-First** architecture:
1. **Zero Telemetry & Cleartext Block by Default**: Offline vault encryption, decryption, and NFC tag operations transmit zero network telemetry. `android/app/src/main/AndroidManifest.xml` declares `android.permission.INTERNET` strictly to support opt-in user-configured Supabase cloud metadata recovery and React Native development Metro bundling, while `res/xml/network_security_config.xml` blocks cleartext HTTP traffic.
2. **Zero Third-Party Trackers**: No analytics, crash reporters, ad networks, or telemetry libraries are bundled in the binary.
3. **Local-Only Operation**: All cryptography, key derivation, erasure coding, and NFC interactions execute exclusively on the local CPU and hardware NFC controller.
4. **Offline-First Recovery**: Local key recovery relies primarily on a **12-word BIP-39 mnemonic phrase** (with 24-word local unwrapping compatibility) written offline by the user, with strictly opt-in zero-knowledge encrypted recovery metadata sync to Supabase (`v2.1.0` challenge/proof) when explicitly configured.

## Consequences
### Positive
- Total immunity from network-based data breaches, cloud outages, or remote surveillance.
- Cryptographic keys and file contents cannot leak over network sockets.
- Complete operational privacy.

### Negative
- Users are solely responsible for backing up their recovery phrase (12-word primary or legacy 24-word offline vault secret) when operating offline.
- No automated cloud backups or cross-device push synchronization.
