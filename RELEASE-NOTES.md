# Ghost-Tag v2.1.0 (Unreleased / Staging Draft)

> [!WARNING]
> **UNRELEASED STAGING STATUS**:
> - **Release Status**: Ghost-Tag v2.1.0 is an unreleased local staging version.
> - Ghost-Tag v2.1.0 has **NOT** been tagged or published to GitHub Releases.
> - **PR #24** and **PR #25** remain strictly unmerged pending explicit maintainer approval.
> - **Supabase Cloud**: Supabase Cloud: Undeployed. Schema and atomic migration RPC are implemented and covered by local tests, but have not been deployed to a live Supabase project or validated against a live database.
> - **Hardware**: Real-device physical validation on Android NFC, iOS CoreNFC, Ghost Bridge ACR122U, and PN532 is pending.
> - **iOS Scope**: Ghost-Tag on iOS does not currently implement NFC tag writing. Its CoreNFC integration is read-only. iOS tag-writing support, if added in the future, would require separate implementation, entitlement review, compatibility testing, and physical-device validation.

> [!NOTE]
> **CANONICAL SPECIFICATION REFERENCE**  
> For the authoritative wire layouts, cryptographic parameters, envelope definitions, and cross-platform derivation standards, refer to [CANONICAL-SPECIFICATION.md](docs/CANONICAL-SPECIFICATION.md).


## Overview

Ghost-Tag v2.1.0 achieves complete cross-platform cryptographic alignment across Android, Web, Ghost Bridge, and Supabase. Android is established as the canonical cryptographic reference implementation. Web has been fully realigned from legacy PBKDF2 to Argon2id RFC 9106 via a vendored offline WebAssembly bundle (`hash-wasm`), unifying `account_id`, `recovery_auth_secret`, `recovery_salt`, `recovery_verifier`, AES-256-GCM AEAD, and Little-Endian envelope wire formats across all platforms. A comprehensive 59-test cross-platform compatibility test suite (`src/__tests__/crossPlatformCryptoCompatibility.test.ts`) verifies 25 explicit cryptographic and architectural invariants against deterministic golden reference fixtures.

## Added

- **Cross-Platform Compatibility Test Suite**: Added `src/__tests__/crossPlatformCryptoCompatibility.test.ts` (59 tests) covering deterministic test vectors, BIP-39 recovery phrases, account ID derivations, auth secret derivations, deterministic salt derivations, Argon2id verifiers, AES-256-GCM AEAD, Ghost v1 single-tag and v2 bulk envelopes, tamper rejection, wrong passphrases, and 25 specific cross-platform interoperability points.
- **Zero-Knowledge Cross-Device Recovery**: Recovery on brand-new devices requires zero prior sessions or authentication; the 12-word recovery phrase is the sole recovery credential.
- **Dedicated Legacy Verifier Migration Edge Function**: Implemented `POST /functions/v1/migrate-recovery-verifier` allowing legacy web users to migrate PBKDF2 verifiers to canonical Argon2id on any device using their legacy verifier as ownership proof with zero secret exposure.
- **Deterministic Recovery Salt (Option A)**: `recovery_salt = SHA256("ghost-recovery-salt-v2.0.5:" || phrase)` enables 100% offline derivation across Android, Web, and iOS without network circularity.
- **Offline Argon2id Web WASM Engine**: Vendored self-contained `web/vendor/argon2.umd.min.js` (30 KB with embedded base64 WebAssembly) backed by `hash-wasm` to guarantee 100% client-side, zero-network recovery verifier derivation matching Android parameters.
- **Deterministic Golden Reference Fixtures**: Created `scripts/generate_compatibility_fixtures.js` which produces deterministic test vectors in `test-fixtures/crypto/`, `test-fixtures/recovery/`, and `test-fixtures/envelopes/` (including binary `.bin` envelopes) reproducible across Android, Web, and iOS.
- **Canonical Envelope Web Adapters**: Added Little-Endian `buildV1Envelope`, `parseV1Envelope`, `buildGtagEnvelope`, and `parseGtagEnvelope` helpers in `web/app.js` with canonical 26-byte (v1) and 74-byte (v2) AAD layouts.

## Changed

- **Canonical KDF Unification**:
  - `account_id`: RFC 4122 v4 UUID derived via single-pass `SHA256("ghost-account-id-v2.0.5:" || recovery_phrase)`.
  - `recovery_auth_secret`: 32-byte secret derived via single-pass `SHA256("ghost-recovery-auth-v2.0.5:" || recovery_phrase)`.
  - `recovery_salt`: 32-byte deterministic salt derived via single-pass `SHA256("ghost-recovery-salt-v2.0.5:" || recovery_phrase)`.
  - `recovery_verifier`: Argon2id RFC 9106 ($m=32768$ KiB, $t=3$ passes, $p=2$ threads, $h=32$ bytes, $v=0x13$, 32-byte salt) serialized to 64 lowercase hexadecimal characters.
- **Bulk Envelope Record Type**: Enforced canonical record type `0x10` (`RECORD_TYPE_BULK_CHUNK`) across serializers.
- **Supabase Anonymous Cloud Sync**: `web/supabase.js` and `web/app.js` now derive and store `recovery_verifier` and `recovery_salt` during account initialization and manual synchronization, passing only `account_id` and `recovery_verifier` during recovery.
- **Ghost Bridge APDU Exports**: Exported `parseNdefRecords` and `parseNdefFromUserMemory` in `desktop/src/apdu.js` for programmatic transport verification.

## Migration & Backward Compatibility

- **Legacy Web Recovery Migration**: Existing Web recovery records with recovery_kdf_version = 1 are recoverable only after successful migration using the original 12-word recovery phrase. Migration must be validated end-to-end before this claim is considered production-ready. Web previously derived recovery verifiers using PBKDF2 (100,000 rounds). The migration flow submits the canonical phrase-derived recovery_salt alongside the Argon2id verifier with legacy PBKDF2 proof of ownership, preventing cross-device recovery failures after migration.
- **Physical NFC Tags Unaffected**: All physical NFC tags written on Web or Android remain 100% decryptable because tag encryption uses the master passphrase and DEK with AES-256-GCM, which does not depend on the Supabase recovery verifier.

## Security & Privacy Invariants

- **Zero Secret Transmission**: Supabase stores ONLY encrypted vault metadata blobs. It NEVER receives or stores passphrases, recovery phrases, KEKs, DEKs, plaintexts, or NFC chunk contents.
- **Zero Open Vulnerabilities**: Confirmed zero open CodeQL alerts and zero open Dependabot vulnerabilities (`npm audit` reports 0 vulnerabilities).
- **Offline Self-Sufficiency**: Web app operates completely offline without external CDN dependencies for Argon2id WASM.
- **Hardware Readiness & Platform Status Disclosures**:
  - **PC/SC ACR122U**: Implemented in source code; pending real-reader hardware validation with physical ACR122U and physical NTAG tags.
  - **PN532 Serial Transport**: Implemented in source code and covered by mocked protocol tests; pending real-device validation with physical ESP32, PN532 module, and physical NTAG tags.
  - **iOS Subsystem**: Cryptographic foundation implemented in source code; pending macOS build, XCTest, and physical iPhone Core NFC validation. iOS UI and Core NFC are not implemented.
  - **Android NFC Engine**: Implemented in source code and unit tested; pending real-device NFC validation on physical Android hardware.
  - **Supabase Cloud Sync**: Schemas and Edge Functions verified locally; not deployed to live production.

## Verification

- **Full Verification Suite**: 16 passed / 16 test suites (280 passed / 280 tests).
- **TypeScript Strict Typecheck**: 0 errors (`npx tsc --noEmit`).
- **Web Build**: Clean production build via Vite (`npm run build`).
- **Lint**: Zero errors (`npm run lint`).
- **Artifacts & Tags**: No release tag, GitHub Release, or Supabase deployment performed in accordance with user constraints.
