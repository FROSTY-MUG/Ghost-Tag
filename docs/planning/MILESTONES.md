# Ghost-Tag Engineering Milestones & Quality Gates

This document formalizes acceptance criteria and deliverables across each milestone release.

---

## Milestone Summary

| Milestone | Target Status | Core Theme | Required Quality Gates |
| :--- | :--- | :--- | :--- |
| **M1: Core Security Baseline** | **Completed (v2.0.0)** | Production Android APK & Web Terminal | 100% Jest tests passing, 0 TSC errors, Native C++ memory audit. |
| **M2: iOS CoreNFC Reader** | **Planned (v2.1.0)** | Cross-platform NDEF reading on iOS | Swift package builds cleanly, XCTest suite passing, NDEF envelope parity. |
| **M3: Hardware Key Attestation** | **Planned (v2.2.0)** | YubiKey / FIDO2 NFC challenge-response | Physical NFC APDU transceiver tests, ISO 7816-4 compliance. |
| **M4: Post-Quantum Resilience** | **Planned (v2.3.0)** | NIST FIPS 203 ML-KEM integration | CAVP test vectors, constant-time C++ verification, zero memory leaks. |

---

## Release Verification Checklist for Every Milestone

Before any tag or APK release is promoted to the `production` environment:
1. **Automated Test Matrix**:
   - `npm test` runs with 100% passing suites (minimum 130 tests).
   - TypeScript compilation passes with zero warnings or errors (`npx tsc --noEmit`).
2. **Cryptographic Invariant Gate**:
   - `npm run audit` runs cleanly.
   - Zero hardcoded secrets, keys, or seeds in codebase.
   - Constant-time equality checks enforced for HMAC/GCM authentication tags.
3. **Hardware Sanity Check**:
   - Physical read-back verification tested against NTAG213, NTAG215, and NTAG216 chips.
   - Capability Container (CC) byte preservation confirmed.
4. **Binary Integrity Check**:
   - APK release artifact SHA-256 generated and verified in `web/assets/release-meta.json`.
   - GitHub Pages static web assets verified with HTTP 200.
