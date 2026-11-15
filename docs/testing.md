# Ghost-Tag Verification & Testing Guide

This guide describes how to run and verify the test suites, static analysis, and cryptographic test vectors for Ghost-Tag.

---

## 1. Automated Test Suites

Ghost-Tag maintains a comprehensive test suite across cryptographic operations, NFC envelopes, Cauchy Reed-Solomon erasure coding, and UI state engines:

```bash
# Run all unit and integration test suites
npm test

# Run tests with code coverage report
npm test -- --coverage
```

### Test Suite Structure:
- `src/__tests__/crypto.test.ts`: AES-256-GCM authenticated encryption, PBKDF2/Argon2id derivation vectors, and CSPRNG salt generation.
- `src/__tests__/security.test.ts`: Zero-secrets policy validation, memory zeroing, and tamper-resistance verification.
- `src/__tests__/nfc.test.ts`: Canonical NDEF record packing, Little-Endian length parsing, and magic byte validation.
- `src/__tests__/bulkEnvelope.test.ts`: Multi-tag envelope slicing, chunk indexing, and payload reassembly.
- `src/__tests__/bulkOperations.test.ts`: Scanning simulation, mixed-capacity tag sorting, and pause/resume logic.
- `src/__tests__/fileEncryptionAndErasure.test.ts`: Binary file serialization (images, PDFs, ZIPs) and secure wiping.
- `src/__tests__/operations.test.ts`: Vault workflow state transitions.
- `src/__tests__/vault.test.ts`: BIP-39 12-word mnemonic entropy generation and checksum verification.
- `src/__tests__/App.test.tsx`: Top-level application rendering and navigation.

---

## 2. Static Type Checking & Code Quality

```bash
# Verify TypeScript strict type-checking (0 errors)
npx tsc --noEmit

# Run ESLint across codebase
npm run lint
```

---

## 3. Web NFC Testing Guidelines

Web NFC is governed by browser platform restrictions:
- **Platform**: Requires Google Chrome on Android (version 89+).
- **Security Origin**: Requires secure HTTPS context (`https://frosty-mug.github.io/Ghost-Tag/`) or `localhost`.
- **Desktop Simulation**: When accessed from desktop or non-supported browsers, Ghost-Tag automatically engages its simulated transceiver, allowing end-to-end verification of vault encryption, envelope creation, and chunk reassembly without physical NFC hardware.
