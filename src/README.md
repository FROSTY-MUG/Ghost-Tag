# Ghost-Tag Shared TypeScript Core Subsystem

## Overview
The `src/` directory contains the core application architecture, business logic, cryptographic engines, NFC transceivers, and UI screens for Ghost-Tag.

---

## Directory Decomposition

```
src/
├── contracts/      # Wire protocols, envelope layouts, error taxonomies, and interface types
├── crypto/         # AES-256-GCM, Argon2id, Cauchy-Reed-Solomon, KEK/DEK, and secure memory
├── nfc/            # Hardware abstraction layer, NDEF builder/parser, and chip capability limits
├── operations/     # High-level state machines: Scan, Write, Wipe, Verify, Reconstruct
├── vault/          # Session management, chunk cache, journal manager, database, and wordlist
├── ui/             # React Native screens, theme definitions, and navigation graph
├── utils/          # Cross-environment polyfills and runtime helpers
└── __tests__/      # Automated Jest unit and integration test suites
```

---

## Important Subsystems

| Module | Purpose | Key Files |
| :--- | :--- | :--- |
| **Contracts** | Wire formats and binary specifications | `contracts/envelope.ts` (v1 54B), `contracts/bulkEnvelope.ts` (v2 134B), `contracts/recovery.ts` |
| **Crypto** | Authenticated encryption and erasure coding | `crypto/aesGcm.ts`, `crypto/argon2.ts`, `crypto/erasureCoding.ts`, `crypto/keyWrap.ts` |
| **NFC** | Transceiver layer and tag handling | `nfc/nfcManager.ts`, `nfc/ndefBuilder.ts`, `nfc/bulkNdefBuilder.ts`, `nfc/tagInfo.ts` |
| **Operations** | User workflows and orchestrators | `operations/writeOperation.ts`, `operations/scanOperation.ts`, `operations/reconstructionEngine.ts` |
| **Vault** | Local state and storage | `vault/vaultManager.ts`, `vault/bulkVaultManager.ts`, `vault/chunkCache.ts`, `vault/dekManager.ts` |
| **UI** | Mobile user interface | `ui/screens/HomeScreen.tsx`, `ui/screens/ReadTagScreen.tsx`, `ui/screens/BulkVaultCreationScreen.tsx` |

---

## How to Build & Typecheck

```bash
# Compile TypeScript declarations
npm run build

# Strict TypeCheck without emitting
npm run typecheck
```

---

## How to Test

```bash
# Run all unit and integration test suites
npm test

# Run tests with coverage reporting
npm test -- --coverage
```

---

## Security & Hardware Constraints

1. **Zero Secret Persistence**: Never log or store passphrases, KEKs, DEKs, or plaintext files in unencrypted storage.
2. **Volatile Memory Sanitization**: Sensitive buffers must be explicitly overwritten using `crypto/secureMemory.ts` wipe routines.
3. **NFC Capacity Invariant**: Payloads must strictly obey chip page boundaries:
   - NTAG213: 144 writable bytes
   - NTAG215: 504 writable bytes
   - NTAG216: 888 writable bytes
4. **Hardware Reality**: In automated test environments without attached physical NFC devices, tests utilize simulated adapters (`__mocks__/react-native-nfc-manager.ts`). All physical hardware claims remain pending real-device validation.

---

## Contributor Guidelines

1. **Adding a Feature**:
   - Define interfaces in `src/contracts/` before implementing logic.
   - Maintain strict separation of concerns: UI screens must not invoke raw crypto directly; use `src/operations/`.
2. **Adding a Test**:
   - Create tests in `src/__tests__/` with descriptive naming (`*.test.ts` or `*.test.tsx`).
   - All tests must pass in CI without network access.
3. **Adding a Cryptographic Vector**:
   - Update `test-fixtures/` and add corresponding test assertions in `src/__tests__/crossPlatformCryptoCompatibility.test.ts`.
