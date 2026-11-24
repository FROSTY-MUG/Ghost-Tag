# Ghost-Tag Cryptographic & Binary Envelope Test Fixtures

## Overview
The `test-fixtures/` directory houses canonical test vectors, reference envelopes, and deterministic verification vectors utilized across Android, iOS, Web, and Desktop test suites.

---

## Important Files

```
test-fixtures/
├── crypto/
│   └── aesGcmVectors.json             # RFC-compliant AES-256-GCM test vectors with known keys, IVs, AAD, and tags
├── envelopes/
│   ├── v1-reference.bin               # 83-byte canonical v1 binary envelope (54B overhead + 29B ciphertext)
│   ├── v1EnvelopeVectors.json         # Parameterized single-tag envelope test vectors
│   ├── v2-bulk-reference.bin          # 203-byte canonical v2 bulk envelope (134B overhead + 69B chunk payload)
│   └── v2BulkEnvelopeVectors.json     # Parameterized bulk chunk envelope test vectors
└── recovery/
    └── recoveryVectors.json           # 12-word BIP-39 mnemonics, seeds, salts, and derived Argon2id verifiers
```

---

## Exact Specifications

1. **v1 Single-Tag Reference Envelope (`v1-reference.bin`)**:
   - Total length: 83 bytes
   - Fixed overhead: 54 bytes
   - Ciphertext length: 29 bytes
   - Deterministic AAD: 26 bytes
   - MIME Type: `application/vnd.ghost.secure`
2. **v2 Bulk Reference Envelope (`v2-bulk-reference.bin`)**:
   - Total length: 203 bytes
   - Fixed overhead: 134 bytes ($74\text{ AAD} + 32\text{ Hash} + 12\text{ IV} + 16\text{ Tag}$)
   - Chunk payload length: 69 bytes
   - Deterministic AAD: 74 bytes (ends at byte 73)
   - MIME Type: `application/vnd.ghost.bulk`

---

## How to Test
Fixtures are validated by:
- TypeScript suite: `src/__tests__/crossPlatformCryptoCompatibility.test.ts`
- iOS XCTest suite: `ios/GhostTagTests/CrossPlatformCryptoTests.swift`
- Web syntax suite: `src/__tests__/webSyntaxAndBuild.test.ts`

Run tests via:
```bash
npm test -- src/__tests__/crossPlatformCryptoCompatibility.test.ts
```

---

## Contributor Guidelines

1. **Adding a Cryptographic Vector**:
   - Vectors must be generated deterministically using `scripts/generate_compatibility_fixtures.js`.
   - Never generate vectors using unseeded or variable random number generators.
   - Any new envelope format must specify exact byte-level field offsets and Little-Endian encoding.
