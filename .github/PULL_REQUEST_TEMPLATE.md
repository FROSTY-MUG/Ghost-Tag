## Description
Briefly describe the purpose, implementation details, and rationale behind this pull request.

## Subsystems Touched
- [ ] Cryptographic Core (`src/crypto/`)
- [ ] NFC Layer & NDEF Framer (`src/nfc/`)
- [ ] Vault & Cache Engine (`src/vault/`)
- [ ] Operations Engine (`src/operations/`)
- [ ] Android Platform & Native C++ Security (`android/`)
- [ ] User Interface (`src/ui/`)
- [ ] Documentation & Specifications (`docs/`)

## Security Invariants Checklist
- [ ] **Zero-Secrets Policy**: No passphrases, KEKs, or unwrapped DEKs are written to persistent storage, logs, or crash handlers.
- [ ] **Volatile Memory Zeroization**: All secret buffers are wiped with `zeroize()` / 4-pass overwrite immediately after use.
- [ ] **Deterministic AAD**: Additional Authenticated Data is bound in AES-256-GCM.
- [ ] **Type 2 Bounds & CC Protection**: Capability Container (`Page 3`) and static lock bytes are strictly untouched during tag writes.
- [ ] **Fail-Closed**: Any integrity violation or checksum failure halts execution immediately.

## Testing & Verification
- [ ] All unit and integration test suites pass (`npm test`).
- [ ] TypeScript compilation passes cleanly (`npm run typecheck`).
- [ ] Real-world NFC read-back verified on physical hardware (if applicable).
