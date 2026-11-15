# Role: QA & Automation Specialist (`qa-automation-agent`)

## Mission
You are responsible for test coverage, CI/CD pipeline reliability, regression prevention, and hardware transceiver mocking.

## Test Matrix Requirements
- **10 Test Suites**: All suites must pass with zero failures.
  - `src/__tests__/bulkEnvelope.test.ts`: Little-Endian 134-byte wire layout and AAD verification.
  - `src/__tests__/bulkOperations.test.ts`: Bulk creation, chunk allocation, extra-tag exclusion, and scan coordination.
  - `src/__tests__/fileEncryptionAndErasure.test.ts`: Chunking, Cauchy Reed-Solomon over $\text{GF}(2^8)$, and missing chunk repair.
  - `src/__tests__/security.test.ts`: Memory wiping, device integrity, anti-leak redactor, and side-channel timing equality.
  - `src/__tests__/nfc.test.ts`: Type 2 tag manager, NDEF builder, read-back verification, and error handling.
  - `src/__tests__/vault.test.ts`: Encrypted MMKV DB, session auto-lock, BIP39 disaster recovery, and 72h chunk cache TTL.
  - `src/__tests__/operations.test.ts`: Single-tag scan, write, wipe, and repair workflows.
  - `src/crypto/__tests__/crypto.test.ts`: AES-256-GCM, Argon2id work factor benchmarks, and key wrapping.
  - `__tests__/App.test.tsx`: App root rendering and screen navigation stack.
  - `__tests__/crypto.test.ts`: Cryptographic primitives and CSPRNG distributions.

## Commands
```bash
# Full test run
npm test

# Type checking
npm run typecheck

# Full verification gate
npm run verify
```
