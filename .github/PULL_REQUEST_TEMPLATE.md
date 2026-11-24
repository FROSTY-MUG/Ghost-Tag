## Summary & Context
Briefly describe the purpose, implementation details, and architectural rationale behind this pull request.
Link related issues: `Fixes #` or `Relates to #`.

---

## Subsystems Touched
- [ ] Cryptographic Core (`src/crypto/`) — Argon2id, AES-256-GCM, Cauchy Reed-Solomon
- [ ] NFC Layer & NDEF Framer (`src/nfc/`) — Transceive loops, Type 2/4/5 framing
- [ ] Vault & Cache Engine (`src/vault/`) — Chunk sharding, reassembly, manifest parsing
- [ ] Android Platform & Native C++ NDK (`android/`)
- [ ] Desktop Ghost Bridge (`desktop/`) — PC/SC APDU & PN532 Serial Transports
- [ ] iOS Swift Core (`ios/`) — CoreNFC Read-Only & Foundation
- [ ] Supabase Cloud Sync (`supabase/`) — Schema & Edge Functions
- [ ] Web Simulator & Companion (`web/`)
- [ ] CI/CD & Security Audits (`ci/`, `.github/`)
- [ ] Documentation & Specifications (`docs/`)

---

## Repository Governance & Policy Invariants
- [ ] **Pull Request Workflow**: All changes must be submitted via pull request; direct pushes to `main` are strictly prohibited.
- [ ] **Hardware Support Policy**: No claims of physical hardware support (Android NFC, iOS CoreNFC, ACR122U, PN532) are made without authentic logs from real physical devices.
- [ ] **Release Tagging Policy**: No Git tags or GitHub Releases may be created without explicit maintainer approval; v2.1.0 remains an unreleased local staging version.
- [ ] **Zero Synthetic Evidence**: No synthetic hardware logs, mock device outputs, or fabricated test results are accepted.

---

## Security Invariants Checklist (Mandatory for merge)
- [ ] **Zero-Secrets Policy**: No passphrases, KEKs, unwrapped DEKs, or plaintext payloads are logged, persisted, or exposed in exceptions.
- [ ] **Memory Zeroization**: Secret key buffers are overwritten with `zeroize()` / native zeroing immediately upon completion.
- [ ] **AES-256-GCM Nonce Uniqueness**: CSPRNG 96-bit nonces are fresh per encryption call; no nonce reuse is possible.
- [ ] **Deterministic AAD**: Additional Authenticated Data (`MAGIC || VERSION || PURPOSE || KEY_ID || LENGTH`) is strictly bound.
- [ ] **Type 2 Bounds & CC Protection**: Capability Container (`Page 3`) and static lock bytes are strictly untouched during tag writes.
- [ ] **Fail-Closed Principle**: Any authentication tag mismatch or CRC error aborts without leaking decrypted fragments.

---

## Code Review & Verification
- [ ] All unit and integration tests pass cleanly (`npm test`).
- [ ] TypeScript compilation passes with 0 errors (`npx tsc --noEmit`).
- [ ] Self-audit completed against [SECURITY.md](SECURITY.md) and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- [ ] Backward compatibility with existing NDEF envelope schemas verified.
