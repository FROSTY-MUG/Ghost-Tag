## Summary & Context
Briefly describe the purpose, implementation details, and architectural rationale behind this pull request.
Link related issues: `Fixes #` or `Relates to #`.

---

## Subsystems Touched
- [ ] Cryptographic Core (`src/crypto/`) — Argon2id, AES-256-GCM, Cauchy Reed-Solomon
- [ ] NFC Layer & NDEF Framer (`src/nfc/`) — Transceive loops, Type 2/4/5 framing
- [ ] Vault & Cache Engine (`src/vault/`) — Chunk sharding, reassembly, manifest parsing
- [ ] Android Platform & Native C++ NDK (`android/app/src/main/cpp/`)
- [ ] Web Simulator & Terminal (`web/`)
- [ ] CI/CD & Security Audits (`ci/`, `.github/`)
- [ ] Documentation & Specifications (`docs/`)

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
- [ ] Self-audit completed against [SECURITY.md](file:///c:/Users/Aryan/Desktop/Projects/Ghost-Tag/SECURITY.md) and [CODE_OF_CONDUCT.md](file:///c:/Users/Aryan/Desktop/Projects/Ghost-Tag/CODE_OF_CONDUCT.md).
- [ ] Backward compatibility with existing NDEF envelope schemas verified.
