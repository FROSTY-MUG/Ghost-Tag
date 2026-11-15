# Ghost-Tag AI Agent & Contributor Guidance

Welcome to the **Ghost-Tag** repository. This document defines the operational rules, cryptographic invariants, and architectural constraints that all autonomous AI coding agents (Antigravity, Cursor, GitHub Copilot, Gemini CLI) and human contributors must strictly observe when modifying this codebase.

---

## 1. Authoritative Reference & Anti-Hallucination Manual

When facing any architectural ambiguity, cross-platform question, or design bottleneck:
> **Always refer to [`docs/GHOST_TAG_SYSTEM_MANUAL.md`](./docs/GHOST_TAG_SYSTEM_MANUAL.md)**  
> This file is the authoritative, verbatim operational manual and cryptographic specification. Do not contradict or rephrase its core rules.

### The Realistic Cross-Platform Rule
> *"Ghost-Tag tags are cross-platform. Android and iPhone native apps can read and write them. The website can read and write them only in browsers that support Web NFC; on iPhone, use the native Ghost-Tag app for NFC."*

---

## 2. Non-Negotiable Security Invariants

All agents must adhere to the following strict invariants. Any code change violating these rules will fail security audits and be rejected:

1. **Zero-Secrets Policy**:
   - Master passphrases, derived KEKs, unwrapped DEKs, and plaintext file data **must never be persisted** to SQLite, MMKV, SharedPreferences, crash dumps, logcat, or console outputs.
   - The private database stores only wrapped DEKs (AES-256-GCM under KEK) and Argon2id salts.
2. **Volatile Memory Zeroization**:
   - Sensitive ephemeral byte buffers (`Uint8Array`, C++ `uint8_t*`) must be securely zeroized (`zeroize()` / 4-pass overwrite) immediately after cryptographic execution.
   - In C++, use `mlock()` and memory barriers to prevent swapping and dead-store compiler elimination.
3. **Deterministic AAD Binding**:
   - Single-tag envelopes bind 26 bytes of AAD (`"GTAG"` || version || purpose || keyId || len).
   - Bulk chunk envelopes bind 74 bytes of AAD (`"GTAG"` || version || recordType || vaultId || fileId || keyId || globalChunkIdx || totalVaultChunks || fileChunkIdx || totalFileChunks || len).
4. **NFC Hardware Protection**:
   - Page 3 (Capability Container - CC) and static/dynamic lock bytes must **never** be overwritten.
   - Writes target exclusively user memory pages (`Page 4` onwards).
5. **Fail-Closed Architecture**:
   - Tampered envelopes, incorrect GCM authentication tags, broken checksums, or detected tracers/root hooks must halt execution immediately. Never fall back to insecure or degraded plaintext modes.

---

## 3. Subsystem Architecture

Ghost-Tag employs strict layer separation:

```
src/
├── contracts/     # Authoritative schemas, envelope offsets, error codes, states
├── crypto/        # AES-256-GCM, Argon2id (RFC 9106), Cauchy RS GF(2^8), key wrapping
├── nfc/           # NDEF framing, Type 2 tag manager, atomic read-back verification
├── vault/         # Encrypted MMKV DB, session manager, 72h chunk cache, BIP39
├── operations/    # Scan, write, bulk partitioning, reconstruction, repair engines
├── security/      # Memory wiping, integrity coordinator, redaction utilities
└── ui/            # Terminal cyber-brutalist React Native screens and navigation
```

Native Android Core:
```
android/app/src/main/
├── cpp/           # libghosttag_security.so (ptrace, /proc/self/maps scan, mlock)
└── java/.../      # KeyStoreMasterKey (TEE/StrongBox), SecurityBridgeModule
```

---

## 4. Verification Workflow

Before submitting or committing any change:

```bash
# 1. Verify TypeScript types
npm run typecheck

# 2. Run full test suite (178 tests must pass)
npm test

# 3. Combined verification gate
npm run verify
```

---

## 5. Specialized Agents Index

For specialized development workflows, refer to the role specifications in `agents/`:
- [`agents/crypto-architect.md`](./agents/crypto-architect.md): Cryptographic algorithms, key derivation, and erasure coding.
- [`agents/nfc-engineer.md`](./agents/nfc-engineer.md): Physical tag memory layouts, NDEF records, and antenna tuning.
- [`agents/security-auditor.md`](./agents/security-auditor.md): Memory hygiene, anti-debugging, R8 obfuscation, and threat defense.
- [`agents/qa-automation-agent.md`](./agents/qa-automation-agent.md): Jest test coverage, fault injection, and mock transceivers.
