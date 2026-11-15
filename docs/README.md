# Ghost-Tag Documentation Portal

Welcome to the **Ghost-Tag** technical documentation repository. This directory contains the authoritative specifications, cryptographic proofs, architectural diagrams, hardware matrices, and security models governing Ghost-Tag and Ghost-Tag Bulk Scanning v2.

---

## 1. Documentation Index

| Document | Primary Focus | Key Topics |
| :--- | :--- | :--- |
| [**System & Fallback Manual**](./GHOST_TAG_SYSTEM_MANUAL.md) | **Master Architectural Guide** | Cross-platform rules, universal interchange format, Android/Web/iOS/Desktop specs, data flows. |
| [**Architecture Guide**](./architecture.md) | System Decomposition | 6 decoupled subsystems, unidirectional dependency graph, contract-first design. |
| [**Codebase Structure**](./code-structure.md) | File & Directory Tour | Comprehensive map of every file across C++, Kotlin, and TypeScript. |
| [**Security Hardening**](./security-hardening.md) | Defense-in-Depth | C++ anti-debugging (`ptrace`), anti-hooking (`/proc/self/maps`), `mlock()`, `FLAG_SECURE`, R8 obfuscation. |
| [**Cryptographic Core**](./cryptography.md) | Cryptography & KDF | RFC 9106 Argon2id work factors, 2-tier key hierarchy, AES-256-GCM, Cauchy Reed-Solomon over $\text{GF}(2^8)$. |
| [**Binary Envelope Spec**](./envelope-specification.md) | Wire Layouts & Framing | 54-byte v1 envelope (`GTAG`), 134-byte v2 bulk envelope (`GTBK`), and 74-byte AAD binding. |
| [**Bulk Scanning v2**](./bulk-scanning-v2.md) | Distributed NFC File-Vault | Multi-file vaults, random-order reassembly, 72-hour chunk cache with TTL, extra-tag exclusion. |
| [**NFC Hardware Matrix**](./nfc-tag-matrix.md) | Embedded RFID / NFC | Supported NTAG21x & MIFARE Ultralight chips, page layouts, locks, and usable capacities. |
| [**User & Backend Flow**](./user-flow.md) | Interaction & State Machines | End-to-end walkthroughs: Scan & Decrypt, Write & Verify, Destructive Wipe, Disaster Recovery. |

---

## 2. Reading Roadmap by Persona

Depending on your role or objective, follow these recommended reading sequences:

```
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│   Security Auditor /    │     │   Android / Embedded    │     │      Contributor /      │
│      Cryptographer      │     │        Engineer         │     │  Application Developer  │
└────────────┬────────────┘     └────────────┬────────────┘     └────────────┬────────────┘
             │                               │                               │
             ▼                               ▼                               ▼
  1. security-hardening.md        1. architecture.md              1. code-structure.md
  2. cryptography.md              2. nfc-tag-matrix.md            2. user-flow.md
  3. envelope-specification.md    3. envelope-specification.md    3. bulk-scanning-v2.md
  4. SECURITY.md                  4. security-hardening.md        4. CONTRIBUTING.md
```

### 🛡️ For Security Auditors & Cryptographers
1. Start with [**Security Hardening Specification**](./security-hardening.md) to understand the multi-language threat model, `ptrace` anti-tracing, Frida/Xposed detection, kernel page locking (`mlock`), and memory wiping barriers.
2. Review [**Cryptographic Core Specification**](./cryptography.md) for Argon2id derivation formulas, 19-byte key-wrap domain separation, and constant-time tag verification.
3. Inspect [**Envelope Specification**](./envelope-specification.md) to verify Additional Authenticated Data (AAD) framing and tamper-resistance against cut-and-paste attacks.
4. Review the project [**SECURITY.md**](../SECURITY.md) policy and vulnerability disclosure procedures.

### 📱 For Android & Embedded Systems Engineers
1. Start with [**System Architecture**](./architecture.md) to review module boundaries, foreground dispatch routing, and state machine lifecycles.
2. Read [**NFC Tag Hardware Matrix**](./nfc-tag-matrix.md) for chip page limits, capability containers (CC), dynamic lock bytes, and physical payload constraints.
3. Review [**Binary Envelope Specification**](./envelope-specification.md) to understand Little-Endian byte ordering and NDEF MIME encapsulation (`application/vnd.ghost.secure` and `application/vnd.ghost.bulk`).
4. Read [**Security Hardening**](./security-hardening.md) for native C++ JNI bridge configuration and Android KeyStore hardware backing (TEE / StrongBox).

### 💻 For Application Developers & Contributors
1. Start with [**Codebase Structure & File Guide**](./code-structure.md) for a complete tour of directories, files, and module responsibilities.
2. Walk through [**User & Backend Flow Walkthrough**](./user-flow.md) to trace the exact UI state transitions and background operations during scans and writes.
3. Read [**Bulk Scanning v2**](./bulk-scanning-v2.md) to understand multi-file distributed storage across physical NFC tags.
4. Consult [**CONTRIBUTING.md**](../CONTRIBUTING.md) for pull request workflows, style guides, and ethical coding boundaries.

---

## 3. Subsystem Architectural Matrix

| Subsystem | Directory | Languages | Core Responsibility |
| :--- | :--- | :--- | :--- |
| **Native Security Core** | `android/app/src/main/cpp/` | C++17 | Kernel-level anti-debugging (`ptrace`), `/proc/self/maps` inspection, RAM page locking (`mlock`), non-optimizable memory zeroization. |
| **Platform Gateway** | `android/app/src/main/java/` | Kotlin | `FLAG_SECURE` window enforcement, Android KeyStore AES-256-GCM hardware master key (TEE / StrongBox), JNI bridge. |
| **Hardened Security** | `src/security/` | TypeScript | Fail-closed integrity assertion, 4-pass memory wiping (`0xAA`, `0x55`, CSPRNG, `0x00`), log secret redaction. |
| **Contracts** | `src/contracts/` | TypeScript | Single source of truth for binary envelope wire layouts, error codes, state machines, and key schemas. |
| **Cryptographic Core** | `src/crypto/` | TypeScript | Argon2id KDF, AES-256-GCM AEAD, Cauchy Reed-Solomon erasure coding, NIST SP 800-38D key wrapping. |
| **Local Vault** | `src/vault/` | TypeScript | Encrypted MMKV database, ephemeral session lifecycle with auto-lock, 72-hour chunk cache, BIP39 disaster recovery. |
| **NFC Abstraction** | `src/nfc/` | TypeScript | Android foreground dispatch, Type 2 tag identification, atomic NDEF read/write, mandatory read-back verification. |
| **Operations Engine** | `src/operations/` | TypeScript | Finite state machines orchestrating single and bulk tag scanning, writing, file reconstruction, and destructive wiping. |
| **Terminal UI** | `src/ui/` | TypeScript / JSX | High-contrast monospace terminal interface, real-time diagnostic status lines, zero decorative delays. |

---

## 4. Fundamental Design Invariants

Every subsystem and document in Ghost-Tag adheres strictly to these six principles:

1. **Fail-Closed Security**: If any security assertion fails (debugger detected, dynamic hooking, missing tag bytes, corrupted AAD), the operation halts immediately and sensitive memory is scrubbed.
2. **Zero Plaintext Secrets**: Passphrases, derived KEKs, unwrapped DEKs, and plaintext file payloads are **never persisted** to disk, database, shared preferences, logcat, or crash dumps.
3. **Mandatory Read-Back Verification**: A write operation is never marked successful until the tag is independently read back and validated byte-for-byte against the intended envelope.
4. **Honest Security Posture**: Ghost-Tag explicitly acknowledges what it does not protect against (physical tag cloning, physical tag destruction, or a compromised unlocked host device).
5. **No Circular Dependencies**: Subsystems follow a strict unidirectional hierarchy; modules only import downwards or sideways via contracts.
6. **100% Deterministic Testing**: Cryptographic and operational logic is covered by automated unit and integration tests with 100% pass rate.

