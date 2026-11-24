# Ghost-Tag Documentation Portal

This directory contains the engineering specifications, architecture diagrams, security policies, ADRs, and user wiki guides for **Ghost-Tag (`v2.1.0` staging)**.

> **Moved FAQ**: The project FAQ is now maintained at the repository root in [`../FAQ.md`](../FAQ.md).

---

## Authoritative Technical Reference
- [**CANONICAL-SPECIFICATION.md**](./CANONICAL-SPECIFICATION.md) — Active source of truth for the `GTAG` (`54B` v1 / `134B` v2) binary wire formats, real NTAG21x framing capacities (`NTAG213` incompatible with v2 bulk; `NTAG215` `326B`/`333B`; `NTAG216` `706B`/`717B`), KEK/DEK key hierarchy, Cauchy Reed-Solomon over $\mathrm{GF}(2^8)$, and `v2.1.0` challenge-proof recovery protocol.

---

## Core Engineering Specifications

| Document | Domain | Focus |
| :--- | :--- | :--- |
| [**FAQ.md**](../FAQ.md) | Repository Root FAQ | 70 evidence-cited Q&As aligned with current code and CI state |
| [**architecture.md**](./architecture.md) | Subsystem Topology | Strict module layering (`contracts` -> core -> `operations` -> `ui`) |
| [**cryptography.md**](./cryptography.md) | Cryptographic Core | Argon2id tiers, AES-256-GCM AEAD, key wrapping, 4-pass memory wipe |
| [**envelope-specification.md**](./envelope-specification.md) | Wire Formats | Little-Endian v1 (`54B`, `26B` AAD) & v2 (`134B`, `74B` AAD, `32B` hash) `GTAG` envelopes |
| [**bulk-scanning-v2.md**](./bulk-scanning-v2.md) | Bulk Vaults | Multi-file splitting, Cauchy RS parity, random-order scanning, 72h RAM cache |
| [**nfc-format.md**](./nfc-format.md) & [**nfc-tag-matrix.md**](./nfc-tag-matrix.md) | NFC Hardware | ISO 14443-3A Type 2 tag layouts (`NTAG213`/`215`/`216`) and NDEF MIME records |
| [**recovery.md**](./recovery.md) | Account Recovery | Canonical 12-word BIP-39 standard, 24-word local compat, v2.1.0 challenge/proof flow |
| [**security.md**](./security.md) & [**security-hardening.md**](./security-hardening.md) | Security & Defense | Threat model, native C++ `mlock`/`ptrace`, `FLAG_SECURE`, anti-leak log redaction |
| [**security-audit.md**](./security-audit.md) | Audit Trail | Static analysis, CodeQL alerts `#75`/`#76`/`#78` remediation, RLS & rate limits |
| [**cors-policy.md**](./cors-policy.md) & [**webhooks.md**](./webhooks.md) | Edge & Bridge Policy | Origin allowlists and webhook HMAC-SHA-256 verification |
| [**code-structure.md**](./code-structure.md) & [**testing.md**](./testing.md) | Repository & QA | Annotated file tree and verified test/coverage baseline (`347 + 22` tests) |
| [**user-flow.md**](./user-flow.md) | UX State Machines | End-to-end user journeys for single-tag, bulk, wipe, and recovery flows |

## Historical Baselines & Compatibility Reports
- [**PROJECT_STATE_MEMORY.md**](./PROJECT_STATE_MEMORY.md) — Annotated historical v2.0.5 engineering dossier (updated with canonical v2.1.0 correction notes).
- [**GHOST_TAG_SYSTEM_MANUAL.md**](./GHOST_TAG_SYSTEM_MANUAL.md) — Historical v2.0.5 product manual.
- [**ios-crypto-compatibility-report.md**](./ios-crypto-compatibility-report.md) — Cross-platform compatibility analysis and iOS alignment checklist.
- [**releases/v2.0.5.md**](./releases/v2.0.5.md) — Historical v2.0.5 release archive.

## Architecture Decision Records (`docs/adr/`)
- [0001 — Cauchy Reed-Solomon Erasure Coding](./adr/0001-cauchy-reed-solomon-erasure-coding.md)
- [0002 — RFC 9106 Argon2id for Key Derivation](./adr/0002-argon2id-rfc9106-key-derivation.md)
- [0003 — Native C++ NDK Memory Zeroization](./adr/0003-native-cpp-ndk-memory-zeroing.md)
- [0004 — Offline-First Architecture & Permissions](./adr/0004-offline-first-zero-telemetry.md)

## End-User Documentation (`docs/wiki/`)
See [Wiki Home](./wiki/Home.md) for guided setup, web client usage, Ghost Bridge, batch encryption/scanning, troubleshooting, and roadmap chapters.
