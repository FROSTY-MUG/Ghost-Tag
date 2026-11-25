# Ghost-Tag Autonomous Agents (`agents/`)

This directory defines specialized verification and engineering agent roles referenced by automated quality/security gates and maintainer runbooks.

## Agent Roster

| File | Role | Primary Responsibilities |
| :--- | :--- | :--- |
| [`crypto-architect.md`](crypto-architect.md) | Cryptographic Architect | Audits Argon2id KDF tiers, AES-256-GCM AEAD bounds, `GTAG` v1/v2 AAD byte offsets, Cauchy Reed-Solomon parity math, and cross-platform vector parity (`test-fixtures/`). |
| [`nfc-engineer.md`](nfc-engineer.md) | NFC Systems Engineer | Validates ISO 14443-3A Type 2 tag layouts, NDEF TLV + MIME framing math (`src/nfc/tagInfo.ts`, `desktop/src/apdu.js`), APDU transceive framing, and hardware-only policy (zero simulated NFC in production paths). |
| [`security-auditor.md`](security-auditor.md) | Security Auditor | Verifies Zero-Secrets invariants, native C++17 `mlock()`/`ptrace` probes, `FLAG_SECURE`, RLS lockdown (`user_accounts`, `ghost_vaults`), Turnstile replay protection, and CI `security_audit_agent.py` compliance. |
| [`qa-automation-agent.md`](qa-automation-agent.md) | QA Automation Agent | Enforces TypeScript strict mode, ESLint zero-error gates, full Jest & desktop test suites, unused-code checks, and version synchronization (`scripts/quality_audit_agent.py`). |

See [`../AGENT.md`](../AGENT.md) for top-level repository execution rules and [`../scripts/README.md`](../scripts/README.md) for automated script invocations.
