# Ghost-Tag Scripts & Automation Subsystem

## Overview
The `scripts/` directory contains automation, verification, fixture generation, branding rendering, and release packaging tooling for the Ghost-Tag repository.

---

## Important Files

| File | Purpose | Environment |
| :--- | :--- | :--- |
| `security_audit_agent.py` | Automated policy auditor verifying zero-secrets, Android platform hardening, binary envelope invariants, and supply-chain integrity. | Python 3.10+ |
| `quality_audit_agent.py` | Automated quality gate verifying version synchronization across targets, strict TypeScript type checking, and Jest test completion. | Python 3.10+ |
| `generate_branding_assets.py` | Generates canonical Ghost-Tag visual assets (Android mipmaps, iOS icons, web favicons, desktop bridge icons, and GitHub social preview) using Pillow. | Python 3.10+ (`Pillow`) |
| `generate_compatibility_fixtures.js` | Generates deterministic cryptographic test vectors, v1 binary envelopes (54B overhead), v2 bulk envelopes (134B overhead), and BIP-39 recovery vectors. | Node.js 22+ |
| `package_release_apk.py` | Validates Android release compilation outputs, verifies SHA-256 integrity, and generates release metadata. | Python 3.10+ |
| `patch_dependencies.js` | NPM postinstall hook resolving upstream dependency compatibility and peer conflicts across React Native and Jest. | Node.js 22+ |
| `verify-webhook.js` | HMAC-SHA256 signature verification utility for deployment and cloud webhooks. | Node.js 22+ |

---

## How to Run & Build

### Running Security & Quality Audit Agents
```bash
# Security invariant audit
python scripts/security_audit_agent.py

# Quality gate audit
python scripts/quality_audit_agent.py

# Combined audit
npm run audit
```

### Generating Compatibility Fixtures
```bash
node scripts/generate_compatibility_fixtures.js
```

### Generating Branding Assets
```bash
python scripts/generate_branding_assets.py
```

---

## How to Test
The scripts are executed as required steps in the following GitHub Actions workflows:
- `.github/workflows/agent-security-audit.yml`
- `.github/workflows/agent-quality-gate.yml`
- `.github/workflows/ci.yml`

Local testing can be verified by running `npm run audit` and confirming exit code `0`.

---

## Contributor Guidelines

1. **How to add a feature or script**:
   - Write standalone, idempotent Python or Node.js scripts.
   - Scripts must exit with status `0` on success and non-zero on failure.
   - Do not bundle hardcoded API tokens, credentials, or private keys.
2. **How to avoid committing secrets or generated artifacts**:
   - Never commit `.keystore`, `.env`, or `.apk` files directly to Git.
   - All generated binaries must be ignored via `.gitignore`.
3. **How to avoid making unsupported hardware claims**:
   - Do not hardcode synthetic NFC scan logs or mock serial test results as proof of physical hardware validation.
