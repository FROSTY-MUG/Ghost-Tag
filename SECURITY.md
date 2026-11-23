# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.1.x | Yes (Current) |
| 2.0.x | Security fixes only (Historical) |

## Reporting a vulnerability

Use GitHub private vulnerability reporting:
1. Navigate to the **Security** tab of this repository ([https://github.com/FROSTY-MUG/Ghost-Tag/security](https://github.com/FROSTY-MUG/Ghost-Tag/security)).
2. Under "Reporting", click **Report a vulnerability** to open a private advisory draft.
3. Provide details, reproduction steps, and impact.

Private vulnerability reporting is the preferred channel: the report, the discussion,
and the fix are visible only to the reporter and the repository maintainers until
a coordinated disclosure is agreed. Please do **not** send sensitive material by
email or open a public issue.

Do not open a public issue for a security vulnerability.

### Never include secrets in a report

A report must never contain any of the following, even in redacted screenshots:

- Recovery phrases (12-word BIP-39 mnemonic) or master passphrases
- KEK / DEK material, wrapped keys, or evidence files exported from the vault
- Plaintext NFC contents, raw tag dumps, or decrypted vault blobs
- Supabase service-role keys, secret keys, or `IP_HASH_SALT` values
- Android keystore files (`*.keystore`, `*.jks`), keystore/alias passwords, or signing certificates
- GitHub personal access tokens or CI secrets

Refer to values by role (e.g. "the recovery verifier for a throw-away test account")
instead of pasting them. If you believe a secret was exposed, say which kind of
secret it was and rotate it yourself first.

## Response expectations

- **Acknowledgement**: within 72 hours of the private report.
- **Triage and severity assessment**: within 7 calendar days.
- **Fix or documented mitigation plan**: normally within 30 days for high/critical
  issues, best effort for lower severities.
- **Disclosure**: coordinated with the reporter; credit is given unless anonymity
  is requested.

These are targets, not guarantees — Ghost-Tag is a small maintainer-led project with
no paid security team and no bug bounty.

## Security boundaries

Ghost-Tag cannot protect data on a compromised or unlocked device.
Client-side controls do not prevent reverse engineering.

Ghost-Tag includes optional runtime environment checks, but these do not prevent reverse engineering or protect data on a compromised or unlocked device.

## Disclosure

We will coordinate disclosure with the reporter.

---

## Threat Model Matrix

Ghost-Tag defines explicit adversarial capabilities and cryptographic boundaries.

| Adversary Profile | Adversary Capabilities | Ghost-Tag Defensive Guarantee |
| :--- | :--- | :--- |
| **Physical Finder of Lost Tag** | Can tap, read, clone, or dump raw tag memory. | Cannot decrypt payload without user master passphrase or recovery secret. Sees only authenticated ciphertext envelope. |
| **RF Sniffer / Malicious Reader** | Can intercept raw NFC RF transactions in transit. | Sees only AES-256-GCM ciphertext, 12-byte random nonce, and 16-byte random key ID. Payloads remain confidential. |
| **Tampering / Active Modifier** | Can alter bits on the NFC tag chip or swap payloads. | Modifying ciphertext or header triggers immediate GCM authentication failure (`GCM_AUTH_FAILED`). |
| **Tag Cloner** | Can duplicate the exact byte contents of a tag to a secondary blank tag. | Ciphertext remains secure. Ghost-Tag verifies cryptographic authenticity but explicitly cannot prevent physical cloning of static data. |
| **Compromised Unlocked Phone** | Malware with root/screen capture running on active host OS. | **Non-goal**. Ghost-Tag cannot defend against a root-compromised host OS observing active process memory. |
| **Device Replacement / Loss** | User replaces their phone or deletes local vault. | Recoverable via 12-word BIP-39 recovery phrase through dedicated recovery envelope derivation. |

---

## Cryptographic Invariants

1. **Two-Tier Key Hierarchy**:
   - Master Passphrase $\rightarrow$ Argon2id $\rightarrow$ Ephemeral KEK (Key Encryption Key).
   - Random 256-bit CSPRNG $\rightarrow$ DEK (Data Encryption Key) per vault/tag.
   - DEKs are stored at rest exclusively wrapped via AES-256-GCM under the KEK.
   - The KEK is never persisted to disk, database, or shared preferences.
2. **Canonical Envelope & AAD Binding**:
   - `MAGIC (4B) || FORMAT_VERSION (1B) || PURPOSE (1B) || KEY_ID (16B) || CIPHERTEXT_LENGTH (4B LE)`.
   - Additional Authenticated Data (AAD) prevents cross-tag swapping, purpose alteration, and length-extension attacks.
3. **Read-Back Verification**:
   - A write operation is marked successful (`WRITE_VERIFIED`) **only after** an independent read-back compares the tag memory byte-by-byte against the written buffer.
4. **Destructive Wipe Honesty**:
   - Overwriting writable pages with zeros and random entropy mitigates flash remanence.
   - Ghost-Tag explicitly states: *Overwrites writable user memory; does not guarantee silicon-level forensic erasure*.
5. **Zero-Secrets Policy**:
   - Passphrases, KEKs, raw DEKs, and unencrypted payloads are strictly forbidden from logs, analytics, crash dumps, and database persistence.
   - Volatile buffers are zeroized immediately following cryptographic operations using platform-maintained constant-time wiping routines.
6. **Zero-Knowledge Cloud Sync (Optional)**:
   - When optional Supabase sync is configured, it stores strictly an authenticated, encrypted vault metadata blob.
   - The cloud relay never receives or stores passphrases, recovery phrases, KEKs, DEKs, plaintext files, plaintext URLs, or NFC contents.
   - Encryption, decryption, and tag workflows remain 100% functional offline without cloud connectivity.
---

## Automated security controls

| Control | Where | Notes |
| :--- | :--- | :--- |
| CodeQL code scanning (`security-extended`, `security-and-quality`) | `.github/workflows/codeql.yml` | On every push/PR to `main` plus a weekly schedule. |
| Dependabot alerts and security updates | `.github/dependabot.yml` | npm at `/`, npm at `/web`, and GitHub Actions. |
| Secret scanning and push protection | GitHub repository settings | Enable both at the organisation/repository level; they are not file-based controls. |
| History secret scan | `.github/workflows/agent-security-audit.yml` | Verified-secret scan (TruffleHog) on pushes and PRs. |
| Dependency audit gate | `ci.yml`, `release.yml` | `npm audit --audit-level=high` must pass before a release is published. |

Known advisory triage, including dependencies that are only reachable at build/test
time and the exact justification for each one, is recorded in
[`docs/security-audit.md`](docs/security-audit.md).
