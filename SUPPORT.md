# Ghost-Tag Support & Operational Guidance

Need help with **Ghost-Tag**? Review the resources below before opening an issue.

| Channel / Topic | Target | Scope |
| :--- | :--- | :--- |
| **Frequently Asked Questions** | [`FAQ.md`](FAQ.md) | 70 evidence-cited answers covering wire formats, NTAG21x limits, Argon2id, recovery, and Ghost Bridge |
| **Technical Documentation** | [`docs/README.md`](docs/README.md) & [`docs/CANONICAL-SPECIFICATION.md`](docs/CANONICAL-SPECIFICATION.md) | Architecture, envelope layouts, cryptography, and cloud recovery specs |
| **Troubleshooting Guide** | [`docs/wiki/Troubleshooting.md`](docs/wiki/Troubleshooting.md) | Common NFC scan errors, USB permissions, Turnstile/cloud checks, and Android diagnostics |
| **Bug Reports & Feature Requests** | [GitHub Issues](https://github.com/FROSTY-MUG/Ghost-Tag/issues) | Use the `.github/ISSUE_TEMPLATE/` templates (`bug_report`, `feature_request`, `nfc_compatibility`, `documentation_issue`) |
| **Security Vulnerabilities** | [`SECURITY.md`](SECURITY.md) | Private reporting to `aryanarora26110@gmail.com` (`72-hour` acknowledgment SLA) |
| **Project Status & Release Gates** | [`PROJECT-STATUS.md`](PROJECT-STATUS.md) | Live status of CI, PR triage, physical hardware validation, and cloud deployment |

## Key Operational Reminders
- **Local-First by Default**: Offline vault creation, single-tag/bulk encryption, and tag reads/writes do not require internet access or Supabase accounts.
- **Passphrase & Recovery**: Loss of a Master Passphrase is only recoverable locally via your BIP-39 phrase (**12-word** primary cross-platform format; `24-word` retained only for legacy local unwrapping) or via opt-in encrypted cloud recovery metadata (`v2.1.0` challenge/proof once deployed). Neither maintainers nor servers can reset lost offline passphrases.
- **v2.1.0 Staging Status**: Latest published GitHub Release is `v2.0.6`. Do not distribute unverified staging builds as production releases until physical NFC and live Supabase gates close.
