# Ghost-Tag Support Policy

Thank you for using Ghost-Tag. Before opening an issue, please review our support channels and troubleshooting resources below.

---

## 1. Where to Get Help

| Need | Channel | Description |
| :--- | :--- | :--- |
| **Bug Reports** | [GitHub Issues](https://github.com/FROSTY-MUG/Ghost-Tag/issues) | Software bugs, reproducible crashes, or unexpected cryptographic exceptions. |
| **Feature Requests** | [GitHub Discussions / Issues](https://github.com/FROSTY-MUG/Ghost-Tag/issues) | Proposals for new cryptographic algorithms, hardware tag support, or UI improvements. |
| **Security Vulnerabilities** | [Security Policy](file:///c:/Users/Aryan/Desktop/Projects/Ghost-Tag/SECURITY.md) | Confidential reporting of security defects to `aryanarora26110@gmail.com`. |
| **Direct Inquiries** | Email: `aryanarora26110@gmail.com` | Architectural consultations or contributor onboarding questions. |

---

## 2. Common Troubleshooting Steps

### NFC Hardware Issues
- **Tag Not Detected**: Ensure NFC is enabled in Android System Settings. Some phone models have NFC coils positioned near the top camera module rather than the center back.
- **Incompatible Tag Type**: Ghost-Tag operates on standard NFC Forum Type 2/4/5 tags (NTAG213, NTAG215, NTAG216, ICODE SLIX). Proprietary non-standard RFID frequencies (125 kHz) or encrypted DESFire EV1/EV2 access cards are not supported as storage targets.
- **Write Interrupted**: Keep the phone steady against the tag until the haptic feedback and confirmation dialog indicate `WRITE_VERIFIED`.

### Vault & Reconstruction Issues
- **Missing Tags**: If erasure coding parity was enabled (Cauchy Reed-Solomon), the vault can reconstruct with any $K$ out of $N$ tags. If fewer than $K$ valid chunks are collected, data recovery is mathematically impossible.
- **Passphrase Loss**: The master passphrase derives the Key Encryption Key (KEK). If lost, recovery is possible **only** via your 24-word BIP39 recovery phrase generated during initial setup.

---

## 3. Scope of Support

Ghost-Tag is an open-source, offline-first personal security utility. 
- We do **not** provide commercial SLA recovery for lost passphrases or tags damaged at the silicon level.
- We do **not** provide support for cloning proprietary physical access control cards, transit passes, or payment credentials.
