# Ghost-Tag Security Policy & Threat Model

Ghost-Tag is designed with a defensive, privacy-first posture. We treat vulnerabilities with the highest priority.

---

## 1. Reporting Security Vulnerabilities

If you discover a security defect, cryptographic vulnerability, or memory-exposure bug in Ghost-Tag:
- **Direct Contact**: Email Aryan Arora at [aryanarora26110@gmail.com](mailto:aryanarora26110@gmail.com).
- **Subject**: `[SECURITY VULNERABILITY] Ghost-Tag - <Brief Description>`
- **Response SLA**: Initial triage acknowledgement within 48 hours.
- Please do not open public GitHub issues for unpatched vulnerabilities until coordinated disclosure has occurred.

---

## 2. Core Threat Model

Ghost-Tag defines explicit adversarial capabilities and cryptographic boundaries.

| Adversary Profile | Adversary Capabilities | Ghost-Tag Defensive Guarantee |
| :--- | :--- | :--- |
| **Physical Finder of Lost Tag** | Can tap, read, clone, or dump raw tag memory. | Cannot decrypt payload without user master passphrase or recovery secret. Sees only authenticated ciphertext envelope. |
| **RF Sniffer / Malicious Reader** | Can intercept raw NFC RF transactions in transit. | Sees only AES-256-GCM ciphertext, 12-byte random nonce, and 16-byte random key ID. Payloads remain confidential. |
| **Tampering / Active Modifier** | Can alter bits on the NFC tag chip or swap payloads. | Modifying ciphertext or header triggers immediate GCM authentication failure (`GCM_AUTH_FAILED`). |
| **Tag Cloner** | Can duplicate the exact byte contents of a tag to a secondary blank tag. | Ciphertext remains secure. Ghost-Tag verifies cryptographic authenticity but explicitly cannot prevent physical cloning of static data. |
| **Compromised Unlocked Phone** | Malware with root/screen capture running on active host OS. | **Non-goal**. Ghost-Tag cannot defend against a root-compromised host OS observing active process memory. |
| **Device Replacement / Loss** | User replaces their phone or deletes local vault. | Recoverable via 24-word BIP39 recovery phrase through dedicated recovery envelope derivation. |

---

## 3. Cryptographic Invariants

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
   - Volatile buffers are zeroized immediately following cryptographic operations.
