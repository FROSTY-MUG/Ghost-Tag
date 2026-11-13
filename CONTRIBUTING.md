# Contributing to Ghost-Tag

Thank you for your interest in improving Ghost-Tag. We welcome code contributions, security audits, and architectural improvements.

---

## 1. Primary Contact & Suggestions

For suggestions, design feedback, or questions before starting significant refactors, please contact:
- **Lead Maintainer**: Aryan Arora
- **Email**: [aryanarora26110@gmail.com](mailto:aryanarora26110@gmail.com)
- **Repository**: [https://github.com/FROSTY-MUG/Ghost-Tag](https://github.com/FROSTY-MUG/Ghost-Tag)

---

## 2. Fork and Pull Request Workflow

1. **Fork the Repository**:
   Click the "Fork" button on [GitHub](https://github.com/FROSTY-MUG/Ghost-Tag) to create a copy in your personal account.
2. **Clone your Fork**:
   ```bash
   git clone https://github.com/<your-username>/Ghost-Tag.git
   cd Ghost-Tag
   npm install
   ```
3. **Create a Feature Branch**:
   ```bash
   git checkout -b feature/your-improvement-name
   ```
4. **Develop and Verify**:
   - Ensure all changes strictly maintain the **Zero-Secrets Policy** (never log, persist, or leak passphrases, KEKs, unwrapped DEKs, or plaintext).
   - Add automated Jest unit tests under `src/__tests__/`.
   - Verify all tests pass: `npm test`.
   - Verify TypeScript type compliance: `npx tsc --noEmit`.
5. **Commit and Push**:
   ```bash
   git commit -m "feat: describe your enhancement"
   git push origin feature/your-improvement-name
   ```
6. **Open a Pull Request**:
   Submit your pull request against the `main` branch of `FROSTY-MUG/Ghost-Tag` detailing your changes.

---

## 3. Strict Prohibitions & Acceptable Use

> [!CAUTION]
> **DO NOT USE THIS SOFTWARE OR CODEBASE FOR ILLEGAL PURPOSES.**

Ghost-Tag is explicitly engineered as a **defensive personal confidentiality vault**, not an offensive exploitation toolkit.
The following activities and contributions are strictly rejected:
- Features intended to emulate or duplicate third-party access control badges without authorization.
- Bypassing access control restrictions on proprietary or unauthorized NFC cards.
- Any functionality that degrades the cryptographic authentication guarantees or silently truncates encrypted payloads.
- Cloud telemetry, remote tracking, or third-party analytic trackers.

---

## 4. Coding Standards

- **Language**: TypeScript in strict mode.
- **Crypto**: Use validated primitives from `react-native-quick-crypto` and `react-native-argon2`. Never roll custom cipher modes.
- **Byte Ordering**: Explicit Little-Endian encoding across all multi-byte envelope fields.
- **Constant Time**: Use constant-time comparisons for all cryptographic hashes, authentication tags, and MAC tags.
- **Memory Hygiene**: Use `zeroize()` on volatile Uint8Array buffers immediately after cryptographic use.
