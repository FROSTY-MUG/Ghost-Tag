# Contributing to Ghost-Tag

Thank you for your interest in improving Ghost-Tag. We welcome code contributions, security audits, and architectural improvements.

---

## 1. Governance & Project Communication

For questions, architectural discussion, or coordinated vulnerability disclosures:
- **Lead Maintainer**: Aryan Arora (GitHub: [@FROSTY-MUG](https://github.com/FROSTY-MUG))
- **Repository**: [https://github.com/FROSTY-MUG/Ghost-Tag](https://github.com/FROSTY-MUG/Ghost-Tag)
- **Security Disclosures**: Report privately via [GitHub Security Advisories](https://github.com/FROSTY-MUG/Ghost-Tag/security/advisories/new).

---

## 2. Fork, Development, and Build Workflow

### 2.1 Clone and Install Dependencies
```bash
git clone https://github.com/<your-username>/Ghost-Tag.git
cd Ghost-Tag

# Install root dependencies
npm install

# Install web companion dependencies
npm --prefix web install

# Install desktop Ghost Bridge dependencies
npm --prefix desktop install
```

### 2.2 Verification & Testing Commands
Every contribution must pass the full local verification suite before opening a pull request:

```bash
# 1. Strict TypeScript check
npm run typecheck

# 2. ESLint code quality gate
npm run lint

# 3. Core Jest test suite
npm test

# 4. Desktop Ghost Bridge APDU tests
npx jest desktop/test/bridge.test.js

# 5. PN532 serial transport protocol tests
npx jest desktop/test/pn532_serial.test.js

# 6. Web production bundle build
npm --prefix web run build

# 7. Android release build (when Android SDK / NDK configured)
cd android && ./gradlew :app:assembleRelease
```

---

## 3. Strict Prohibitions & Contribution Invariants

> [!CAUTION]
> **MANDATORY SECURITY INVARIANTS**

1. **Zero-Secrets Policy**:
   - Never commit `.env` files, credentials, private keys, API keys, passwords, 12-word recovery phrases, or keystores.
   - Passphrases, KEKs, and DEKs must never be logged or persisted in plaintext.
2. **No Generated Binaries or Artifacts**:
   - Never commit generated `.apk`, `.ipa`, `build/`, `dist/`, `node_modules/`, or temporary test dumps to Git.
3. **No Synthetic Hardware Evidence**:
   - Never fabricate, mock, or simulate NFC card-present events, logcat traces, or hardware compatibility claims. A hardware capability is only claimed when validated with authentic physical devices.
4. **Defensive Use Only**:
   - Ghost-Tag is explicitly engineered as a **defensive personal confidentiality vault**, not an offensive exploitation toolkit. Features intended for unauthorized card cloning or access bypass are strictly rejected.

---

## 4. Coding Standards

- **Language**: TypeScript in strict mode (`tsconfig.json`).
- **Crypto**: Use validated primitives from `react-native-quick-crypto` and `react-native-argon2`. Never roll custom cipher modes.
- **Byte Ordering**: Explicit Little-Endian encoding across all multi-byte envelope fields.
- **Constant Time**: Use `crypto.timingSafeEqual` / `timingSafeEqual()` for all cryptographic comparisons.
- **Memory Hygiene**: Use `secureWipeBuffer()` on volatile Uint8Array buffers immediately after cryptographic use.

