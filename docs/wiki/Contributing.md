# Contributing to Ghost-Tag

Thank you for your interest in contributing to Ghost-Tag.

---

## 1. Development Principles

1. **Zero Compromise on Security**: Never introduce server-side key escrow, unencrypted fallback storage, or telemetry.
2. **Minimal & Brutalist UI**: Follow the dark, Apple-like brutalist design philosophy. Technical complexity belongs in `/technical`, not cluttering the primary user interface.
3. **Format Compatibility**: Any changes to binary envelopes or crypto must preserve cross-platform decryption parity between the Android APK and the Web Client.
4. **No Scanned-Chunk Cache**: Do not reintroduce disk or persistent chunk caching; in-memory volatile sessions only.

---

## 2. Setting Up Your Environment

### Clone the Repository
```bash
git clone https://github.com/FROSTY-MUG/Ghost-Tag.git
cd Ghost-Tag
```

### Install Dependencies
```bash
npm install
```

### Running Test Suites
All unit tests and cryptographic assertions must pass:
```bash
npm test
```

### TypeScript Type Checking
TypeScript compilation must be 100% clean with zero warnings or errors:
```bash
npx tsc --noEmit
```

### Running Web Client Locally
```bash
cd web
npm run dev
```

---

## 3. Pull Request Guidelines

1. **Branch Naming**: Use feature branches like `feat/secure-wipe` or `fix/nfc-timeout`.
2. **Commit Hygiene**: Write clear, descriptive commit messages.
3. **Unit Tests**: Every new feature or bug fix must include corresponding tests in `src/__tests__/`.
4. **Code Quality**: Ensure linting, formatting, and strict type safety before submitting.
