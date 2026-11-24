# Ghost-Tag Automated Verification & Test Suite (`tests/`)

## 1. Overview
Repository-level verification helpers and Jest workspace test documentation. Static dead-code checks live here, while Jest unit/integration test suites live under [`../src/__tests__/`](../src/__tests__/) and [`../desktop/test/`](../desktop/test/).

## 2. Contents
- [`scan-unused.cjs`](scan-unused.cjs): Static AST/token scanner targeting `web/` and `desktop/` sources to catch unused top-level declarations before PR review.
- `npm test -- --ci --maxWorkers=2`: Runs **26 test suites / 347 tests** across cryptography, key wrapping, bulk envelopes, Cauchy Reed-Solomon erasure coding over $\mathrm{GF}(2^8)$, mocked NFC tag operations, vault sessions, RLS policies, Turnstile CAPTCHA boundaries, challenge/proof recovery, anti-enumeration, deletion purge worker, CORS policy validation, Desktop Ghost Bridge (`desktop/test/bridge.test.js`), and web Vite syntax/build verification (`src/__tests__/webSyntaxAndBuild.test.ts`).
- `npx jest desktop/test/pn532_serial.test.js`: Runs **1 suite / 22 tests** verifying ESP32/PN532 serial protocol framing, read-back hash checks, and synthetic event rejection — bringing combined coverage to **369 tests across 27 suites**.

## 3. Latest Measured Coverage (`jest --ci --coverage --maxWorkers=2`)
- **All files**: `56.06% Statements` | `46.44% Branches` | `54.67% Functions` | `57.16% Lines`
- Core layers (`src/contracts/` `100%`, `src/crypto/`, `src/security/`, `src/operations/`, `src/vault/`, `supabase/functions/_shared/`) carry high unit coverage, while browser DOM controllers in `web/app.js` require interactive Chromium/Web NFC verification.

## 4. Commands

```bash
npm run typecheck
npx tsc -p tsconfig.build.json --noEmit
npm run lint
node tests/scan-unused.cjs
npm test -- --ci --coverage --maxWorkers=2
npx jest desktop/test/pn532_serial.test.js
node desktop/test/bridge.test.js
```

Note that NFC adapter calls in Jest use `__mocks__/react-native-nfc-manager.ts`. Real physical hardware NFC tests remain open (`../PROJECT-STATUS.md`, [`../FAQ.md`](../FAQ.md)).
