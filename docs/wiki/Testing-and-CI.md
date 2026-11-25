# Testing, CI Gates & Verification Boundaries

Ghost-Tag strictly separates **automated mock-backed software verification** from **unexecuted physical hardware verification**.

## What Is Verified Automatically on CI / Local Host
- **Core TypeScript & Jest (`npm run typecheck`, `tsc -p tsconfig.build.json --noEmit`, `npm run lint`, `npm test -- --ci --maxWorkers=2`)**: `347/347` tests across `26/26` suites verifying encryption, Argon2id parameters, Cauchy RS parity, `GTAG` envelopes, UI logic, RLS policies, Turnstile replay, challenge/proof recovery, and deletion workers.
- **Desktop Ghost Bridge (`node desktop/test/bridge.test.js`, `npx jest desktop/test/pn532_serial.test.js`)**: `22/22` PN532 UART protocol tests + APDU/framing/CSPRNG session-token WebSocket checks using mock PC/SC & `MockSerialPort`.
- **Web Showcase (`npm --prefix web run build`, `node tests/scan-unused.cjs`, Chrome CDP checks)**: Vite `6.4.6` production build, zero-error JS syntax checks, and live GitHub Pages UI inspection (`#loadingScreen`, skeletons, `technical.html`, `390x844` responsive check).
- **Security Scanning**: CodeQL (`javascript-typescript` including `desktop/**`), Dependabot, secret scanning, `npm audit --omit=dev` (root & `/web`), `scripts/security_audit_agent.py`, and `scripts/quality_audit_agent.py`.
- **Android Build**: Gradle compiles cleanly (`BUILD SUCCESSFUL`); emulator launch (`Medium_Phone_API_37.0`) verified (`:app:testDebugUnitTest` currently reports `NO-SOURCE`).

## What Is NOT Physically Verified Yet
- Cold launch and logcat on a physical Android phone.
- Real RF read/write transactions on physical `NTAG213`/`215`/`216` tags via Android native NFC, Chrome Android WebNFC, ACS ACR122U USB PC/SC, ESP32/PN532 UART, or iPhone CoreNFC.
- Live hosted Supabase end-to-end integration tests.

See [`docs/testing.md`](../testing.md) and [`PROJECT-STATUS.md`](../../PROJECT-STATUS.md).
