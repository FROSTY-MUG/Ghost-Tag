# Ghost-Tag Automated Testing & Verification Guide (`v2.1.0`)

## 1. Automated Verification Commands

| Check | Command | Current Verified Outcome |
| :--- | :--- | :--- |
| **TypeScript Check** | `npm run typecheck` | Pass (`0` errors) |
| **TypeScript Build** | `npx tsc -p tsconfig.build.json --noEmit` | Pass (`0` errors) |
| **ESLint** | `npm run lint` | Pass (`0` errors) |
| **Default Jest Suite** | `npm test -- --ci --maxWorkers=2` | Pass (**26/26 suites, 347/347 tests**) |
| **Coverage Snapshot** | `npm test -- --ci --coverage --maxWorkers=2` | `56.06% Stmts \| 46.44% Branch \| 54.67% Funcs \| 57.16% Lines` |
| **PN532 Serial Suite** | `npx jest desktop/test/pn532_serial.test.js` | Pass (**1/1 suite, 22/22 tests**; combined `369` tests) |
| **Bridge Standalone** | `node desktop/test/bridge.test.js` | Pass (APDU, capacity, HTTP `/status`, WS `sessionToken` + `Origin`) |
| **Unused-Code Scan** | `node tests/scan-unused.cjs` | Pass (`0` unused top-level declarations in `web/` & `desktop/`) |
| **Web Production Build** | `npm --prefix web run build` | Pass (`vite 6.4.6` -> `web/dist/`) |
| **Dependency Audits** | `npm audit --audit-level=moderate` & `npm --prefix web audit --audit-level=moderate` | Pass (`0` vulnerabilities) |
| **Security & QA Agents** | `python scripts/security_audit_agent.py` & `python scripts/quality_audit_agent.py` | Pass (all invariants verified) |

---

## 2. Android Gradle Verification (JDK 17+ Required)

```powershell
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
Push-Location android
./gradlew.bat test --no-daemon
Pop-Location
```

- Compiles cleanly (`BUILD SUCCESSFUL`), while `:app:testDebugUnitTest` currently outputs `NO-SOURCE` (no JVM unit tests under `android/app/src/test`).
- Launch verified cleanly on Android emulator `Medium_Phone_API_37.0`.

---

## 3. Hardware-Only Browser & Reader Policy (No Simulated NFC)
- **Automated Jest Environment**: Uses `__mocks__/react-native-nfc-manager.ts` and mock PC/SC / PN532 streams for deterministic CI coverage.
- **Runtime Application Clients**: **Zero simulated or synthetic NFC mode.** Desktop browsers communicate exclusively with real physical readers through local **Ghost Bridge** (`ws://127.0.0.1:41789` with per-connection `sessionToken` auth), while Chrome on Android requires HTTPS + Web NFC (`NDEFReader`).
- Physical hardware verification (real Android phone NFC, physical ACS ACR122U, physical ESP32/PN532, physical iPhone CoreNFC) remains pending ([`../PROJECT-STATUS.md`](../PROJECT-STATUS.md), [`../FAQ.md`](../FAQ.md)).
