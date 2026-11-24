# Ghost-Tag Project Status (`v2.1.0` Staging)

> **Honest Release State**: The latest published GitHub Release is **`v2.0.6`**. Version **`2.1.0`** is unreleased staging software. Source code hardening, CodeQL alert fixes, UI stub removal, and automated CI checks pass cleanly, while physical NFC hardware validation and live Supabase deployment remain open release gates.

---

## 1. Subsystem Implementation & Verification Matrix

| Subsystem / Control | Status | Verification Evidence |
| :--- | :--- | :--- |
| **Core TypeScript Engine (`src/`)** | ✅ Verified (Mocked NFC) | `npm run typecheck` (`0` errors), `npx tsc -p tsconfig.build.json --noEmit` (`0` errors), `npm run lint` (`0` errors) |
| **Default Jest Automated Suite** | ✅ Passing | `npm test -- --ci --maxWorkers=2`: **26/26 suites, 347/347 tests passing** |
| **PN532 Serial Protocol Suite** | ✅ Passing | `npx jest desktop/test/pn532_serial.test.js`: **1/1 suite, 22/22 tests passing** (combined **369 tests across 27 suites**) |
| **Measured Jest Coverage** | ✅ Measured | `--coverage`: `56.06% Statements` \| `46.44% Branches` \| `54.67% Functions` \| `57.16% Lines` |
| **Desktop Ghost Bridge (`desktop/`)** | ✅ Unit/WS Passing | `node desktop/test/bridge.test.js` passes; per-connection CSPRNG `sessionToken`, `timingSafeEqual`, origin allowlist, `Map` guard enforced |
| **Static Unused-Code & Audits** | ✅ Passing | `node tests/scan-unused.cjs`, `python scripts/security_audit_agent.py`, `python scripts/quality_audit_agent.py` pass |
| **Web Companion (`web/`)** | ✅ Build & Audit Clean | `npm --prefix web run build` (`vite 6.4.6`), `npm --prefix web audit --audit-level=moderate` (`0` vulnerabilities); root `npm audit` (`0` vulnerabilities) |
| **CodeQL Security Scanning** | ✅ 0 Open PR/Main Alerts | High alerts `#75`, `#76`, and follow-up `#78` on `desktop/src/server.js` fixed cleanly in PR `#34`; `.github/workflows/codeql.yml` covers `desktop/**` |
| **Android Build & Emulator Launch** | ⚠️ Emulator Only | `./gradlew.bat test --no-daemon` (`JAVA_HOME` JDK 17+/Studio JBR) builds (`BUILD SUCCESSFUL`; `:app:testDebugUnitTest NO-SOURCE`); emulator `Medium_Phone_API_37.0` launches cleanly; **physical NFC pending** |
| **Physical NFC Hardware Testing** | ⏳ Pending Gate | Physical Android handset NFC, ACS ACR122U USB PC/SC reader, and ESP32+PN532 module hardware validation remain pending |
| **Supabase Backend (`supabase/`)** | ⏳ Pending Live Deploy | Migrations & Edge Functions tested via Jest policy suites; live remote deployment and secrets configuration remain pending |
| **iOS Target (`ios/`)** | ⏸️ Deferred (`iOS Beta`) | `project.pbxproj` synced to `2.1.0` (build `7`); PR `#25` deferred pending macOS Xcode, CoreNFC entitlements, IPA `os.walk` fix, and physical iPhone test |
| **Git Tag / Release / npm Publish** | ⏳ Pending Release Gates | No `v2.1.0` tag, GitHub Release, or npm publish has been created |

---

## 2. Pull Request Resolution Ledger

| PR | Title / Scope | Resolution | Evidence & Next Action |
| :--- | :--- | :--- | :--- |
| **#24** | Bulk Scanning v2 (`Skeletor-Pirate`) | ✅ **Merged** | Audited and merged on `main` (`bulkVaultVerification.test.ts` verified). |
| **#2** | Bump `prettier` `2.8.8 -> 3.10.1` (`dependabot`) | ✅ **Merged** | Rebased onto `main`, verified in isolated worktree (`lint`/`typecheck`/`test`), passed all 4 required CI checks, squashed. |
| **#34** | Fix CodeQL `#75/#76/#78`, remove UI stubs, sync scripts/iOS `pbxproj` | ✅ **Merged** | Resolved all CodeQL alerts cleanly, removed fake UI timeouts/sample payloads, verified all 4 required CI checks, squashed. |
| **#25** | iOS CoreNFC scaffolding (`ios/ghost-tag-support`, `Skeletor-Pirate`) | ⏸️ **Deferred (`iOS Beta`)** | Merge conflicts + duplicate #24 commit; missing `GhostTag.entitlements`; `scripts/package_release_ipa.py` directory-only zip bug; legacy single-POST recovery client; requires macOS + physical iPhone. |
| **#21** | Bump `vite` `6.4.6 -> 8.3.8` in `/web` (`dependabot`) | ⏸️ **Deferred (`v2.2+`)** | Conflicts on `web/package.json` (omits `hash-wasm`); Vite 8 emits CJS `configLoader` deprecation warnings on `web/vite.config.ts`. |
| **#9** | Bump `typescript` `6.0.3 -> 7.0.2` (`dependabot`) | ⏸️ **Deferred (`v2.2+`)** | Fails `npm run lint` (exit 2, `@typescript-eslint/parser` peer `<6.1.0`) and `tsc -p tsconfig.build.json --noEmit` (exit 1, `TS5108`). |

---

## 3. Open Release Gates Required Before Tagging `v2.1.0`
1. **Android Physical-Device Gate**: Verify real `NTAG213` (v1), `NTAG215` (v1 + v2 bulk), and `NTAG216` (v1 + v2 bulk) NFC reads/writes + `logcat` on physical Android hardware.
2. **Desktop Hardware Reader Gate**: Verify live PC/SC reads/writes on a physical ACS ACR122U reader and UART framing on physical ESP32 + PN532 hardware.
3. **Web NFC on Chrome Android**: Execute live physical tap read/write over HTTPS (`https://frosty-mug.github.io/Ghost-Tag/`) using real Android Chrome hardware.
4. **Live Supabase Deployment**: Apply `20261115`–`20261126` migrations, deploy all Edge Functions, configure `IP_HASH_SALT` / `TURNSTILE_SECRET_KEY` / `CAPTCHA_TOKEN_HMAC_KEY`, and verify live Turnstile + challenge/proof recovery.
5. **Project Board Auth Refresh (Operator Local Step)**: OAuth CLI token currently carries `gist, read:org, repo, workflow, write:packages` (missing `read:project` and `project`); run `gh auth refresh -s project,read:project` interactively to publish GitHub Projects v2 board alongside tracked Issues.

---

## 4. Local Staging Release Artifact vs Published GitHub Release
- **Latest Published GitHub Release**: `v2.0.6` (`https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.6`).
- **Local Staging APK (`web/assets/Ghost-Tag-v2.1.0.apk`)**: `41,367,086 bytes` (`39.45 MB`), SHA-256 `077ecdb3ec3c052b5c30ec52d884e56461209cf92eb0cc1fe93ddd8214723952` (`web/assets/release-meta.json`). Retained strictly as a local/staging artifact until gates above close.
