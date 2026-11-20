# Ghost-Tag v2.0.6 Release Notes

## Overview

Ghost-Tag v2.0.6 delivers comprehensive security hardening, static analysis remediation, and release pipeline integrity enforcement. This release resolves all open CodeQL findings (including syntax errors, client-side DOM XSS, polynomial ReDoS, and insecure randomness) and all open Dependabot alerts, hardens Android release builds by eliminating debug keystore fallback, introduces atomic file operations to eliminate TOCTOU races, and integrates end-to-end AST validation for web client builds.

## Added

- Automated AST & Bundle Verification: Added `src/__tests__/webSyntaxAndBuild.test.ts` to enforce JavaScript syntax parsing and Vite bundle compilation in automated CI gates.
- Atomic Dependency Patching: Implemented unique temporary file staging and atomic descriptor replacement in `scripts/patch_dependencies.js`.
- Strict Keystore Guards: Added `gradle.taskGraph.whenReady` execution guards in `android/app/build.gradle` to strictly reject unsigned or debug-signed release artifacts.

## Changed

- Android CI Workflow: Separated release APK packaging (requiring four valid GitHub Secrets) from debug CI smoke testing in `.github/workflows/android-build.yml`.
- Dynamic APK Signer Discovery: Upgraded `.github/workflows/release.yml` with dynamic `apksigner` discovery and explicit rejection of Android debug keys.
- CodeQL Matrix Alignment: Streamlined `.github/workflows/codeql.yml` to target `javascript-typescript`.

## Fixed

- Web Client Syntax Error (Alert #6): Removed orphaned `catch` block in `web/app.js:1168`.
- Payload Validation Conditional (Warning #5): Replaced redundant conditional with strict type and length validation in `src/operations/writeOperation.ts:73`.
- Client-Side DOM XSS (Alert #60): Refactored `renderScanHistory` in `web/app.js:818` to use safe DOM `createElement` and `textContent`.
- Incomplete Regex Meta-Character Escape (Alert #61): Escaped all meta-characters in `tests/scan-unused.cjs:141`.
- Unused Loop Identifier (Alert #62): Replaced `.entries()` with `.values()` in `web/app.js:506`.
- Polynomial Regular Expression ReDoS (Alert #1): Replaced unanchored regex in `src/cloud/supabaseClient.ts:63` with strict RFC 4122 UUID matcher.
- Insecure Randomness (Alerts #2 & #3): Replaced `Math.random()` with WebCrypto `crypto.getRandomValues()` in `web/supabase.js:234` and `web/supabase.js:266`.

## Security

- Zero Open CodeQL Alerts: 0 open security alerts confirmed via GitHub Code Scanning API.
- Zero Open Dependabot Alerts: 0 open vulnerability alerts confirmed via GitHub Dependabot API.
- Supply Chain Hardening: Resolved `minimatch` ReDoS (`GHSA-7r86-5chv-c4rg`) via scoped override to `11.0.9`. Evaluated and dismissed withdrawn `deepmerge` advisory as tolerable risk.
- Zero Secrets Tracked: Full secret hygiene verified across codebase and git history.

## Dependencies

- `@typescript-eslint/typescript-estree`: Scoped override to `minimatch@^11.0.9`.
- Verified `npm audit` reports 0 vulnerabilities.

## Verification

- Exact test suite count: 14 passed / 14 suites (184 passed / 184 tests).
- TypeScript typecheck result: 0 errors (`npx tsc --noEmit` in strict mode).
- Lint result: 0 errors, 14 style warnings (`npm run lint`).
- Web build result: Vite v6.4.6 production build succeeded in 216ms (`dist/index.html` 34.70 kB).
- Android build result: Clean debug APK build succeeded on GitHub Actions (`assembleDebug` passed, 9m 35s).
- CodeQL result: 0 open alerts (`CodeQL Analysis` workflow passed in 1m 13s).
- Dependabot status: 0 open alerts (verified via GitHub Dependabot API).
- APK SHA-256: No release APK created (release tagging blocked pending explicit approval).

## Known limitations

- Deployment blocker: Live Supabase deployment requires `SUPABASE_ACCESS_TOKEN` and linked project ref.
- Hardware blocker: Physical NFC validation requires a supported Android device, physical NTAG213/215/216 tags, and optionally an ACS ACR122U USB reader for Ghost Bridge testing.
- Offline-first web NFC requires Chrome on Android or Ghost Bridge desktop companion on desktop browsers (Web NFC is unsupported on iOS Safari).

## Security boundary

Ghost-Tag includes optional runtime environment checks, but these do not prevent reverse engineering or protect data on a compromised or unlocked device.
