# Ghost-Tag Roadmap & Milestones

> **Release Honesty**: Latest published GitHub Release is **`v2.0.6`**. **`v2.1.0`** is unreleased staging on `main` (`5f48932`). No `v2.1.0` tag, release, npm package, or live Supabase deployment has been published.

## Status Legend
- **Planned**: Committed work for `v2.1.0` or next milestone.
- **Blocked**: Waiting on external hardware, credentials, or interactive action.
- **Proposed**: Scoped for future consideration; not yet scheduled.
- **Under investigation**: Feasibility or compatibility evaluation in progress.
- **Not planned**: Explicitly out of current scope.

---

## Roadmap Matrix

| Item | Target | Status | Notes / Evidence |
|---|---|---|---|
| **1. Current `v2.1.0` Code & CI Baseline** | `v2.1.0` | **Planned** (Code Complete) | `347/347` Jest tests, `22/22` PN532 serial tests, desktop bridge tests, CodeQL `0`, Dependabot `0`, GitHub Pages live |
| **2. Physical Android Launch & `logcat` Gate** | `v2.1.0` | **Blocked** | Emulator verified (`emulator-5554`); physical USB handset required ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)) |
| **3. Physical NTAG213/215/216 NFC Validation** | `v2.1.0` | **Blocked** | Requires physical NFC tags & reader/handset ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)) |
| **4. Desktop ACS ACR122U Validation** | `v2.1.0` | **Blocked** | Mock bridge verified; physical ACR122U PC/SC test pending ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)) |
| **5. ESP32 / PN532 Serial Hardware Validation** | `v2.1.0` | **Blocked** | `22/22` protocol tests pass; physical UART hardware pending ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)) |
| **6. Web NFC Validation (Chrome for Android)** | `v2.1.0` | **Blocked** | Live GitHub Pages verified; physical Android Chrome NFC tap pending ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)) |
| **7. Live Supabase Project & Deployment (`ap-south-1`)** | `v2.1.0` | **Blocked** | Pending project creation, Turnstile site key, and secret setup ([Issue #37](https://github.com/FROSTY-MUG/Ghost-Tag/issues/37)) |
| **8. Live Supabase Integration Testing** | `v2.1.0` | **Blocked** | Pending live deployment (`verify-captcha`, `account-auth`, `recover-vault`) |
| **9. GitHub Project Creation (`v2.1.0` Tracker)** | `v2.1.0` | **Blocked** | Pending interactive `gh auth refresh -s project,read:project` |
| **10. iOS CoreNFC Beta (`PR #25`)** | `iOS Beta` | **Blocked** | Deferred (`CHANGES_REQUESTED`); needs macOS archive + entitlements + physical iPhone ([Issue #38](https://github.com/FROSTY-MUG/Ghost-Tag/issues/38)) |
| **11. Vite 8 Upgrade (`PR #21`)** | `v2.2+` | **Planned** (Deferred) | Deferred until `web/vite.config.ts` migrates cleanly to ESM `.mts` ([Issue #39](https://github.com/FROSTY-MUG/Ghost-Tag/issues/39)) |
| **12. TypeScript 7 Upgrade (`PR #9`)** | `v2.2+` | **Planned** (Deferred) | Deferred until ESLint React Native parser supports TS 7 ([Issue #39](https://github.com/FROSTY-MUG/Ghost-Tag/issues/39)) |
| **13. Android JVM Unit Tests** | `v2.2+` | **Proposed** | Currently `:app:testDebugUnitTest NO-SOURCE`; add Kotlin/Java unit tests |
| **14. Desktop `package-lock.json` & Audit** | `v2.2+` | **Planned** | Generate lockfile in `desktop/` so `npm audit` covers bridge dependencies |
| **15. GitHub Actions Deprecation Cleanup** | `v2.2+` | **Planned** | `codeql-action` upgraded `v3` → `v4` in PR `#43`; review `deploy-pages` / Dependabot actions |
| **16. Email Verification on Free Tier** | `v2.1.0` | **Not planned** | Excluded on Supabase Free Tier (`2` emails/hr limit without custom SMTP); uses anonymous/phrase flow |
| **17. Future Release Planning** | `v2.2+` | **Under investigation** | See [Future Prospects](Future-Prospects.md) |

See [PROJECT-STATUS.md](../../PROJECT-STATUS.md) and [FAQ.md](../../FAQ.md).
