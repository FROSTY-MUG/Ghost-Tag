# Ghost-Tag Roadmap & Milestones

## 1. Version `v2.0.6` (Published Release)
- Latest published GitHub Release (`https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.6`) with hardened CI gates and ReDoS fixes.

## 2. Version `v2.1.0` (Current Staging — Unreleased)
- **Completed in Code & CI**:
  - Server-generated 32-byte CSPRNG `recovery_salt`, two-stage Argon2id recovery, Turnstile CAPTCHA verification, `76B` HMAC challenge/proof flow, and RLS lockdown of `ghost_vaults` & `user_accounts`.
  - CodeQL alerts `#75`, `#76`, and `#78` resolved on `desktop/src/server.js` (per-connection CSPRNG `sessionToken`, `timingSafeEqual`, allowlisted `Map` checks).
  - Removal of fabricated UI tag simulations and hardcoded sample payloads; unified `16/32/64 MiB` Argon2id tiers; PR `#24` (`bulk-scanning-v2`), PR `#2` (`prettier` `3.10.1`), and PR `#34` merged cleanly.
  - Android emulator launch verified (`Medium_Phone_API_37.0`) with custom branding.
- **Open Gates Required to Tag `v2.1.0`**:
  - Physical NFC handset validation (Android real NTAG213/215/216 reads/writes + `logcat`).
  - Physical ACS ACR122U USB PC/SC and ESP32+PN532 hardware validation.
  - Live Supabase migration & Edge Function deployment with Turnstile/HMAC/salt secrets.

## 3. Milestone: `iOS Beta` (`PR #25`, Deferred)
- Rebase PR `#25` onto `main`, add `GhostTag.entitlements`, fix `scripts/package_release_ipa.py` recursive `.app` zipping (`os.walk`), upgrade `SupabaseRecoveryClient.swift` to `v2.1.0` challenge/proof recovery, verify macOS `xcodebuild`/`XCTest`, and pass physical iPhone read-only CoreNFC tests.

## 4. Milestone: `v2.2+` Toolchain Upgrades (`PR #9`, `PR #21`, Deferred)
- Upgrade `typescript` to `7.x` once `@react-native/eslint-config` / `@typescript-eslint/parser` supports `TS 7` and `tsconfig.build.json` drops `moduleResolution: "node"`.
- Upgrade `web/` Vite (`8.x`) once `web/vite.config.ts` migrates cleanly to ESM `.mts`.

See [`../../PROJECT-STATUS.md`](../../PROJECT-STATUS.md) and [`../../FAQ.md`](../../FAQ.md).
