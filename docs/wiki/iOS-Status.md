# iOS Support Status (`iOS Beta` — Deferred)

> **Status Honesty**: Ghost-Tag `v2.1.0` does **not** ship an iOS binary or physical CoreNFC validation.

## Current State on `main`
- `ios/GhostTag.xcodeproj/project.pbxproj` synchronizes `MARKETING_VERSION = 2.1.0` and `CURRENT_PROJECT_VERSION = 7`, with Swift cryptographic foundation files under `ios/GhostTag/Core/`.
- Open PR `#25` (`Skeletor-Pirate:ios/ghost-tag-support`, tracked in Issue `#38`) is **intentionally deferred to `iOS Beta`** due to:
  1. Merge conflicts on `README.md` and `package-lock.json` plus a duplicated already-merged PR `#24` commit.
  2. Missing `ios/GhostTag/GhostTag.entitlements` (`com.apple.developer.nfc.readersession.formats`) and `CODE_SIGN_ENTITLEMENTS`.
  3. Directory-only archive bug in `scripts/package_release_ipa.py` (`os.walk` required for valid `.ipa` packaging).
  4. Legacy single-POST client recovery code needing alignment with `v2.1.0` Turnstile + challenge/proof Edge Functions.
  5. Unverified macOS Xcode build (`xcodebuild`/`XCTest`) and physical iPhone CoreNFC validation (hardware unavailable on the current Windows host).

See [`ios/README.md`](../../ios/README.md) and [`PROJECT-STATUS.md`](../../PROJECT-STATUS.md).
