# Ghost-Tag iOS Foundation (`ios/`, Beta Deferred)

## 1. Purpose
Native Swift cryptographic foundation and React Native Xcode project scaffolding for iOS (`deployment target 15.1`), mirroring Ghost-Tag binary wire formats (`GTAG` v1 `54B`, v2 `134B`) and Argon2id key derivation primitives.

## 2. Current Contents & Version Alignment
- [`GhostTag.xcodeproj/project.pbxproj`](GhostTag.xcodeproj/project.pbxproj): Synchronized to `MARKETING_VERSION = 2.1.0` and `CURRENT_PROJECT_VERSION = 7` across Debug and Release configurations (referenced via `$(MARKETING_VERSION)` and `$(CURRENT_PROJECT_VERSION)` in [`GhostTag/Info.plist`](GhostTag/Info.plist)).
- `GhostTag/Core/Crypto/`: `EnvelopeCodec.swift`, `BulkEnvelopeCodec.swift`, `Argon2idBridge.swift`.
- `GhostTag/Core/Recovery/`: `RecoveryDerivation.swift`.
- `GhostTag/Core/Cloud/`: `SupabaseRecoveryClient.swift` (requires upgrade from legacy single-POST to `v2.1.0` Turnstile + challenge/proof endpoints).
- `Tests/`: Swift unit test scaffolding (`Argon2idBridgeTests.swift`, `EnvelopeCodecTests.swift`, `RecoveryDerivationTests.swift`).

## 3. PR #25 Status (`ios/ghost-tag-support`) — Deferred (`iOS Beta`)
Open PR `#25` adds initial read-only CoreNFC scaffolding but remains deferred (`defer_with_documented_plan`) until the `iOS Beta` milestone on a macOS build host:
1. Resolve merge conflicts with `main` (`README.md`, `package-lock.json`) and drop duplicate commit `9b30b3d` already merged via PR `#24`.
2. Add `ios/GhostTag/GhostTag.entitlements` (`com.apple.developer.nfc.readersession.formats` for `TAG`/`NDEF`) and wire `CODE_SIGN_ENTITLEMENTS` in `project.pbxproj`.
3. Fix directory-entry bug in `scripts/package_release_ipa.py` (`os.walk` recursive bundle packaging for `Payload/GhostTag.app`).
4. Update `SupabaseRecoveryClient.swift` to the `v2.1.0` Turnstile + challenge/proof protocol.
5. Run macOS `xcodebuild` / `XCTest` and validate read-only CoreNFC on a physical iPhone (`../PROJECT-STATUS.md`, [`../FAQ.md`](../FAQ.md)).

## 4. Platform Limitations
On iOS, third-party browsers (Safari, Chrome iOS) do not support the Web NFC API. Physical NFC interaction on iOS requires native CoreNFC app distribution after the macOS `iOS Beta` build gate completes.
