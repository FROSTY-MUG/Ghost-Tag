# Physical Hardware Validation

> **Current Status**: **Pending** ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)). No physical NFC hardware test results are claimed for `v2.1.0`.

## Verified vs. Pending Matrix

| Surface | Verified Today | Pending Hardware Gate |
|---|---|---|
| **Android App** | Emulator launch (`Medium_Phone_API_37.0`), Gradle debug & unit build | Physical Android handset via USB (`adb` `logcat`) + physical NTAG213/215/216 tap |
| **Desktop Ghost Bridge** | Standalone bridge tests + 22/22 mocked PN532 serial tests | Physical ACS ACR122U (PC/SC) + ESP32/PN532 USB-UART hardware |
| **Web Companion** | Live GitHub Pages UI & Vite production build | Chrome on physical Android handset with Web NFC |
| **iOS App** | Deferred (`PR #25`, [Issue #38](https://github.com/FROSTY-MUG/Ghost-Tag/issues/38)) | macOS `xcodebuild` + physical iPhone CoreNFC |

## Canonical Sources
- [PROJECT-STATUS.md](../../PROJECT-STATUS.md)
- [Testing-and-CI.md](Testing-and-CI.md)
- [Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)
