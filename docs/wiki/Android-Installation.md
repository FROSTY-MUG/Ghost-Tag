# Android Installation (`v2.0.6` Release / `v2.1.0` Staging)

> **Release Honesty Note**: The latest published GitHub Release is **`v2.0.6`** ([v2.0.6 Release](https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.6)). **`v2.1.0`** (`Ghost-Tag-v2.1.0.apk`, `versionCode 7`) is an unreleased local staging APK pending real physical NFC handset validation and live Supabase deployment (`../../PROJECT-STATUS.md`).

---

## 1. Requirements
- Android `8.0+` (`minSdk 26`, `targetSdk 36`).
- Hardware NFC transceiver enabled in Android System Settings for physical tag operations.

## 2. Local Staging Checksum Verification (`v2.1.0`)
If verifying the local staging build [`web/assets/Ghost-Tag-v2.1.0.apk`](../../web/assets/Ghost-Tag-v2.1.0.apk) (`41,367,086` bytes / `39.45 MB`):

```bash
sha256sum web/assets/Ghost-Tag-v2.1.0.apk
```

Expected SHA-256 (`web/assets/Ghost-Tag-v2.1.0.apk.sha256`):

```text
077ecdb3ec3c052b5c30ec52d884e56461209cf92eb0cc1fe93ddd8214723952  Ghost-Tag-v2.1.0.apk
```

## 3. Building & Packaging Locally (JDK 17+ Required)

```powershell
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
$env:ANDROID_KEY_ALIAS = "<your-alias>"
$env:ANDROID_KEYSTORE_PASSWORD = "<your-password>"
python scripts/package_release_apk.py
```

See [`../../android/README.md`](../../android/README.md) and [`../../FAQ.md`](../../FAQ.md).
