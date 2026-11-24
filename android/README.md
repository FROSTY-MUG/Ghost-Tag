# Ghost-Tag Android Client (`v2.1.0`)

## 1. Purpose
Native React Native (`0.84.1`) + Kotlin + C++17 (NDK/CMake) Android client and security runtime for Ghost-Tag. Implements physical NFC Forum Type 2 tag reading/writing, hardware-backed AndroidKeyStore TEE key protection, `FLAG_SECURE` window protection, native ptrace/Frida/root/memory-locking checks, and local offline vault management.

## 2. Architecture & Key Files
- [`app/build.gradle`](app/build.gradle): `applicationId "com.ghosttag"`, `versionCode 7`, `versionName "2.1.0"`, `minSdk 26`, `targetSdk 36`, `compileSdk 37`, Hermes + New Architecture, CMake C++17 native security library (`libghosttag_security.so`), release R8/ProGuard hardening.
- [`app/src/main/AndroidManifest.xml`](app/src/main/AndroidManifest.xml): Declares `android.permission.NFC`, `<uses-feature android:name="android.hardware.nfc" android:required="false" />`, `android.permission.INTERNET` (used only when optional Supabase cloud metadata sync or dev Metro bundling is enabled; cleartext traffic disabled via `res/xml/network_security_config.xml`), `android:allowBackup="false"`, and NFC tech dispatch filters.
- [`app/src/main/java/com/ghosttag/`](app/src/main/java/com/ghosttag/): `MainActivity.kt` (`FLAG_SECURE`), `MainApplication.kt`, `security/KeyStoreMasterKey.kt`, `security/SecurityBridgeModule.kt`, `security/SecurityPackage.kt`.
- [`app/src/main/cpp/`](app/src/main/cpp/): `CMakeLists.txt`, `security_core.cpp/.h`, `secure_memory.cpp/.h` (`mlock` + 4-pass volatile zeroization + compiler barrier), `jni_bridge.cpp`.
- [`app/src/main/res/`](app/src/main/res/): Custom Ghost-Tag adaptive launcher icons (`mipmap-*`) and pitch-black splash resources (`#000000` / `#FFFFFF` / `#DC2626`).
- [`app/src/main/assets/index.android.bundle`](app/src/main/assets/index.android.bundle): Pre-bundled React Native JS bundle kept in sync with `src/`.

## 3. Build & Verification (JDK 17+ Required)
Gradle requires JDK 17+ (`OpenJDK 25.0.4` via Android Studio JBR or Adoptium JDK 17; a legacy JRE 8 on `PATH` will fail):

```powershell
# PowerShell (Windows with Android Studio JBR)
$env:JAVA_HOME = "C:\Program Files\Android\Android Studio\jbr"
Push-Location android
./gradlew.bat test --no-daemon
Pop-Location
```

```bash
# Re-bundle React Native JS bundle after modifying src/
npx react-native bundle --platform android --dev false --entry-file index.js --bundle-output android/app/src/main/assets/index.android.bundle
```

To package a signed release APK via [`../scripts/package_release_apk.py`](../scripts/package_release_apk.py), supply `ANDROID_KEY_ALIAS` and `ANDROID_KEYSTORE_PASSWORD` environment variables (never store passwords in source control).

## 4. Verification Status & Hardware Caveats
- **Gradle Build (`./gradlew.bat test --no-daemon`)**: Compiles cleanly (`BUILD SUCCESSFUL`). Note that `:app:testDebugUnitTest` currently outputs `NO-SOURCE` because no standalone JVM unit tests exist under `android/app/src/test`.
- **Emulator Launch**: Verified clean launch on `Medium_Phone_API_37.0` with custom branding and zero crash signatures in `logcat`.
- **Pending Physical Hardware Gate**: Real physical Android phone NFC antenna read/write validation against physical `NTAG213` / `NTAG215` / `NTAG216` tags remains open (`PROJECT-STATUS.md`, [`../FAQ.md`](../FAQ.md)).
