# Ghost-Tag Android Client

Ghost-Tag Android is the primary, full-featured native client for Ghost-Tag encrypted NFC storage.

---

## 1. Overview & Capabilities

- **Direct Hardware NFC Access**: Full ISO/IEC 14443 Type A, Mifare Ultralight, and NDEF raw page read/write transceiver.
- **Hardware-Backed Keystore**: Secure key isolation using Android Keystore and Argon2id memory-hard KDF.
- **Offline Invariant**: Zero internet or network permissions (`android.permission.INTERNET` is omitted from `AndroidManifest.xml`).
- **Binary Envelope Support**: Compatible with the canonical Ghost-Tag NDEF envelope format (`application/vnd.ghost.secure` and `application/vnd.ghost.bulk`).
- **Mixed Tag Handling**: Real-time capacity computation and chunk distribution across NTAG213, NTAG215, and NTAG216 chips.

---

## 2. Building from Source

### Prerequisites
- Android Studio Hedgehog (2023.1.1) or newer
- JDK 17
- Android SDK Platform 34
- Android NDK 25.1+

### Build Commands
```bash
cd android

# Build Debug APK
./gradlew assembleDebug

# Build Signed Release APK
./gradlew assembleRelease
```

The output APK will be generated at:
`android/app/build/outputs/apk/release/app-release.apk`

---

## 3. Architecture & Security Invariants

```
+-------------------------------------------------------+
| UI Layer: React Native (TypeScript, Brutalist Theme) |
+-------------------------------------------------------+
                           |
+-------------------------------------------------------+
| JNI / NDK Bridge: Native C++ Memory Zeroing (memset_s)|
+-------------------------------------------------------+
                           |
+-------------------------------------------------------+
| Android Keystore + Argon2id (RFC 9106) KDF            |
+-------------------------------------------------------+
                           |
+-------------------------------------------------------+
| Android NFC Adapter (NDEF Reader / Writer)            |
+-------------------------------------------------------+
```

---

## 4. Hardware Validation Status

> [!IMPORTANT]
> **Pending Physical Hardware Execution**: The Android release build pipeline compiles cleanly with verified v2/v3 signatures. However, physical device launch and NFC read/write testing on real physical Android hardware remain pending physical device connection. No claim of physical hardware validation is made without real-device test logs.

