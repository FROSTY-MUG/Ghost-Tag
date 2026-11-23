# Android Installation

The Ghost-Tag Android APK is the primary full-featured client. It provides direct hardware-level NFC access, background tag intent interception, physical sector verification, and safe entry deletion.

---

## 1. Downloading the APK

Always download official Ghost-Tag APK releases directly from the GitHub repository:
- **Releases Page**: [https://github.com/FROSTY-MUG/Ghost-Tag/releases](https://github.com/FROSTY-MUG/Ghost-Tag/releases)
- **Direct Asset**: `Ghost-Tag-v2.1.0.apk`

---

## 2. Integrity Verification

Before installing, verify the SHA-256 checksum of the downloaded file:

### Windows (PowerShell)
```powershell
Get-FileHash -Algorithm SHA256 .\Ghost-Tag-v2.1.0.apk
```

### Linux / macOS
```bash
sha256sum Ghost-Tag-v2.1.0.apk
```

### Expected Checksum for v2.1.0:
```text
27bb49ae1bba7a110022e3f0df8f220f8a58bbe878f658c511cc0508730e8a31
```

---

## 3. Installation Steps

1. Transfer the `.apk` file to your Android device (or download directly in your mobile browser).
2. Tap the downloaded APK in your device's file manager or notification drawer.
3. If prompted with *"Install unknown apps"*, enable permission for your browser or file manager.
4. Tap **Install**.
5. Ensure NFC is enabled in Android Settings:
   - Go to **Settings** → **Connected devices** → **Connection preferences** → **NFC** → **On**.

---

## 4. Permissions
Ghost-Tag requests only the minimum hardware permissions required for its function:
- `android.permission.NFC`: To communicate with NFC tags.
- `android.permission.VIBRATE`: To provide tactile feedback when a tag is detected or written.
- Ghost-Tag does **NOT** request location, contacts, camera, microphone, or telephony permissions.
