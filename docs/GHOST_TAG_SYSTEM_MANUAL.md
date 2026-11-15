Ghost-Tag can be designed as a cross-platform encrypted NFC vault, but you must separate three things: the Android APK, the web app, and iOS. They can share the same encrypted NFC format, but they cannot all have the same NFC permissions or capabilities.
The realistic cross-platform rule is:
A tag written by the Android APK can be read by the web app or iOS app only if that platform supports NDEF reading, the user has the correct passphrase/key material, and the tag has enough accessible NDEF data.
Web NFC in Chrome on Android supports NDEF reading and writing, requires HTTPS, and is limited to NDEF; it does not guarantee raw-tag access or support on every browser. iOS does not provide the same Web NFC API, so a website cannot reliably replace an iOS native app for NFC reading or writing.developer.chrome+1
1. What Ghost-Tag is
Ghost-Tag is an offline encrypted NFC storage system.
It lets a user store sensitive information on NFC tags in encrypted form. The tag can be read by anyone with an NFC reader, but the stored payload is ciphertext. Without the correct passphrase and key material, the reader sees only meaningless encrypted bytes.
It supports:
Small single-tag records.
Large files split across many NFC tags.
Text, images, videos, PDFs, ZIPs, and arbitrary binary files.
Multiple files in one vault.
Scanning tags in any order.
Temporary encrypted caching.
In-app viewing and export.
Recovery on a new device through a recovery phrase.
It is not:
A Proxmark3 or Flipper Zero replacement.
An NFC cloning tool.
A universal RFID hacking tool.
A cloud storage service.
A system that prevents tag copying or deletion.
A system that protects data on a compromised unlocked phone.
2. What it is made for
Ghost-Tag is made for people who want to carry small or medium-sized sensitive data physically, offline, and encrypted.
Examples:
A student carrying encrypted study notes.
A developer carrying a server-recovery note.
A person carrying an emergency contact instruction.
A small business storing asset or inventory information.
A photographer carrying encrypted project metadata.
A user backing up a small encrypted archive across multiple NFC tags.
A person who wants an offline, physical “encrypted USB stick” using NFC tags.
The important use case is personal offline encrypted storage, not anonymous identity, payment, access control, or RFID security testing.
3. Core purposes
Purpose
What Ghost-Tag does
Confidential storage
Encrypts file data before writing it to NFC tags
Integrity protection
Detects modified, corrupted, or tampered ciphertext
Offline access
Works without a server or internet connection
Portable storage
Stores encrypted data on physical NFC tags
Large-file support
Splits encrypted files across multiple tags
Random-order recovery
Reassembles chunks regardless of scanning order
Cross-platform interoperability
Uses a common NDEF-based encrypted format
Recovery
Lets a user restore access on a new device using a recovery phrase
Temporary cache
Avoids rescanning recently scanned tags
Export
Lets users save reconstructed files to their device
4. How a user uses it
4.1 First-time setup
text
1. Install Ghost-Tag. 2. Create a master passphrase. 3. Save the recovery phrase offline. 4. Create a vault. 5. Add files. 6. Select NFC tags. 7. Write encrypted chunks to tags. 8. Keep the tags safe.
The passphrase is the main key. The recovery phrase is the emergency backup key. The app never stores the passphrase or recovery phrase in plaintext.
4.2 Writing a file
text
1. Open Ghost-Tag. 2. Choose “New Bulk Vault”. 3. Select one or more files. 4. App calculates encrypted size. 5. App detects usable NFC capacity. 6. App calculates required tags. 7. User confirms. 8. User scans blank compatible tags one by one. 9. App writes one encrypted chunk per tag. 10. App reads each tag back and verifies it. 11. App marks the vault as complete.
If a 10 MB file needs 86 tags and the user has 100 tags, the app says:
text
Only 86 tags are required. Please set aside the other 14 tags. Scan 86 blank compatible tags one by one.
The app writes only to the 86 required tags.
4.3 Reading a file
text
1. Open Ghost-Tag. 2. Choose “Scan Bulk Vault”. 3. Tap tags one by one in any order. 4. App reads each encrypted chunk. 5. App verifies each chunk. 6. App caches verified chunks. 7. When enough chunks are collected, app reassembles the file. 8. App decrypts it. 9. User views or exports the file.
The user does not need to remember which tag contains which chunk. The app identifies chunks from their encrypted envelope.
4.4 Viewing and exporting
After reconstruction:
text
Text file -> in-app text viewer or export Image -> in-app viewer or export Video -> in-app player or export PDF -> in-app viewer or system PDF viewer ZIP -> export only Unknown file -> export only
The app should delete its temporary decrypted file after viewing or export, unless the user explicitly chooses to keep it.
5. Cross-platform model
You want Android APK, web, iOS, and other systems to read the same tags. This is possible only if every platform implements the same Ghost-Tag Interchange Format.
The tag itself must be platform-neutral. The platform-specific part is the app that reads, decrypts, displays, and writes it.
text
NFC TAG └── Ghost-Tag encrypted NDEF record | +-- Android APK +-- Web app +-- iOS app +-- Desktop app
All clients must implement:
The same NDEF MIME type.
The same binary envelope.
The same crypto algorithms.
The same key-derivation method.
The same recovery-envelope format.
The same chunking rules.
The same error codes.
If one platform changes the format without a version number, tags written by another platform may become unreadable.
6. Android APK specification
6.1 Role
The Android APK is the primary full-featured client.
It should support:
NFC reading.
NFC writing.
Bulk multi-tag writing.
Bulk random-order scanning.
File import.
File reconstruction.
In-app viewing.
File export.
Encrypted local vault.
Recovery phrase setup.
Temporary encrypted cache.
Tag wipe for supported tags.
6.2 Android capabilities
Android is the best first platform because it has broad NFC support and allows foreground NFC dispatch. Android requires NFC devices to enumerate and implement NDEF for NFC Forum Types 1–4, and recommends NFC Forum Types 1–4 for new NDEF deployments to maximize compatibility.[developer.android](https://developer.android.com/reference/kotlin/android/nfc/tech/Ndef)
6.3 Android UI flow
text
HOME ├── Create Vault ├── Unlock Vault ├── Scan Tag ├── Bulk Vault ├── Recovery └── Settings
Bulk Vault:
text
BULK VAULT ├── Create Bulk Vault ├── Add File ├── Write Tags ├── Scan Tags ├── View Files ├── Export Files ├── Cache Status └── Vault Settings
6.4 Android APK distribution
Distribute as:
Direct APK installation.
Signed release build.
Local network transfer.
Private repository.
Optional Play Store release later.
Do not rely on Play Protect or app-store review as a security boundary.
7. Web app specification
7.1 Role
The web app is a cross-platform companion client.
It should allow a user to open a website in a supported browser and read Ghost-Tag NFC tags without installing an APK.
It can also allow writing, but only on browsers and devices that support Web NFC.
7.2 Web NFC reality
Chrome on Android supports Web NFC from Chrome 89. It supports NDEF reading and writing, requires HTTPS, and is limited to NDEF. The presence of NDEFReader does not guarantee that the device has NFC hardware.developer.chrome+1
This means:
Platform
Web NFC read
Web NFC write
Notes
Android Chrome
Yes, if device supports NFC
Yes, if device supports NFC
Primary web target
Android Firefox
Not guaranteed
Not guaranteed
Must detect support
iPhone Safari
No standard Web NFC API
No standard Web NFC API
Needs native iOS app
Desktop Chrome
Usually no NFC hardware
Usually no NFC hardware
Requires external reader and native bridge
Desktop Safari
Usually no Web NFC
Usually no Web NFC
Requires native bridge
Do not promise “web works everywhere.” Build feature detection:
text
if (!"NDEFReader" in window) { show "This browser does not support Web NFC." }
7.3 Web app features
The web app should support:
Ghost-Tag format parsing.
AES-256-GCM decryption.
Argon2id key derivation.
Recovery-phrase entry.
Bulk-chunk scanning.
Chunk caching in IndexedDB.
File reconstruction.
File preview.
File download/export.
NFC writing where Web NFC is available.
Clear browser-capability warnings.
7.4 Web app limitations
The web app cannot safely provide the same level of key protection as a native app.
Browser storage is more exposed to:
XSS.
Malicious browser extensions.
Compromised browser profiles.
Local device malware.
Accidental synchronization or backup.
Therefore, the web app must not become the primary key vault.
Recommended web security model:
text
Web app = reader / emergency recovery client Android APK = primary vault and writer
The web app may decrypt a tag only after the user provides the passphrase in that browser session. It must not permanently store the passphrase, KEK, or DEK.
7.5 Web cache
Use IndexedDB for encrypted chunk cache.
Cache rules:
Store only encrypted chunks.
Encrypt cache metadata.
Expire cache after 72 hours.
Clear cache on logout.
Clear cache on vault deletion.
Never cache plaintext.
Never cache passphrase, KEK, or DEK.
Warn users that browser storage is less trustworthy than native secure storage.
8. iOS app specification
8.1 Role
iOS needs a native Swift/SwiftUI app.
A website cannot reliably provide the same NFC experience on iOS because Safari does not provide the standard Web NFC NDEFReader API used by Chrome on Android.developer.chrome+1
8.2 iOS capabilities
iOS can support:
NFC tag reading.
NDEF reading.
Core NFC-based tag sessions.
File import through the Files app.
File export through the share sheet.
Secure local storage using Keychain.
Biometric unlock.
Bulk scanning.
File reconstruction.
iOS support for writing and raw tag operations is more restricted than Android. The iOS app must clearly state what it can and cannot do on each device and iOS version.
8.3 iOS UI flow
text
HOME ├── Scan Tag ├── Bulk Vault ├── Create Vault ├── Recovery ├── Files └── Settings
8.4 iOS cross-platform rule
A tag written by Android can be read on iOS if:
The tag is NDEF-formatted.
The tag uses the same Ghost-Tag MIME type.
The iOS app implements the same envelope parser.
The user has the passphrase or recovery phrase.
The iOS device supports the required NFC operations.
A tag written on iOS can be read on Android if the same conditions are true.
9. Desktop specification
Desktop support is useful but should come after mobile.
9.1 Desktop role
The desktop app can act as:
A recovery client.
A bulk-vault manager.
A file importer/exporter.
A reader for USB NFC readers.
A writer for supported USB NFC readers.
9.2 Desktop stack
Use:
Tauri.
React frontend.
Rust backend.
pcsc crate for PC/SC smart-card readers.
SQLite or SQLCipher for local encrypted metadata.
9.3 Desktop limitations
Desktop NFC depends heavily on the USB reader and operating system.
A web app alone cannot talk to a USB ACR122U reader. The desktop app needs a native Rust backend.
Supported reader example:
text
ACR122U USB NFC reader
But the app must not claim support for every reader. It must maintain a tested-reader compatibility list.
10. Universal interchange format
To make Android, web, iOS, and desktop interoperable, define one format and treat it as a public specification.
10.1 NDEF MIME type
text
application/vnd.ghost.bulk
For single-tag records:
text
application/vnd.ghost.secure
10.2 Binary envelope
Use little-endian byte order.
text
MAGIC: "GTAG" FORMAT_VERSION: uint8 RECORD_TYPE: uint8 VAULT_ID: 16 bytes FILE_ID: 16 bytes KEY_ID: 16 bytes GLOBAL_CHUNK_INDEX: uint32 TOTAL_VAULT_CHUNKS: uint32 FILE_CHUNK_INDEX: uint32 TOTAL_FILE_CHUNKS: uint32 CHUNK_CIPHERTEXT_LENGTH: uint32 CHUNK_HASH: 32 bytes NONCE: 12 bytes CHUNK_CIPHERTEXT: variable GCM_TAG: 16 bytes
10.3 Crypto rules
All clients must use:
AES-256-GCM.
12-byte random nonce.
16-byte GCM authentication tag.
SHA-256 for chunk and file ciphertext hashes.
Argon2id for passphrase key derivation.
128-bit random salt.
256-bit derived KEK.
256-bit random DEK.
Versioned key-wrap envelope.
Versioned recovery envelope.
10.4 Compatibility rule
A client must reject unknown future format versions rather than guessing.
text
if format_version > supported_version: show "This tag uses a newer Ghost-Tag format."
11. Cross-platform recovery
A user should be able to move between Android, web, and iOS.
11.1 Recovery flow
text
1. User installs Ghost-Tag on a new device. 2. User chooses “Recover Vault”. 3. User enters recovery phrase. 4. App derives recovery KEK using Argon2id. 5. App unwraps recovery copy of DEK. 6. App restores vault metadata. 7. User scans NFC tags. 8. App decrypts and reconstructs files.
11.2 What must be portable
The recovery phrase must be enough to restore:
Vault metadata.
Wrapped DEKs.
File manifests.
Chunk indexes.
Chunk hashes.
File hashes.
Key IDs.
The recovery phrase must not be enough to reconstruct files by itself. The user still needs the physical NFC tags.
11.3 What cannot be recovered
If the user loses:
The recovery phrase, and
The passphrase,
then the encrypted NFC tags cannot be decrypted.
If the user loses physical tags, the encrypted chunks on those tags are unavailable. Without redundancy, the file cannot be reconstructed.
12. Cross-platform security differences
Platform
Key storage
NFC support
Best role
Android APK
Android Keystore / biometrics
Full read/write for supported tags
Primary vault and writer
Web app
Browser memory / IndexedDB
Chrome Android only for Web NFC
Reader and recovery client
iOS app
iOS Keychain / Secure Enclave where available
Native Core NFC; restrictions apply
Reader and mobile vault
Desktop app
OS keychain / TPM where available
Depends on USB reader
Recovery and desktop vault
Do not claim that all platforms have the same hardware security. Android, iOS, and desktop have different key-storage and NFC capabilities.
13. Data flow across platforms
13.1 Android writes, web reads
text
Android APK | v Encrypts file | v Splits ciphertext into chunks | v Writes encrypted chunks to NFC tags | v User opens Ghost-Tag website on Android Chrome | v User enters passphrase | v User scans NFC tags | v Web app reads NDEF chunks | v Web app verifies and reassembles | v Web app decrypts and displays/downloads file
13.2 Web writes, Android reads
text
Web app on Android Chrome | v User selects file | v Web app encrypts file | v Web app splits ciphertext | v Web app writes encrypted chunks to NFC tags | v User opens Android APK | v User enters passphrase or recovery phrase | v User scans tags | v Android app reconstructs and decrypts file
13.3 Android writes, iOS reads
text
Android APK writes encrypted NDEF chunks | v User opens iOS Ghost-Tag app | v User enters passphrase or recovery phrase | v iOS app scans NDEF tags | v iOS app verifies and reconstructs | v iOS app displays or exports file
13.4 iOS writes, Android reads
text
iOS app writes encrypted NDEF chunks | v User opens Android APK | v User enters passphrase or recovery phrase | v Android scans tags | v Android reconstructs and decrypts file
This works only if both apps implement the exact same format and crypto rules.
14. What “same data everywhere” means
It does not mean the plaintext is stored on every device.
It means:
text
Same encrypted NFC tag format + Same cryptographic algorithms + Same recovery format + Same chunking rules + Compatible client apps = Same files can be recovered on any supported client
The encrypted chunks are portable. The decryption capability depends on the user’s passphrase, recovery phrase, and the client app.
15. Required cross-platform test matrix
Test these paths:
Writer
Reader
Expected result
Android APK
Android APK
Full read, reconstruct, decrypt
Android APK
Web app on Android Chrome
Full read, reconstruct, decrypt
Android APK
iOS app
Full read, reconstruct, decrypt
Android APK
Desktop app with supported reader
Full read, reconstruct, decrypt
Web app on Android Chrome
Android APK
Full read, reconstruct, decrypt
Web app on Android Chrome
iOS app
Full read, reconstruct, decrypt
iOS app
Android APK
Full read, reconstruct, decrypt
iOS app
Web app on Android Chrome
Full read, reconstruct, decrypt
Desktop app
Android APK
Full read, reconstruct, decrypt
Desktop app
Web app on Android Chrome
Full read, reconstruct, decrypt
Also test:
Wrong passphrase.
Missing tag.
Corrupted tag.
Duplicate tag.
Foreign tag.
Unsupported browser.
Unsupported iOS device.
Cache expiry.
Interrupted scanning.
File export.
Cross-device recovery.
16. Recommended product phases
Phase 1: Android MVP
Build:
Android APK.
Single-file encrypted NFC vault.
Bulk multi-tag vault.
Text, image, video, PDF, ZIP, and arbitrary files.
Bulk random-order scanning.
Encrypted temporary cache.
In-app viewing.
SAF export.
Recovery phrase.
Phase 2: Web companion
Build:
Responsive web app.
Ghost-Tag parser.
AES-GCM decryption.
Argon2id.
Recovery phrase entry.
Web NFC scanning on supported Android browsers.
IndexedDB encrypted cache.
File preview and download.
Clear browser-support warnings.
Phase 3: iOS app
Build:
Native iOS app.
Core NFC reading.
Same Ghost-Tag format.
Recovery phrase support.
File import/export.
Bulk scanning.
Clear iOS capability disclosures.
Phase 4: Desktop app
Build:
Tauri desktop app.
Rust PC/SC backend.
Supported USB-reader list.
Bulk-vault management.
Recovery and export.
17. Final architecture statement
Ghost-Tag is an offline, encrypted, cross-platform NFC file-vault system. It uses a common versioned NDEF-based encrypted format so a tag written by the Android APK can be read by the web app, iOS app, or desktop app, provided that platform supports the required NFC operations and the user has the correct passphrase or recovery phrase.
The Android APK should be the primary full-featured writer and vault. The web app should be a lightweight cross-platform reader and recovery client. iOS requires a native app because browser-based NFC is not reliably available there. Desktop requires a native PC/SC backend for USB readers.
The system’s security boundary is the encrypted payload and the user-controlled key material—not physical control of the NFC tag, the browser, or the phone. NFC Forum NDEF is the interoperable data-format layer that makes cross-platform tag exchange possible, but platform NFC APIs and hardware still determine what each client can actually do. The correct model is one shared encrypted NFC format, three different clients. Android and iOS get native apps with real NFC access; the web app is a universal companion that can manage, decrypt, view, and export data, but can access NFC only on browsers/devices that support Web NFC.
text
┌──────────────────────────┐ │ Ghost-Tag NFC Tags │ │ Encrypted NDEF chunks │ └────────────┬─────────────┘ │ ┌─────────────────────┼─────────────────────┐ │ │ │ ┌───────▼────────┐ ┌────────▼────────┐ ┌────────▼────────┐ │ Android APK │ │ iOS Native App │ │ Ghost-Tag Web │ │ Full NFC │ │ Core NFC │ │ Browser client │ │ Read + Write │ │ Read + Write* │ │ NFC only on │ │ Primary vault │ │ iPhone client │ │ supported browser│ └────────────────┘ └─────────────────┘ └─────────────────┘
* iOS can read and write NDEF tags through Core NFC, but its capabilities depend on the iPhone model, iOS version, and whether the physical tag is writable. Apple’s NFCNDEFReaderSession detects NDEF tags, and NFCNDEFTag supports querying status/capacity and writing NDEF messages.developer.apple+1
1. Shared Ghost-Tag format
Every client must implement the same format. This is what makes a tag written on Android readable on iPhone, web, or desktop.
text
NFC tag └── NDEF MIME record type: application/vnd.ghost.bulk payload: Ghost-Tag encrypted binary envelope
Envelope
Use one versioned binary format:
text
"GTAG" + format version + record type + vault ID + file ID + key ID + global chunk index + total vault chunks + file chunk index + total file chunks + ciphertext length + chunk hash + AES-GCM nonce + encrypted chunk + AES-GCM authentication tag
Crypto rules
All platforms use:
AES-256-GCM.
12-byte random nonce.
16-byte authentication tag.
SHA-256 for chunk and file ciphertext hashes.
Argon2id for passphrase-derived KEK.
256-bit random DEK.
Versioned recovery envelope.
If Android, iOS, and web do not use exactly the same envelope, endianness, MIME type, nonce length, KDF parameters, and recovery format, cross-platform reading will fail.
2. Android APK model
The Android APK is the primary full Ghost-Tag client.
What it does
Detects NFC tags.
Reads NDEF records.
Writes encrypted NDEF records.
Creates bulk vaults.
Splits encrypted files into chunks.
Writes one chunk per NFC tag.
Scans tags in any order.
Caches verified chunks.
Reconstructs and decrypts files.
Views text, images, videos, and PDFs.
Exports files to phone storage.
Manages passphrase and recovery phrase.
Performs supported tag wipe operations.
Android NFC model
Android uses its native NFC stack and can use foreground dispatch so the active Ghost-Tag app receives tag events. Android’s NFC system parses NDEF messages and identifies their MIME type or URI, which is how it can route a Ghost-Tag record to the app.
text
User opens Android APK ↓ App enables foreground NFC dispatch ↓ User taps NFC tag ↓ Android delivers tag intent to app ↓ App reads NDEF record ↓ App parses Ghost-Tag envelope ↓ App verifies and decrypts ↓ User sees plaintext or file
Android role
text
Android APK = primary writer + primary vault + full mobile client
3. iOS native app model
The iOS app is the iPhone equivalent of the Android APK.
It must be a native Swift/SwiftUI app using Apple’s Core NFC framework. It is not a website wrapper.
What it does
Detects NFC tags.
Reads NDEF messages.
Writes NDEF messages to compatible writable tags.
Queries tag capacity and NDEF status.
Creates bulk vaults.
Imports files from the Files app.
Encrypts and splits files into chunks.
Writes one encrypted chunk per tag.
Scans tags in any order.
Caches verified encrypted chunks.
Reconstructs and decrypts files.
Views and exports files.
Uses Face ID / Touch ID and the iOS Keychain.
Apple documents that Core NFC can detect NFC tags, read NDEF messages, save data to writable tags, and interact with protocol-specific tags including MIFARE.
iOS NFC model
text
User opens iOS Ghost-Tag app ↓ User taps “Scan” ↓ App starts NFCNDEFReaderSession ↓ iPhone shows NFC reader UI ↓ User taps NFC tag ↓ Core NFC delivers NDEF message ↓ App parses Ghost-Tag envelope ↓ App verifies chunk ↓ App caches encrypted chunk ↓ App waits for next tag ↓ When enough chunks collected, reconstruct and decrypt
For bulk scanning, create the reader session with:
swift
invalidateAfterFirstRead = false
Apple documents that this keeps the session active so it can read multiple tags; the session ends when it times out, the user cancels it, or the app calls invalidate().[developer.apple](https://developer.apple.com/documentation/corenfc/nfcndefreadersession/init\(delegate:queue:invalidateafterfirstread:\).md)
iOS write model
text
User selects file ↓ App encrypts file ↓ App splits encrypted ciphertext ↓ User taps blank compatible tag ↓ Core NFC connects to tag ↓ App queries NDEF status and capacity ↓ App writes encrypted NDEF record ↓ App reads tag back ↓ App verifies GCM tag and chunk hash ↓ WRITE_VERIFIED
queryNDEFStatus tells the app whether the tag is read-only or read/write and its maximum NDEF capacity. writeNDEF saves an NDEF message to a writable tag.
iOS limitations
The iOS app cannot promise exact parity with Android:
NFC sessions are user-initiated; no true background scanning.
Raw tag access depends on tag family and iOS restrictions.
Not every tag is writable.
Not every iPhone supports every NFC feature.
The app must check readingAvailable before starting a session.
So the iOS app should say:
text
This iPhone supports Ghost-Tag NFC reading. Writing is available only for compatible writable tags.
iOS distribution
You do not need the App Store for personal use.
Method
Best for
Limitation
Free Apple ID + Xcode
Testing on your own iPhone
App expires after about 7 days
Paid Apple Developer Program + Xcode
Personal long-term use
Annual developer fee
Ad Hoc
Small trusted device list
Each iPhone UDID must be registered
TestFlight
Invited testers
External testers require App Review
App Store
Public release
Apple review required
For your own iPhone, the best option is paid Apple Developer Program + Xcode direct install. That gives you a native, personally installed iOS app without publishing it publicly.
4. Web app model
The web app is the universal companion, not the primary NFC client.
It should work in any modern browser for non-NFC features, but NFC itself is browser- and device-dependent.
What the web app can always do
Open the Ghost-Tag website.
Enter a recovery phrase.
Restore an encrypted vault backup.
Decrypt an exported encrypted vault, if the user provides the passphrase.
View reconstructed text files.
Download reconstructed images, videos, PDFs, and other files.
Manage vault metadata.
Show documentation and security warnings.
Store encrypted chunk cache in IndexedDB.
What the web app can do only with Web NFC
On supported browsers and devices, mainly Chrome on Android, the website can:
Detect NFC tags.
Read NDEF records.
Write NDEF records.
Scan a bulk vault.
Write encrypted chunks.
Chrome supports Web NFC on Android from Chrome 89, but it is limited to NDEF, requires HTTPS, and does not guarantee that the device has NFC hardware.
Web NFC model
text
User opens Ghost-Tag website ↓ Website checks for NDEFReader support ↓ If supported: ↓ User grants NFC permission ↓ User taps NFC tag ↓ Website reads NDEF record ↓ Website parses Ghost-Tag envelope ↓ Website verifies chunk ↓ Website caches encrypted chunk in IndexedDB ↓ When enough chunks collected, reconstruct and decrypt
Web browser matrix
Browser / platform
NFC read
NFC write
Recommended role
Chrome on Android
Yes, if device supports NFC
Yes, if device supports NFC
Web NFC client
Firefox on Android
Not guaranteed
Not guaranteed
Show unsupported message
Safari on iPhone
No
No
Recovery/view/export only
Chrome on iPhone
No
No
Recovery/view/export only
Desktop Chrome
Usually no NFC hardware
Usually no NFC hardware
Recovery/view/export only
Desktop Safari
Usually no Web NFC
Usually no Web NFC
Recovery/view/export only
The Web NFC API is not universally supported; MDN explicitly warns developers to check browser compatibility before using it in production.
Web app fallback
On iPhone or unsupported browsers, show:
text
GHOST-TAG WEB This browser cannot access NFC hardware. To scan or write Ghost-Tag NFC tags: - On iPhone: open the Ghost-Tag iOS app. - On Android: use the Ghost-Tag APK or a supported Chromium browser. You can still: - Enter recovery phrase - Restore encrypted vault backup - View reconstructed files - Download exported files
5. Cross-platform data flow
Android writes, iPhone reads
text
Android APK ↓ Encrypts file ↓ Splits encrypted ciphertext ↓ Writes encrypted chunks to NFC tags ↓ User opens iOS Ghost-Tag app ↓ Enters passphrase or recovery phrase ↓ Scans NFC tags using Core NFC ↓ iOS verifies and reassembles chunks ↓ iOS decrypts file ↓ User views or exports file
iPhone writes, Android reads
text
iOS Ghost-Tag app ↓ Encrypts file ↓ Splits encrypted ciphertext ↓ Writes encrypted chunks to NFC tags ↓ User opens Android APK ↓ Enters passphrase or recovery phrase ↓ Scans NFC tags ↓ Android verifies and reassembles chunks ↓ Android decrypts file ↓ User views or exports file
Android writes, website reads
text
Android APK writes encrypted NFC chunks ↓ User opens Ghost-Tag website in Chrome on Android ↓ User enters passphrase ↓ Website uses Web NFC to read tags ↓ Website verifies and caches chunks ↓ Website reconstructs and decrypts file ↓ User downloads file
Website writes, Android reads
text
User opens Ghost-Tag website in Chrome on Android ↓ Selects file ↓ Website encrypts and splits file ↓ Website writes encrypted NDEF chunks ↓ User opens Android APK ↓ Enters passphrase or recovery phrase ↓ Scans tags ↓ Android reconstructs and decrypts file
6. Key and recovery model
The same user must be able to move between Android, iPhone, and web.
text
User passphrase | v Argon2id | v KEK | +--> Wrapped DEK | +--> Recovery-wrapped DEK
Recovery phrase
The recovery phrase must be portable across all platforms.
text
User loses Android phone ↓ Installs Ghost-Tag iOS app ↓ Enters recovery phrase ↓ iOS derives recovery KEK ↓ iOS unwraps recovery copy of DEK ↓ iOS restores vault metadata ↓ User scans NFC tags ↓ Files become readable again
The recovery phrase does not replace the NFC tags. It restores the key needed to decrypt the tags.
If the user loses both the passphrase and recovery phrase, the encrypted NFC tags cannot be decrypted.
7. Security boundaries
Platform
Strongest role
Weakness
Android APK
Primary vault and writer
Compromised/unlocked Android can expose decrypted data
iOS native app
iPhone vault and NFC client
Compromised/unlocked iPhone can expose decrypted data
Web app
Recovery and cross-platform access
Browser XSS, extensions, and compromised browser profile are risks
Desktop app
Recovery and USB-reader client
Depends on OS and USB-reader security
The web app must never become the primary long-term key vault. It should keep only encrypted chunk caches and require the passphrase fresh in each session.
8. Recommended final product
Build in this order:
Android APK: full NFC reader/writer, bulk vault, file vault, cache, export.
iOS native app: Core NFC reader/writer, bulk vault, recovery, export.
Web app: recovery, decryption, viewing, download; Web NFC only where supported.
Desktop app: PC/SC USB-reader support, recovery, bulk-vault management.
Use this user-facing rule:
Ghost-Tag tags are cross-platform. Android and iPhone native apps can read and write them. The website can read and write them only in browsers that support Web NFC; on iPhone, use the native Ghost-Tag app for NFC.