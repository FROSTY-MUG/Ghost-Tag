# Ghost-Tag Wiki

Welcome to the official **Ghost-Tag** documentation wiki.

```
       .-.
      (o.o)
       |=|
      __|__
    // .=. \\
   || // \ ||
    \\ \_/ //
     '-' '-'
    G H O S T
```

> **Core Promise**: Encrypted NFC storage. Write. Scan. Decrypt.

---

## What is Ghost-Tag?

Ghost-Tag is a hardware-anchored encrypted NFC storage system designed for zero-trust physical data persistence. It allows users to write encrypted text, files, photos, videos, and private links across one or more NFC tags, and decrypt them later by scanning the tags in any order.

Ghost-Tag operates via two clients:
- **Android APK (Primary Full Client)**: Full native NFC transceiver access (NFC-A, ISO 14443-3A, Type 2 Tag), background tag dispatch, physical sector verification, and safe individual entry deletion.
- **Web Client (Lightweight Companion)**: Browser-based companion running directly via GitHub Pages with Web NFC on supported mobile browsers (e.g. Chrome on Android).

---

## Documentation Index

| Section | Description |
| :--- | :--- |
| **[Getting Started](Getting-Started)** | Quickstart overview and basic concepts |
| **[Android Installation](Android-Installation)** | Installing and verifying the Ghost-Tag APK |
| **[Web App](Web-App)** | Using the web companion on GitHub Pages |
| **[Creating an Account](Creating-an-Account)** | Anonymous identity, passphrases, and BIP-39 phrases |
| **[Recovery Phrase](Recovery-Phrase)** | 12-word seed phrase security and mechanics |
| **[Encrypt Flow](Encrypt)** | Scanning tags, chunking payloads, and writing encrypted records |
| **[Decrypt Flow](Decrypt)** | Scanning tags in any order, reassembly, and decryption |
| **[NFC Compatibility](NFC-Compatibility)** | Supported tag families (NTAG213, NTAG215, NTAG216) |
| **[Security Model](Security-Model)** | Zero-knowledge architecture, Argon2id/PBKDF2, AES-256-GCM |
| **[Technical Format](Technical-Format)** | Binary envelope (`GTAG`), Little-Endian layout, NDEF MIME |
| **[Recovery System](Recovery)** | Restoring vaults across devices with zero server secrets |
| **[Troubleshooting](Troubleshooting)** | Hardware alignment, write verification errors, browser flags |
| **[Contributing](Contributing)** | Architecture guidelines, testing conventions, and pull requests |
| **[Roadmap](Roadmap)** | Native iOS app, Reed-Solomon redundancy, and hardware security keys |

---

## Live Links
- **Web App**: [https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)
- **Technical Specifications**: [https://frosty-mug.github.io/Ghost-Tag/technical.html](https://frosty-mug.github.io/Ghost-Tag/technical.html)
- **Releases & APK Downloads**: [https://github.com/FROSTY-MUG/Ghost-Tag/releases](https://github.com/FROSTY-MUG/Ghost-Tag/releases)
- **Repository**: [https://github.com/FROSTY-MUG/Ghost-Tag](https://github.com/FROSTY-MUG/Ghost-Tag)
