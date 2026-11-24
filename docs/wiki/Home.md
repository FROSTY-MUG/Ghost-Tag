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

> **Core Promise**:
> Encrypted NFC storage.
> Create. Encrypt. Scan. Decrypt.

---

## What is Ghost-Tag?

Ghost-Tag is a hardware-anchored encrypted NFC storage system designed for zero-trust physical data persistence. It allows users to write encrypted text, files, photos, videos, and private links across one or more NFC tags, and decrypt them later by scanning the tags in any order.

Ghost-Tag operates via three clients:
- **Android APK (Primary Full Client)**: Full native NFC transceiver access (NFC-A, ISO 14443-3A, Type 2 Tag), background tag dispatch, physical sector verification, and safe individual entry deletion.
- **Web Client (Lightweight Companion)**: Browser-based companion running directly via GitHub Pages with Web NFC on supported mobile browsers (e.g. Chrome on Android).
- **Ghost Bridge (Desktop USB Companion)**: Desktop daemon bridging PC/SC USB NFC readers (ACR122U) to web browsers on laptops and workstations.

---

## Documentation Index (18 Chapters)

| Section | Description |
| :--- | :--- |
| **[Getting Started](Getting-Started)** | Quickstart overview and basic concepts |
| **[Android Installation](Android-Installation)** | Installing and verifying the Ghost-Tag APK |
| **[Web App](Web-App)** | Using the web companion on GitHub Pages |
| **[Ghost Bridge](Ghost-Bridge)** | Native desktop PC/SC USB NFC reader companion |
| **[Creating an Account](Creating-an-Account)** | Anonymous identity, passphrases, and BIP-39 phrases |
| **[Recovery Phrase](Recovery-Phrase)** | 12-word seed phrase security and mechanics |
| **[Encrypt Flow](Encrypt)** | Scanning tags, chunking payloads, and writing encrypted records |
| **[Decrypt Flow](Decrypt)** | Scanning tags in any order, reassembly, and decryption |
| **[Batch Write](Batch-Write)** | Multi-tag batch distribution and write verification |
| **[Batch Read](Batch-Read)** | Order-independent tag scanning, reassembly, and recovery |
| **[NFC Compatibility](NFC-Compatibility)** | Supported tag families (NTAG213, NTAG215, NTAG216) |
| **[Security Model](Security-Model)** | Two-tier Argon2id (`16/32/64 MiB` & WASM), AES-256-GCM, Turnstile challenge/proof |
| **[FAQ](../../FAQ.md)** | 70 evidence-cited Q&As covering formats, chips, security, and release state |
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
