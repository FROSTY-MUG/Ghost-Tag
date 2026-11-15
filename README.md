# Ghost-Tag

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗   ████████╗ █████╗  ██████╗ 
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝   ╚══██╔══╝██╔══██╗██╔════╝ 
  ██║  ███╗███████║██║   ██║███████╗   ██║         ██║   ███████║██║  ███╗
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║         ██║   ██╔══██║██║   ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║         ██║   ██║  ██║╚██████╔╝
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝         ╚═╝   ╚═╝  ╚═╝ ╚═════╝ 
```

> **Encrypted NFC storage. Write. Scan. Decrypt.**
> Offline-first, cross-platform encrypted NFC vault writing authenticated AES-256-GCM ciphertext envelopes to physical NDEF tags, backed by a 12-word BIP-39 recovery hierarchy.

---

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)
[![Platform: Android](https://img.shields.io/badge/Platform-Android%20(API%2026%2B)-black.svg)](https://developer.android.com)
[![Web Client: Live](https://img.shields.io/badge/Web%20Client-GitHub%20Pages-blue.svg)](https://frosty-mug.github.io/Ghost-Tag/)
[![Crypto: AES--256--GCM](https://img.shields.io/badge/Crypto-AES--256--GCM%20%2B%20PBKDF2-blueviolet.svg)](./docs/security.md)
[![Tests: 130 Passing](https://img.shields.io/badge/Tests-130%20Passing%20(100%25)-brightgreen.svg)](./docs/testing.md)
[![TypeScript: Strict](https://img.shields.io/badge/TypeScript-0%20Errors-blue.svg)](./tsconfig.json)
[![Release: v2.0.5](https://img.shields.io/badge/Release-v2.0.5-crimson.svg)](https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.5)

---

### Quick Links
- **[Launch Web Client](https://frosty-mug.github.io/Ghost-Tag/)** — Minimal client-side encrypted NFC app on GitHub Pages.
- **[Download Android APK (v2.0.5)](https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.5)** — Primary native client (`Ghost-Tag-v2.0.5.apk`, SHA-256 verified).
- **[NDEF Envelope Specification](./docs/nfc-format.md)** — Canonical binary envelope layout.
- **[Security Architecture](./docs/security.md)** — Zero-secrets policy and cryptographic threat boundaries.

---

## 1. Project Thesis

### 1.1 The Core Problem
Ordinary NFC tags are physical, ubiquitous, and convenient—but fundamentally insecure by default:
- Anyone with an NFC-enabled smartphone can read their contents in plaintext.
- Standard NDEF formatting commands zero out only table-of-contents records, leaving data remanence in EEPROM pages.
- Losing an NFC tag carrying sensitive recovery seed phrases, Wi-Fi credentials, or private files exposes plaintext to any finder.

### 1.2 Ghost-Tag's Solution
Ghost-Tag provides **data confidentiality and cryptographic tamper-evidence** for payloads stored on physical NFC chips:
> **The physical NFC tag may be inspected, duplicated, erased, or lost—yet its protected payload remains computationally unusable without the user's master passphrase and cryptographic key material.**

### 1.3 What Ghost-Tag IS NOT
- **Not a Proxmark3 or Flipper Zero replacement**: Ghost-Tag does not clone chips, perform raw RF sniffing, or bypass proprietary chip auth.
- **Not a PKI or cloud vault**: Ghost-Tag is completely offline. It never communicates with remote servers or cloud backends.
- **Not an anti-cloning token**: If an attacker copies an NFC tag byte-for-byte, they duplicate the ciphertext; they still cannot decrypt it without the key hierarchy.

---

## 2. System Architecture

Ghost-Tag operates across two decoupled clients sharing a unified binary envelope and key recovery format:

```mermaid
flowchart TD
    subgraph Clients["Ghost-Tag Client Interfaces"]
        AndroidApp["Android Native APK<br/>(Primary Full Client, API 26+)"]
        WebApp["Web Client<br/>(GitHub Pages, Chrome Android)"]
    end

    subgraph SecurityCore["Cryptographic Security Engine"]
        KDF["PBKDF2 / Argon2id KDF<br/>(100k Iterations / 64MB RAM)"]
        AES["AES-256-GCM Cipher<br/>(12-Byte IV, 16-Byte Tag)"]
        AAD["Additional Authenticated Data<br/>(26-Byte Header Binding)"]
        BIP39Engine["BIP-39 12-Word Engine<br/>(128-Bit Entropy + 4-Bit Checksum)"]
    end

    subgraph HardwareTransceiver["NFC Transceiver Layer"]
        SingleTag["Single-Tag Envelope<br/>(application/vnd.ghost.secure)"]
        BulkTag["Bulk File Vault Chunks<br/>(application/vnd.ghost.bulk)"]
    end

    subgraph PhysicalChips["Target Physical Media"]
        NTAG213["NTAG213 (144B NDEF)"]
        NTAG215["NTAG215 (504B NDEF)"]
        NTAG216["NTAG216 (888B NDEF)"]
    end

    AndroidApp --> KDF
    WebApp --> KDF
    KDF --> AES
    AES --> AAD
    BIP39Engine -.-> KDF
    AAD --> SingleTag
    AAD --> BulkTag
    SingleTag --> NTAG213
    SingleTag --> NTAG215
    SingleTag --> NTAG216
    BulkTag --> NTAG215
    BulkTag --> NTAG216
```

---

## 3. Cryptographic Key Hierarchy

Ghost-Tag enforces an ephemeral two-tier key hierarchy where master keys are never stored in plaintext on disk:

```mermaid
flowchart TD
    subgraph UserCredentials["User Input & Recovery"]
        Passphrase["Master Passphrase<br/>(≥16 Characters)"]
        RecoveryPhrase["12-Word BIP-39 Recovery Phrase<br/>(128-bit CSPRNG Entropy)"]
    end

    subgraph KDFDerivation["Memory-Hard KDF"]
        Salt["CSPRNG Salt (32 Bytes)"]
        Salt --> DerivationEngine["PBKDF2-SHA256 (Web, 100k iters)<br/>Argon2id (Android, 64MB, t=3)"]
        Passphrase --> DerivationEngine
        RecoveryPhrase -.-> DerivationEngine
    end

    subgraph MemoryTier["Volatile Memory (Never Persisted)"]
        KEK["Key Encryption Key (KEK, 256-bit)"]
        DEK["Data Encryption Key (DEK, 256-bit)"]
        DerivationEngine --> KEK
        KEK -->|Unwraps| DEK
    end

    subgraph LocalStorage["Encrypted Local State (MMKV / localStorage)"]
        WrappedDEK["Wrapped DEK Ciphertext"]
        SaltStorage["Vault Salt (32B)"]
        IVStorage["DEK IV (12B) + Tag (16B)"]
    end

    WrappedDEK -.-> DEK
    SaltStorage -.-> Salt
```

---

## 4. NFC Write Flow & Read-Back Verification

Every NFC write transaction executes cryptographic encapsulation followed by immediate read-back verification:

```mermaid
flowchart TD
    StartWrite["Select Data (Text or File)"] --> CheckSize{"Payload Fits<br/>Tag Writable Space?"}
    CheckSize -- No --> AlertBulk["Prompt: Use Bulk File Vault"]
    CheckSize -- Yes --> GenEnvelope["Construct 54-Byte Header<br/>Magic (GHTG) + Version (0x02) + KeyID"]
    GenEnvelope --> EncryptPayload["AES-256-GCM Encrypt<br/>(12B Nonce, 16B Tag, AAD Bound)"]
    EncryptPayload --> WriteNDEF["Write NDEF MIME Record<br/>(application/vnd.ghost.secure)"]
    WriteNDEF --> ReadBack["Immediate Read-Back from Tag Chip"]
    ReadBack --> VerifyTag{"Compare Decrypted<br/>vs Original Data?"}
    VerifyTag -- Match --> DoneSuccess["WRITTEN AND VERIFIED<br/>Data safely encrypted on tag"]
    VerifyTag -- Mismatch --> AlertFail["WRITE NOT VERIFIED<br/>Data corrupted or incomplete"]
```

---

## 5. Bulk File Vault & Multi-Tag Reconstruction

Large files (images, PDFs, ZIPs, videos) are split across multiple NFC chips. Tags can be scanned in any order during recovery:

```mermaid
flowchart LR
    subgraph FileSlice["File Chunking & Encryption"]
        LargeFile["Large File / Multi-Files"] --> SplitChunks["Split into N Payload Chunks"]
        SplitChunks --> EncryptChunks["Encrypt Each Chunk (AES-256-GCM)<br/>with Sequence & Vault Identifiers"]
    end

    subgraph PhysicalTags["Arbitrary Order NFC Tags"]
        Tag3["Tag #3 (Chunk 3/N)"]
        Tag1["Tag #1 (Chunk 1/N)"]
        TagN["Tag #N (Chunk N/N)"]
        Tag2["Tag #2 (Chunk 2/N)"]
    end

    subgraph Reconstruction["Reconstruction Engine"]
        ScanLoop["Scan Tags in Any Order"]
        Cache["72-Hour IndexedDB Cache"]
        DecryptAction["Tap Decrypt Now"]
        Reassemble["Order Chunks by Index & Reassemble"]
        RecoveredFile["Recovered Original Files"]
    end

    EncryptChunks --> Tag3
    EncryptChunks --> Tag1
    EncryptChunks --> TagN
    EncryptChunks --> Tag2

    Tag3 --> ScanLoop
    Tag1 --> ScanLoop
    TagN --> ScanLoop
    Tag2 --> ScanLoop

    ScanLoop --> Cache
    Cache --> DecryptAction
    DecryptAction --> Reassemble
    Reassemble --> RecoveredFile
```

---

## 6. Cross-Platform Recovery Workflow

Vaults initialized on Android can be seamlessly recovered on the Web Client (and vice versa) using the 12-word mnemonic:

```mermaid
flowchart TD
    subgraph SetupDevice["Device A (e.g. Android APK)"]
        GenEntropy["Generate 128-bit CSPRNG Entropy"] --> CalcChecksum["Append 4-Bit SHA-256 Checksum (132 Bits Total)"]
        CalcChecksum --> MapWords["Map to 12 BIP-39 English Words"]
        MapWords --> ConfirmWords["Confirm Words 4, 8, 11"]
        ConfirmWords --> VaultActiveA["Vault Created & Initialized"]
    end

    subgraph ExportImport["Mnemonic Transfer"]
        UserPhrase["User Records 12 Words on Physical Paper"]
    end

    subgraph RecoverDevice["Device B (e.g. GitHub Pages Web Client)"]
        ImportAction["Select 'I Have a Recovery Phrase'"] --> InputWords["Enter 12 Words"]
        InputWords --> VerifyChecksum{"Validate 11-Bit Indices<br/>& 4-Bit Checksum"}
        VerifyChecksum -- Valid --> ReconstructKEK["Reconstruct Vault Master Keys"]
        ReconstructKEK --> SetLocalPass["Set Device Passphrase"]
        SetLocalPass --> VaultActiveB["Vault Successfully Restored"]
        VerifyChecksum -- Invalid --> ShowErr["Show: Recovery phrase is invalid."]
    end

    VaultActiveA --> UserPhrase
    UserPhrase --> ImportAction
```

---

## 7. Cross-Platform Compatibility Matrix

```mermaid
flowchart LR
    subgraph AndroidNative["Android APK (Native)"]
        FullNFC["Raw NDEF Read / Write<br/>Mifare Ultralight Commands<br/>Background Dispatch"]
    end

    subgraph WebChromeAndroid["Web Client (Chrome on Android)"]
        WebNFC["Web NFC API<br/>NDEF Read / Write<br/>HTTPS Context Required"]
    end

    subgraph WebDesktop["Web Client (Desktop Browsers)"]
        SimMode["Simulated Hardware Transceiver<br/>Full Cryptographic Suite<br/>Vault Management"]
    end

    subgraph AppleiOS["Apple iOS (Safari / Web)"]
        NoWebNFC["Web NFC Not Supported by iOS<br/>(Use Android Native APK)"]
    end

    AndroidNative <-->|Shared Format| WebChromeAndroid
    WebChromeAndroid <-->|Shared Format| WebDesktop
```

### Detailed Capability Matrix:

| Feature / Capability | Android APK (v2.0.5) | Web Client (Chrome Android) | Web Client (iOS Web) | Web Client (Desktop) |
| :--- | :---: | :---: | :---: | :---: |
| **NDEF Record Reading** | Yes (Native) | Yes (Web NFC) | No (OS Limitation) | Simulated |
| **NDEF Record Writing** | Yes (Native) | Yes (Web NFC) | No (OS Limitation) | Simulated |
| **AES-256-GCM Encryption** | Yes (256-bit) | Yes (WebCrypto) | Yes (WebCrypto) | Yes (WebCrypto) |
| **BIP-39 12-Word Recovery** | Yes | Yes | Yes | Yes |
| **Single-Tag Vault** | Yes | Yes | Read-only with native app | Simulated |
| **Bulk Multi-Tag Vault** | Yes | Yes | Read-only with native app | Simulated |
| **72-Hour Cache Engine** | Yes (MMKV) | Yes (IndexedDB) | Yes (IndexedDB) | Yes (IndexedDB) |
| **Stop & Pause Controls** | Yes | Yes | Yes | Yes |
| **Zero Network Permissions** | Enforced | Enforced | Enforced | Enforced |

---

## 8. Physical NFC Tag Specifications

Ghost-Tag automatically detects tag geometry and computes usable Ghost storage:

| IC Type | Total EEPROM | Usable NDEF Space | Header Overhead | Max Usable Ghost Storage |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | 180 Bytes | 144 Bytes | 54 Bytes | **90 Bytes** |
| **NTAG215** | 540 Bytes | 504 Bytes | 54 Bytes | **450 Bytes** |
| **NTAG216** | 924 Bytes | 888 Bytes | 54 Bytes | **834 Bytes** |

---

## 9. Verification & Quality Gates

Ghost-Tag maintains 100% test passing rates across all cryptographic and hardware simulation suites:

```bash
# Run unit & integration tests (130 passing)
npm test

# Static type verification (0 errors)
npx tsc --noEmit
```

---

## 10. Repository Architecture

```
Ghost-Tag/
├── android/               # Android APK native codebase (Gradle, NDK, JNI)
│   ├── app/               # Native application module
│   └── README.md          # Android build and architecture guide
├── web/                   # Client-side web client (GitHub Pages)
│   ├── index.html         # Minimal brutalist landing & vault UI
│   ├── app.js             # Web NFC transceiver, cache, and crypto engine
│   ├── styles.css         # Apple-inspired brutalist dark styling
│   ├── wordlist.js        # BIP-39 2,048 English wordlist
│   ├── assets/            # Subtle blurred visual assets
│   ├── package.json       # Web client package descriptor
│   └── README.md          # Web client documentation
├── docs/                  # Technical documentation suite
│   ├── nfc-format.md      # Canonical NDEF binary envelope layout
│   ├── security.md        # Cryptographic security & threat boundaries
│   ├── recovery.md        # BIP-39 12-word recovery specification
│   ├── testing.md         # Test verification & test vectors
│   └── architecture.md    # System design documentation
├── .github/               # GitHub issue templates, rulesets, and configs
│   ├── ISSUE_TEMPLATE/    # Bug report, feature request, nfc-compat, docs
│   └── FUNDING.yml        # Sponsorship configuration
├── CHANGELOG.md           # Keep a Changelog compliant release history
├── LICENSE                # MIT License
├── README.md              # Project thesis and technical specifications
└── SECURITY.md            # Vulnerability reporting and security policy
```

---

## License

Ghost-Tag is licensed under the [MIT License](./LICENSE).
