# Getting Started with Ghost-Tag

Ghost-Tag makes physical data cold storage secure and portable by splitting encrypted data across standard NFC stickers, cards, or key fobs.

---

## 1. Prerequisites
- **Hardware**: An Android device with an NFC controller (or an NFC-enabled Android phone running Chrome for the Web client).
- **Tags**: Any NFC Forum Type 2 tags, such as:
  - **NTAG213**: 144 bytes user memory (~100 bytes writable payload per tag)
  - **NTAG215**: 504 bytes user memory (~460 bytes writable payload per tag)
  - **NTAG216**: 888 bytes user memory (~844 bytes writable payload per tag)
- **Account**: A Ghost account (created locally on your device in seconds).

---

## 2. Core Concepts

### Local-First Anonymous Account
Ghost-Tag requires no email, phone number, username, or personal credentials. When you set up Ghost-Tag, you create a local master passphrase (minimum 16 characters) and receive a standard **12-word BIP-39 English recovery phrase**.

### Unified Cross-Platform Storage
NFC tags written by the Android app can be decrypted by the web client, and tags written on the web client can be decrypted by the Android app. Both clients use the exact same binary format, crypto primitives, and MIME identifiers.

### Out-of-Order Scanning
When a file is encrypted across multiple tags, each tag receives a self-describing encrypted envelope. You can later scan the tags in **any order**. Ghost-Tag identifies each chunk, verifies its cryptographic hash, and decrypts the entire payload when all chunks are collected.

---

## 3. Quickstart Workflow

```text
Step 1: Create Account
  → Enter master passphrase (≥ 16 chars)
  → Save 12-word recovery phrase offline
  → Confirm 3 words

Step 2: Encrypt & Write
  → Tap [ Encrypt ]
  → Tap [ Start Scanning ] and touch your NFC tags one-by-one
  → Tap [ End Scanning Process ]
  → Add Text, File, Photo, Video, or URL
  → Enter passphrase and tap [ Encrypt and Write ]
  → Hold each tag against the phone until verified

Step 3: Decrypt Anywhere
  → Tap [ Decrypt Now ]
  → Tap [ Start Scanning ] and touch tags in any order
  → Tap [ All Chips Scanned ]
  → Enter passphrase
  → View or Download recovered files
```
