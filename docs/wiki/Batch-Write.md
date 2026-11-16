# Batch Write

Ghost-Tag v2.0.5 supports writing encrypted text, arbitrary files, photos, videos, and private links across one or more physical NFC tags in a single guided batch operation.

```
 +-------------------------------------------------------+
 |                     USER CONTENT                      |
 |  [Text Note]  [Document.pdf]  [Photo.jpg]  [Enc. URL] |
 +---------------------------+---------------------------+
                             |
                   Double AES-256-GCM
                 (Passphrase KDF + DEK)
                             |
 +---------------------------v---------------------------+
 |                 Encrypted Ciphertext                  |
 |                 (Self-contained blob)                 |
 +---------------------------+---------------------------+
                             |
                     Chunk Splitting
           (Payload fits tag capacity - 134B)
                             |
             +---------------+---------------+
             |                               |
 +-----------v-----------+       +-----------v-----------+
 |     Tag 1 / NTAG215   |  ...  |     Tag K / NTAG215   |
 |  Chunk 0 / GTAG Envel |       |  Chunk K-1 / GTAG Env |
 +-----------------------+       +-----------------------+
```

---

## 1. Overview of the Batch Write Flow

1. **Tag Scanning & Capacity Tally**:
   - The user scans physical NFC tags one by one.
   - Ghost-Tag measures the real detectable capacity and subtracts the 134-byte fixed envelope overhead per tag to compute **Total Usable Ghost Storage**.
   - The user taps **End Scanning Process** when all intended tags are scanned.

2. **Content Staging**:
   - The user stages entries:
     - **Add Text**: Arbitrary sensitive notes, credentials, recovery seeds.
     - **Add File**: Arbitrary binary payloads (PDFs, archives, binary data).
     - **Add Photo**: Compressed images (`image/*`).
     - **Add Video**: Short video clips (`video/*`).
     - **Add URL**: Encrypted URLs (stored as encrypted `text/uri-list`).
   - The app dynamically compares total serialized encrypted size against the available Usable Ghost Storage:
     - If content fits: Displays **CONTENT READY** with chunk breakdown.
     - If content exceeds capacity: Displays **NOT ENOUGH NFC STORAGE** with options to **Scan More Tags** or **Remove Entry**.

3. **Passphrase Prompt**:
   - The user enters their single vault passphrase.
   - Ghost-Tag derives the Key Encryption Key (KEK) using PBKDF2 (100,000 iterations of SHA-256) or Argon2id on Android.
   - The payload is encrypted with authenticated AES-256-GCM with Additional Authenticated Data (AAD).

4. **Sequential Writing & Read-Back Verification**:
   - The app guides the user to tap each tag sequentially:
     - `WRITING CHUNK 1 / N...`
     - Physical NDEF write executed (`application/vnd.ghost.bulk`).
     - `VERIFYING CHUNK 1 / N...`
     - Read-back verification reads the written record, checks magic bytes (`GTAG`), computes the SHA-256 hash of the ciphertext, and validates the GCM authentication tag.
   - If verified, the app advances to the next chunk until all tags are written.
   - The user can tap **Stop Writing** at any point to cancel safely.

---

## 2. Capacity Calculation

| Tag IC | Total Capacity | User Writable | Fixed Overhead | Usable Ghost Payload |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | 180 Bytes | 144 Bytes | 134 Bytes | **10 Bytes** (Single tiny record) |
| **NTAG215** | 540 Bytes | 504 Bytes | 134 Bytes | **370 Bytes** per tag |
| **NTAG216** | 924 Bytes | 888 Bytes | 134 Bytes | **754 Bytes** per tag |

Total required tags $K$ for a payload of size $S$:
$$K = \left\lceil \frac{S + 28}{\text{Tag Capacity} - 134} \right\rceil$$

---

## 3. Real Hardware Invariants

- **Zero Synthetic Tags**: Writing requires a real NFC transceiver (Web NFC on Android Chrome, Ghost-Tag Android APK, or Ghost Bridge on PC/SC).
- **Physical Read-Back Verification**: Ghost-Tag never declares a write "complete" until the physical sector is read back from the tag's EEPROM and cryptographically verified.
- **Fail-Safe Abort**: If a tag is pulled away before completion, the app preserves unwritten chunks in volatile memory and prompts the user to re-tap the tag.
