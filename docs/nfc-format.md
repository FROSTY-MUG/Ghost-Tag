# Ghost-Tag NDEF Envelope Specification

This document defines the canonical binary envelope format used across all Ghost-Tag clients (Android APK and GitHub Pages Web Client) for storing encrypted data on NFC tags.

---

## 1. Canonical NDEF Record Structure

Ghost-Tag writes standard NFC Data Exchange Format (NDEF) MIME records:

| Vault Mode | Canonical MIME Type | Purpose Byte | Supported Chips |
| :--- | :--- | :--- | :--- |
| **Single-Tag Vault** | `application/vnd.ghost.secure` | `0x01` | NTAG213, NTAG215, NTAG216 |
| **Bulk File Vault** | `application/vnd.ghost.bulk` | `0x02` | NTAG213, NTAG215, NTAG216 |

---

## 2. Binary Envelope Layout

The NDEF record payload consists of a fixed 54-byte header followed by variable-length ciphertext:

```
+---------------+---------------+---------------+-------------------------------+
| Field Offset  | Size (Bytes)  | Type          | Description                   |
+---------------+---------------+---------------+-------------------------------+
| 0x00 - 0x03   | 4             | Magic Bytes   | 0x47, 0x48, 0x54, 0x47 ("GHTG") |
| 0x04          | 1             | Version       | Format Version: 0x02          |
| 0x05          | 1             | Purpose       | 0x01 = Single, 0x02 = Bulk    |
| 0x06 - 0x15   | 16            | Key Identifier| Random 128-bit Key ID         |
| 0x16 - 0x19   | 4             | Length        | Ciphertext Length (32-bit LE) |
| 0x1A - 0x25   | 12            | Nonce / IV    | CSPRNG AES-GCM IV             |
| 0x26 - 0x35   | 16            | Auth Tag      | AES-256-GCM 128-bit Tag       |
| 0x36 - End    | Variable      | Ciphertext    | AES-256-GCM Encrypted Payload |
+---------------+---------------+---------------+-------------------------------+
```

### 2.1 Header Field Definitions
1. **Magic Bytes (`0x00` - `0x03`)**: ASCII string `GHTG` (`[0x47, 0x48, 0x54, 0x47]`). Ensures fast identification without leaking content.
2. **Format Version (`0x04`)**: Unsigned 8-bit integer (`0x02` for Ghost-Tag v2.0+).
3. **Purpose (`0x05`)**:
   - `0x01`: Single-tag payload (complete self-contained text or binary file).
   - `0x02`: Bulk-vault slice (chunk of a larger multi-tag file vault).
4. **Key Identifier (`0x06` - `0x15`)**: 16-byte random identifier corresponding to the vault DEK or wrapped key descriptor.
5. **Ciphertext Length (`0x16` - `0x19`)**: 32-bit unsigned integer encoded in **Little-Endian (LE)** byte order specifying exact payload length.
6. **Initialization Vector (`0x1A` - `0x25`)**: 12-byte cryptographically secure pseudorandom number generator (CSPRNG) nonce. Never reused under the same key.
7. **Authentication Tag (`0x26` - `0x35`)**: 16-byte (128-bit) GCM authentication tag verifying ciphertext and AAD integrity.
8. **Ciphertext (`0x36` - End)**: Authenticated encrypted payload bytes.

---

## 3. Additional Authenticated Data (AAD) Binding

To guarantee that envelope metadata cannot be altered or swapped by an adversary, the first 26 bytes of the envelope are bound as Additional Authenticated Data (AAD) in the AES-256-GCM cipher call:

$$\text{AAD} = \text{Magic}[0..3] \mathbin{\Vert} \text{Version}[4] \mathbin{\Vert} \text{Purpose}[5] \mathbin{\Vert} \text{KeyID}[6..21] \mathbin{\Vert} \text{CiphertextLen}[22..25]$$

Any unauthorized modification to the version byte, purpose byte, key identifier, or length field causes AES-GCM tag verification to fail immediately.

---

## 4. Physical NFC Chip Capacity Matrix

| Chip Family | Total Physical EEPROM | NDEF Usable Capacity | Header Overhead | Max Usable Ghost Storage |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | 180 bytes (45 pages) | 144 bytes | 54 bytes | **90 bytes** |
| **NTAG215** | 540 bytes (135 pages) | 504 bytes | 54 bytes | **450 bytes** |
| **NTAG216** | 924 bytes (231 pages) | 888 bytes | 54 bytes | **834 bytes** |

### Usable Storage Formula:
$$\text{Usable Ghost Storage} = \max\left(0, \sum_{i=1}^N \text{WritableBytes}_i - (N \times 54)\right)$$
