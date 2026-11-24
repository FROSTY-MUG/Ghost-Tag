# Ghost-Tag NFC Storage & Wire Formats (`v2.1.0`)

Ghost-Tag stores encrypted payloads inside standard **NFC Forum Type 2 NDEF MIME Media Records**:
- **v1 Single-Tag MIME**: `application/vnd.ghost.secure`
- **v2 Bulk Distributed Chunk MIME**: `application/vnd.ghost.bulk`

All multi-byte integer fields use strict **Little-Endian** encoding. Every envelope opens with the 4-byte ASCII magic marker `"GTAG"` (`0x47, 0x54, 0x41, 0x47`).

---

## 1. v1 Single-Tag Envelope (`54 + N` bytes)

| Offset | Length | Field | Value / Encoding |
| :--- | :--- | :--- | :--- |
| `0x00..0x03` | `4B` | `MAGIC` | `0x47, 0x54, 0x41, 0x47` (`"GTAG"`) |
| `0x04` | `1B` | `FORMAT_VERSION` | `0x01` |
| `0x05` | `1B` | `PURPOSE` | Categorical ID (`0x01`..`0x06`) |
| `0x06..0x15` | `16B` | `KEY_ID` | Unique 128-bit DEK Identifier |
| `0x16..0x19` | `4B` | `CIPHERTEXT_LENGTH` | `uint32` LE (`N`) |
| `0x1A..0x25` | `12B` | `NONCE` | 96-bit CSPRNG AES-GCM IV |
| `0x26..` | `N B` | `CIPHERTEXT` | AES-256-GCM Encrypted Data |
| `tail` | `16B` | `GCM_TAG` | 128-bit Authentication Tag |

- **AAD (`26B`)**: `Envelope[0x00..0x19]` (`MAGIC || VERSION || PURPOSE || KEY_ID || CIPHERTEXT_LENGTH`).

---

## 2. v2 Bulk Chunk Envelope (`134 + N` bytes)

- **AAD (`74B`)**: `Envelope[0..73]` (`MAGIC`, `0x02`, `RECORD_TYPE = 0x10`, `VAULT_ID`, `FILE_ID`, `KEY_ID`, `GLOBAL_CHUNK_INDEX`, `TOTAL_VAULT_CHUNKS`, `FILE_CHUNK_INDEX`, `TOTAL_FILE_CHUNKS`, `CHUNK_CIPHERTEXT_LENGTH`).
- **Chunk Integrity Hash (`74..105`)**: `32B` `SHA-256(CHUNK_CIPHERTEXT)`.
- **AEAD (`106..133+N`)**: `NONCE (12B)` + `CHUNK_CIPHERTEXT (N B)` + `GCM_TAG (16B)`.

---

## 3. Physical NFC Chip Framed Capacity Matrix

| Chip Family | User EEPROM | v1 Max Ciphertext (`TagInfo.ts` / `apdu.js`) | v2 Bulk Max Ciphertext (`TagInfo.ts` / `apdu.js`) |
| :--- | :--- | :--- | :--- |
| **NTAG213** | `144B` | `52B` / `56B` | **Incompatible (`0B`, `fits: false`)** |
| **NTAG215** | `504B` | `404B` / `411B` | `326B` / `333B` |
| **NTAG216** | `888B` | `784B` / `795B` | `706B` / `717B` |

For exact binary field tables and parsing rules, see [`envelope-specification.md`](./envelope-specification.md) and [`CANONICAL-SPECIFICATION.md`](./CANONICAL-SPECIFICATION.md).
