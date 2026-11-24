# Technical Wire Format Specification (`v2.1.0`)

Ghost-Tag enforces deterministic **Little-Endian** binary envelopes opening with 4-byte ASCII `"GTAG"` (`0x47, 0x54, 0x41, 0x47`), carried inside NDEF MIME records (`application/vnd.ghost.secure` for v1; `application/vnd.ghost.bulk` for v2).

---

## 1. Single-Tag Envelope (`v1`, `54 bytes` Fixed Overhead)
- `0..3` (`4B`): `MAGIC` = `"GTAG"` (`0x47 0x54 0x41 0x47`)
- `4` (`1B`): `FORMAT_VERSION` = `0x01`
- `5` (`1B`): `PURPOSE` = `0x01..0x06`
- `6..21` (`16B`): `KEY_ID`
- `22..25` (`4B`): `CIPHERTEXT_LENGTH` (`uint32` LE = $N$)
- `26..37` (`12B`): `NONCE` (`IV`)
- `38..(38+N-1)` (`N` B): `CIPHERTEXT`
- `(38+N)..(53+N)` (`16B`): `GCM_TAG`
- **AAD**: Bytes `0..25` (`26 bytes`).

---

## 2. Bulk Distributed Chunk Envelope (`v2`, `134 bytes` Fixed Overhead)

| Offset | Length | Encoding | Field | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0..3` | `4B` | ASCII | `MAGIC` | `"GTAG"` (`0x47, 0x54, 0x41, 0x47`) |
| `4` | `1B` | `uint8` | `FORMAT_VERSION` | `0x02` |
| `5` | `1B` | `uint8` | `RECORD_TYPE` | `0x10` (`RECORD_TYPE_BULK_CHUNK`) |
| `6..21` | `16B` | `bytes` | `VAULT_ID` | Vault UUID |
| `22..37` | `16B` | `bytes` | `FILE_ID` | File UUID |
| `38..53` | `16B` | `bytes` | `KEY_ID` | DEK ID |
| `54..57` | `4B` | `uint32 LE` | `GLOBAL_CHUNK_INDEX` | Global chunk index across vault |
| `58..61` | `4B` | `uint32 LE` | `TOTAL_VAULT_CHUNKS` | Total vault shards ($K + M$) |
| `62..65` | `4B` | `uint32 LE` | `FILE_CHUNK_INDEX` | Shard index within file |
| `66..69` | `4B` | `uint32 LE` | `TOTAL_FILE_CHUNKS` | Total shards for this file |
| `70..73` | `4B` | `uint32 LE` | `CHUNK_CIPHERTEXT_LENGTH` | $N$ bytes of chunk ciphertext |
| `74..105` | `32B` | `bytes` | `CHUNK_HASH` | `SHA-256(CHUNK_CIPHERTEXT)` (no Merkle tree) |
| `106..117` | `12B` | `bytes` | `NONCE` | 96-bit AES-256-GCM IV |
| `118..(118+N-1)` | `N` B | `bytes` | `CHUNK_CIPHERTEXT` | Encrypted shard payload |
| `(118+N)..(133+N)` | `16B` | `bytes` | `GCM_TAG` | 128-bit GCM authentication tag |

- **AAD (`74 bytes`)**: Bytes `0..73` (`MAGIC` through `CHUNK_CIPHERTEXT_LENGTH`).

See [`../../docs/envelope-specification.md`](../envelope-specification.md) and [`../../docs/CANONICAL-SPECIFICATION.md`](../CANONICAL-SPECIFICATION.md).
