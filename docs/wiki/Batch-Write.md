# Batch Write (`v2.1.0` Distributed Bulk Vault)

Ghost-Tag `v2.1.0` splits encrypted files into $K$ data chunks plus optional Cauchy Reed-Solomon parity shards ($M$) over $\mathrm{GF}(2^8)$ (`0x11d`) and writes them across a verified set of `NTAG215` or `NTAG216` tags.

---

## 1. Workflow Steps
1. Select files (`BulkVaultCreation`) and target redundancy tolerance ($M$ parity tags).
2. Ghost-Tag derives the KEK via Argon2id (`16 / 32 / 64 MiB` on native), generates a random 256-bit DEK, encrypts files with AES-256-GCM, and calculates exact chunk counts.
3. **Extra-Tag Exclusion**: If you have surplus blank tags, Ghost-Tag instructs you to set the extra tags aside and refuses to write more than $K + M$ tags.
4. Tap blank `NTAG215` / `NTAG216` tags sequentially. Each write sends `application/vnd.ghost.bulk`, verifies `CHUNK_HASH` and EEPROM read-back, and rejects any previously written session tag (`CHUNK_ALREADY_WRITTEN`).

---

## 2. Real Framed Chunk Capacity Matrix

| Chip IC | Standard | User EEPROM | Overhead (`v2`) | Framed Max Chunk Payload (`TagInfo.ts` / `apdu.js`) |
| :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | Type 2 | `144B` | `134B` | **Incompatible (`0B`, `fits: false`)** |
| **NTAG215** | Type 2 | `504B` | `134B` | **`326B` / `333B`** |
| **NTAG216** | Type 2 | `888B` | `134B` | **`706B` / `717B`** |

See [Batch Read](Batch-Read) and [NFC Compatibility](NFC-Compatibility).
