# Ghost-Tag NFC Tag Compatibility & Capacity Matrix

> **Honest Framing Rule**: Real NTAG21x capacity is strictly less than raw user EEPROM because Type 2 TLV containers and NDEF MIME headers (`application/vnd.ghost.secure` or `application/vnd.ghost.bulk`) consume framing bytes prior to Ghost-Tag envelope overhead (`54B` v1 / `134B` v2).

---

## 1. Supported Type 2 Tag Matrix

| Chip | Total EEPROM | User EEPROM | Page Count | v1 Max Ciphertext (`TagInfo.ts` / `apdu.js`) | v2 Bulk Max Ciphertext (`TagInfo.ts` / `apdu.js`) | Recommended Use |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **NTAG213** | `180B` | `144B` | Pages `0..44` (user `4..39`) | `52B` / `56B` | **Does Not Fit (`0B`)** | Short secrets/seeds (`v1` single-tag only; incompatible with `v2` bulk) |
| **NTAG215** | `540B` | `504B` | Pages `0..134` (user `4..129`) | `404B` / `411B` | `326B` / `333B` | Standard v1 and v2 distributed bulk file vaults |
| **NTAG216** | `924B` | `888B` | Pages `0..230` (user `4..225`) | `784B` / `795B` | `706B` / `717B` | Large v1 secrets and high-density v2 distributed bulk file vaults |
| **MIFARE Classic** | Various | Proprietary | Non-Type-2 | **Rejected** | **Rejected** | Unsupported (legacy Crypto-1; non-NDEF Type 2 compliance) |

---

## 2. Page Preservation & Lock Safety
1. **System & Lock Pages Preserved**: Multi-pass tag wiping (`src/nfc/tagWiper.ts`) overwrites writable user memory pages (`4`..end of user space) while preserving UID pages (`0..2`), Capability Container (`3`), and dynamic lock / configuration pages to avoid permanently bricking tags.
2. **Hardware Validation Gate**: Capacity calculations and mocked NDEF read/write tests pass across `src/__tests__/nfc.test.ts`, `desktop/test/bridge.test.js`, and `desktop/test/pn532_serial.test.js`. Physical read/write testing against real `NTAG213` / `NTAG215` / `NTAG216` hardware remains an open release gate ([`../PROJECT-STATUS.md`](../PROJECT-STATUS.md), [`../FAQ.md`](../FAQ.md)).
