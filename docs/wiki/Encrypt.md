# Encrypt Workflow (`v2.1.0`)

The **Encrypt** workflow packages text, credentials, configs, URLs (encrypted by default — never written as cleartext NDEF URIs), or files with AES-256-GCM and writes canonical `GTAG` NDEF records to physical Type 2 NFC tags.

## Payload Modes & Overheads
1. **Single-Tag (`v1`, `application/vnd.ghost.secure`)**:
   - Fixed binary overhead: **`54 bytes`** (`26B` AAD + `12B` nonce + `16B` GCM tag).
   - Framed ciphertext capacity:
     - `NTAG213` (`144B` EEPROM): `52B` (`TagInfo.ts`) / `56B` (`apdu.js`)
     - `NTAG215` (`504B` EEPROM): `404B` (`TagInfo.ts`) / `411B` (`apdu.js`)
     - `NTAG216` (`888B` EEPROM): `784B` (`TagInfo.ts`) / `795B` (`apdu.js`)
2. **Bulk Distributed (`v2`, `application/vnd.ghost.bulk`)**:
   - Fixed binary overhead: **`134 bytes`** (`74B` AAD + `32B` SHA-256 `CHUNK_HASH` + `12B` nonce + `16B` GCM tag).
   - **Only `NTAG215` (`326B`/`333B`) and `NTAG216` (`706B`/`717B`) fit v2 bulk chunks.** `NTAG213` cannot fit v2 bulk headers (`0B`, `fits: false`).

## Write-Verify Invariant
Ghost-Tag never declares a physical tag write complete until the NDEF record is written and read back cleanly (`verifyOperation` / `writeTagNdefAndVerify`). See [Batch Write](Batch-Write) and [Technical Format](Technical-Format).
