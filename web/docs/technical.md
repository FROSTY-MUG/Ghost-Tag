# Ghost-Tag (`v2.1.0`) Technical Specification

## Binary Envelope Format (v1 Single-Tag: 54 Bytes Overhead / v2 Bulk: 134 Bytes Overhead)

Every Ghost-Tag NFC payload is stored inside an NDEF MIME Media Record:
- **v1 Single-Tag MIME**: `application/vnd.ghost.secure`
- **v2 Bulk Chunk MIME**: `application/vnd.ghost.bulk`

All integers use strict **Little-Endian** encoding. Both versions begin with the 4-byte ASCII magic identifier `"GTAG"` (`0x47 0x54 0x41 0x47`).

### v1 Single-Tag Envelope (`54 + N` bytes)

```text
Offset  Size    Field               Value / Notes
0       4B      MAGIC               0x47 0x54 0x41 0x47 ("GTAG")
4       1B      VERSION             0x01
5       1B      PURPOSE             0x01 (NOTE) .. 0x06 (RECOVERY)
6       16B     KEY_ID              Unique 128-bit DEK Identifier
22      4B      CIPHERTEXT_LEN (N)  uint32 Little-Endian
26      12B     NONCE (IV)          96-bit CSPRNG AES-256-GCM IV
38      N       CIPHERTEXT          AES-256-GCM Encrypted Payload
38+N    16B     GCM_TAG             128-bit AEAD Authentication Tag
```

- **Authenticated Additional Data (`AAD`)**: Bytes `0..25` (`26 bytes`).

### v2 Bulk Distributed Chunk Envelope (`134 + N` bytes)
- **AAD**: Bytes `0..73` (`74 bytes`: `MAGIC`, `0x02`, `RECORD_TYPE = 0x10`, `VAULT_ID`, `FILE_ID`, `KEY_ID`, `GLOBAL_CHUNK_INDEX`, `TOTAL_VAULT_CHUNKS`, `FILE_CHUNK_INDEX`, `TOTAL_FILE_CHUNKS`, `CHUNK_CIPHERTEXT_LENGTH`).
- **Per-Chunk Digest (`74..105`)**: Full `32-byte` `SHA-256(CHUNK_CIPHERTEXT)`. (No Merkle tree is used.)
- **Encryption (`106..133+N`)**: `NONCE (12B)` + `CHUNK_CIPHERTEXT (N B)` + `GCM_TAG (16B)`.

## NTAG21x Framed Capacity Matrix

| Tag IC | User EEPROM | v1 Single Max (`TagInfo.ts` / `apdu.js`) | v2 Bulk Max (`TagInfo.ts` / `apdu.js`) |
| :--- | :--- | :--- | :--- |
| **NTAG213** | `144B` | `52B` / `56B` | **Incompatible (`0B`, `fits: false`)** |
| **NTAG215** | `504B` | `404B` / `411B` | `326B` / `333B` |
| **NTAG216** | `888B` | `784B` / `795B` | `706B` / `717B` |

## Cryptographic Primitives & Key Derivation
1. **Primary Vault KDF (`src/contracts/keyHierarchy.ts`)**: RFC 9106 Argon2id (`16 MiB` Low-End, `32 MiB` Standard default, `64 MiB` High-End; `16B` CSPRNG salt).
2. **Cross-Platform Recovery KDF (`supabase/functions/_shared/recoveryCrypto.ts`, Web `hash-wasm` WASM)**: Two-stage Argon2id (`m=32768 KiB, t=3, p=2, h=32B, v=0x13`) over a server-generated 32-byte CSPRNG `recovery_salt` (`account-auth`), paired with Cloudflare Turnstile + `76B` HMAC challenge-proof verification (`recover-vault`).
3. **Erasure Coding**: Systematic Cauchy-Vandermonde Reed-Solomon over $\mathrm{GF}(2^8)$ (`0x11d`).
4. **Hardware-Only Companion**: Desktop browsers connect exclusively via WebSocket (`ws://127.0.0.1:41789`) using CSPRNG `sessionToken` auth to Ghost Bridge; zero synthetic NFC simulation exists.

See [`../../README.md`](../../README.md), [`../../FAQ.md`](../../FAQ.md), and [`../../docs/CANONICAL-SPECIFICATION.md`](../../docs/CANONICAL-SPECIFICATION.md).
