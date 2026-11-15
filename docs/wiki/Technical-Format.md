# Technical Binary Envelope Format

Ghost-Tag v2.0.5 uses a unified binary envelope layout across both Android and Web clients.

---

## 1. NDEF Packaging

Ghost-Tag records are encapsulated in standard NFC Data Exchange Format (NDEF) records:
- **TNF**: `0x02` (MIME Media Type)
- **Type**: `application/vnd.ghost.bulk`
- **Payload**: Raw binary envelope described below.

---

## 2. Binary Envelope Layout (Little-Endian)

The fixed header overhead is exactly **106 bytes** followed by variable-length ciphertext and a 16-byte authentication tag:

| Offset | Length | Type | Field Name | Description |
| :--- | :--- | :--- | :--- | :--- |
| `0x00` | 4 bytes | ASCII | `MAGIC` | ASCII `"GTAG"` (`0x47`, `0x54`, `0x41`, `0x47`) |
| `0x04` | 1 byte | uint8 | `FORMAT_VERSION` | Format version (`0x02` for v2.0.5) |
| `0x05` | 1 byte | uint8 | `RECORD_TYPE` | `0x01` = Data Chunk, `0x02` = Redundancy Chunk |
| `0x06` | 16 bytes | raw | `VAULT_ID` | UUIDv4 identifying the target vault |
| `0x16` | 16 bytes | raw | `FILE_ID` | UUIDv4 identifying this specific file/entry |
| `0x26` | 16 bytes | raw | `KEY_ID` | Identifier of the DEK used for encryption |
| `0x36` | 4 bytes | uint32 LE | `GLOBAL_CHUNK_INDEX` | 0-based index across the entire vault |
| `0x3A` | 4 bytes | uint32 LE | `TOTAL_VAULT_CHUNKS` | Declared total chunks in the vault |
| `0x3E` | 4 bytes | uint32 LE | `FILE_CHUNK_INDEX` | 0-based index within this file |
| `0x42` | 4 bytes | uint32 LE | `TOTAL_FILE_CHUNKS` | Declared total chunks for this file |
| `0x46` | 4 bytes | uint32 LE | `CIPHERTEXT_LENGTH` | Length of the encrypted payload in bytes |
| `0x4A` | 32 bytes | raw | `CHUNK_HASH` | SHA-256 digest of `ENCRYPTED_CHUNK` |
| `0x6A` | 12 bytes | raw | `AES_GCM_NONCE` | Random 96-bit initialization vector |
| `0x76` | *L* bytes | raw | `ENCRYPTED_CHUNK` | Ciphertext of the payload chunk |
| `0x76+L` | 16 bytes | raw | `AES_GCM_AUTH_TAG` | 128-bit authentication tag |

---

## 3. Authenticated Additional Data (AAD)

To prevent metadata tampering or chunk re-indexing, the AES-256-GCM cipher binds the first 106 bytes into the authentication tag:

```text
AAD = MAGIC (4B) 
    || FORMAT_VERSION (1B) 
    || RECORD_TYPE (1B) 
    || VAULT_ID (16B) 
    || FILE_ID (16B) 
    || KEY_ID (16B) 
    || GLOBAL_CHUNK_INDEX (4B LE) 
    || TOTAL_VAULT_CHUNKS (4B LE) 
    || FILE_CHUNK_INDEX (4B LE) 
    || TOTAL_FILE_CHUNKS (4B LE) 
    || CIPHERTEXT_LENGTH (4B LE) 
    || CHUNK_HASH (32B)
```

If an attacker alters any header field (such as changing the chunk index or vault ID), AES-GCM verification fails and the chunk is discarded.
