# Ghost-Tag v2.0.5 Technical Specification

Ghost-Tag is an offline encrypted NFC data storage system. It allows sensitive binary payloads to be encrypted client-side and stored across standard NFC Forum Type 2/4/5 tags without remote servers or cloud accounts.

---

## 1. Canonical Binary Envelope Layout

Every NFC record written by Ghost-Tag is prefixed with a binary header bound to the AES-256-GCM cipher via Additional Authenticated Data (AAD):

```text
Offset  Length  Field                Description
0       4B      MAGIC                0x47 0x48 0x54 0x47 ("GHTG")
4       1B      FORMAT_VERSION       0x02
5       1B      PURPOSE              0x01 = Single Tag, 0x02 = Bulk Chunk
6       16B     KEY_ID               Random 128-bit CSPRNG identifier
22      4B      CIPHERTEXT_LENGTH    Little-Endian unsigned 32-bit integer
26      12B     IV / NONCE           Random 96-bit CSPRNG initialization vector
38      16B     AUTH_TAG             128-bit AES-GCM authentication tag
54      ...     CIPHERTEXT           Authenticated encrypted payload
```

### Additional Authenticated Data (AAD) Binding
The AAD encompasses bytes `0..25`:
$$\text{AAD} = \text{MAGIC} \parallel \text{FORMAT\_VERSION} \parallel \text{PURPOSE} \parallel \text{KEY\_ID} \parallel \text{CIPHERTEXT\_LENGTH}$$

Any modification to the header, tag purpose, or payload length results in an immediate authentication rejection (`GCM_AUTH_FAILED`).

---

## 2. Key Derivation & Hierarchy

1. **Master Passphrase**: Minimum 16 characters.
2. **Key Encryption Key (KEK)**:
   - Derived via RFC 9106 Argon2id (mobile native) or PBKDF2-SHA256 (100,000 iterations, web client).
   - 32-byte CSPRNG salt.
3. **Data Encryption Key (DEK)**:
   - 256-bit fresh random CSPRNG key per vault/record.
   - Stored at rest exclusively wrapped via AES-256-GCM under the KEK.
   - Raw keys are zeroized from memory immediately after encryption operations.

---

## 3. BIP-39 12-Word Recovery Specification

- **Entropy**: 128 bits (16 bytes) generated via CSPRNG.
- **Checksum**: First 4 bits of $\text{SHA-256}(\text{Entropy})$.
- **Combined Length**: 132 bits.
- **Words**: 12 words derived from 11-bit indices into the standard 2,048-word BIP-39 English dictionary.
- **Interoperability**: Identical phrase derivation across Android APK and web client.

---

## 4. Multi-Tag Chunking & Erasure Coding

- **MIME Types**:
  - `application/vnd.ghost.secure` (single tag)
  - `application/vnd.ghost.bulk` (bulk distributed chunk)
- **Erasure Coding**: Cauchy Reed-Solomon over Galois Field $GF(2^8)$. Any $K$ out of $N = K + M$ tags allow complete deterministic reconstruction regardless of scanning order.

---

## 5. 72-Hour Cache Policy

- Scanned encrypted chunks are preserved in local browser IndexedDB (`GhostVaultCacheDB_v2`).
- Chunks expire strictly 72 hours after storage.
- Plaintext, passphrases, KEKs, and recovery phrases are **never** persisted to cache.
