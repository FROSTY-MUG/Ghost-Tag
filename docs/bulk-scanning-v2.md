# Ghost-Tag Bulk Scanning v2: Distributed NFC File-Vault

## 1. Product Thesis

**Ghost-Tag Bulk Scanning v2** is an offline, encrypted, distributed NFC file-vault for Android. It allows users to store arbitrary files—such as high-resolution images, video recordings, PDF contracts, audio files, ZIP archives, or raw binary streams—partitioned across a collection of standard physical NFC Forum Type 2 tags (NTAG21x / MIFARE Ultralight family).

Each NFC tag holds exactly one authenticated, encrypted chunk. Later, the user can scan the tags in **any random order**. Ghost-Tag identifies each chunk, verifies its cryptographic authenticity, caches it in local encrypted storage (with a 72-hour TTL), and reassembles and decrypts the original files once sufficient valid chunks have been collected.

---

## 2. Core User Promise and Limitation

### Core User Promise
> **"Ghost-Tag splits your encrypted files into pieces and stores one piece on each NFC tag. You can scan the tags in any order later. Ghost-Tag identifies each piece, verifies it, and reassembles your files when enough valid pieces are collected."**

### Core Limitation
> **"A lost, damaged, or missing tag may prevent reconstruction. Enable redundancy to tolerate lost tags. Ghost-Tag does not prevent tag cloning, deletion, or replay."**

---

## 3. Supported File Types & Storage Access Framework (SAF)

Ghost-Tag treats all selected files as **opaque binary streams** (`Uint8Array`). File contents are never parsed or interpreted prior to encryption.

- **Documents**: `.pdf`, `.docx`, `.xlsx`, `.pptx`, `.txt`, `.md`
- **Images**: `.jpg`, `.png`, `.webp`, `.heic`, `.svg`
- **Videos**: `.mp4`, `.mov`, `.webm`, `.mkv`
- **Audio**: `.mp3`, `.m4a`, `.wav`, `.flac`
- **Archives**: `.zip`, `.7z`, `.tar.gz`
- **Any arbitrary binary file**

### Android Scoped Storage Compliance
Ghost-Tag strictly uses Android's **Storage Access Framework (SAF)**:
- File selection: `Intent.ACTION_OPEN_DOCUMENT`
- File export: `Intent.ACTION_CREATE_DOCUMENT`

Ghost-Tag requests **zero broad storage permissions** (`READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`, or `MANAGE_EXTERNAL_STORAGE` are never required or requested).

---

## 4. Bulk Chunk Binary Envelope Layout (v2)

Bulk chunk records use the registered NDEF MIME type `application/vnd.ghost.bulk`.
All multi-byte numeric fields are encoded in **Little-Endian (LE)** byte order.

```
Offset (Bytes)   Field Name                 Size (Bytes)   Description
--------------------------------------------------------------------------------------------------
00 .. 03         MAGIC                      4 bytes        ASCII "GTAG" (0x47, 0x54, 0x41, 0x47)
04               FORMAT_VERSION             1 byte         0x02 (Bulk Distributed Format)
05               RECORD_TYPE                1 byte         0x10 (BULK_CHUNK)
06 .. 21         VAULT_ID                   16 bytes       128-bit Bulk Vault unique identifier
22 .. 37         FILE_ID                    16 bytes       128-bit unique file identifier
38 .. 53         KEY_ID                     16 bytes       128-bit Data Encryption Key (DEK) ID
54 .. 57         GLOBAL_CHUNK_INDEX         4 bytes        uint32 LE, vault-wide chunk index
58 .. 61         TOTAL_VAULT_CHUNKS         4 bytes        uint32 LE, total chunks in vault
62 .. 65         FILE_CHUNK_INDEX           4 bytes        uint32 LE, chunk index within file
66 .. 69         TOTAL_FILE_CHUNKS          4 bytes        uint32 LE, total chunks for file
70 .. 73         CHUNK_CIPHERTEXT_LENGTH    4 bytes        uint32 LE, chunk payload byte length (N)
74 .. 105        CHUNK_HASH                 32 bytes       SHA-256 digest of chunk ciphertext
106 .. 117       NONCE                      12 bytes       AES-256-GCM Initialization Vector
118 .. (118+N-1) CHUNK_CIPHERTEXT           N bytes        AES-256-GCM encrypted chunk payload
(118+N)..(133+N) GCM_TAG                    16 bytes       128-bit AES-256-GCM authentication tag
--------------------------------------------------------------------------------------------------
Fixed Overhead: 134 bytes
Total Envelope Length: N + 134 bytes
```

### Additional Authenticated Data (AAD)
The envelope binds 74 bytes of Additional Authenticated Data (AAD) into the AES-256-GCM tag:
$$\text{AAD} = \text{MAGIC} \parallel \text{FORMAT\_VERSION} \parallel \text{RECORD\_TYPE} \parallel \text{VAULT\_ID} \parallel \text{FILE\_ID} \parallel \text{KEY\_ID} \parallel \text{GLOBAL\_INDEX} \parallel \text{TOTAL\_VAULT\_CHUNKS} \parallel \text{FILE\_CHUNK\_INDEX} \parallel \text{TOTAL\_FILE\_CHUNKS} \parallel \text{CIPHERTEXT\_LENGTH}$$

Any byte corruption, chunk swap, or index modification causes immediate GCM authentication failure (`GCM_AUTH_FAILED` / `CHUNK_CORRUPT`).

---

## 5. Fault Tolerance: Reed-Solomon / Cauchy Erasure Coding

To protect against lost or physically damaged NFC tags, Ghost-Tag implements systematic $(K + M)$ Cauchy-Vandermonde erasure coding over Galois Field $\text{GF}(2^8)$:
- **$K$ Data Chunks**: Original file ciphertext chunks.
- **$M$ Recovery Chunks**: Parity chunks computed over $\text{GF}(2^8)$ using an $(K+M) \times K$ Cauchy generator matrix.
- **Reconstruction Property**: **Any $K$ valid chunks** out of the $K + M$ total chunks are mathematically sufficient to reconstruct the entire file.

---

## 6. Temporary Encrypted Chunk Cache (72-Hour TTL)

Scanning dozens of tags may occur across multiple physical sessions, locations, or days.
- **72-Hour Time-to-Live (TTL)**: Scanned chunks are cached in local encrypted storage.
- **Duplicate Suppression**: Rescanning an already-collected tag is detected and suppressed (`CHUNK_ALREADY_CACHED`).
- **Auto-Purge**: Chunks exceeding 72 hours are automatically zeroized and purged (`CACHE_EXPIRED`).

---

## 7. Write Pipeline & Extra Tag Exclusion

When storing files across tags:
1. **Dynamic Capacity Calculation**:
   $$\text{Usable Capacity} = \text{Tag User Memory} - \text{NDEF TLV (7B)} - \text{MIME Framing (29B/32B)} - \text{Bulk Overhead (134B)}$$
2. **Extra Tag Exclusion**:
   If a user has 100 NFC tags and the files only require 86 tags:
   - The app explicitly displays:
     > *"Only 86 tags are required. Please set aside the other 14 tags. Scan the 86 required tags one by one."*
   - Ghost-Tag strictly excludes the 14 extra tags from the write session.
3. **Anti-Overwrite Protection**:
   If the user accidentally presents a tag that has already received a chunk in the current session, Ghost-Tag rejects it with `CHUNK_ALREADY_WRITTEN`.
4. **Mandatory Read-Back**:
   Every written tag is immediately read back and verified against the source SHA-256 chunk hash and GCM authentication tag before marking the chunk complete.
