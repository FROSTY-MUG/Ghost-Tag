# Decrypt Flow

The Decrypt flow allows you to reassemble and decrypt entries from physical tags with a single simple workflow.

---

## 1. Step-by-Step Flow

```text
[ Decrypt Now ]
    │
    ▼
[ Start Scanning ] ──► Tap Ghost Tags in ANY order
    │
    ▼
[ All Chips Scanned ] ──► Stops NFC transceiver
    │
    ▼
[ Enter Passphrase ] ──► Verifies auth tag & KEK
    │
    ▼
[ Decrypt & Reassemble ] ──► Validates SHA-256 chunk hashes
    │
    ▼
[ Recovered Entries ] ──► [ View ]  [ Download ]  [ Clear Temporary Data ]
```

---

## 2. Scanning in Any Order

Because every NFC tag contains a 106-byte self-describing header with:
- `global_chunk_index` (which chunk in the entire vault)
- `total_vault_chunks` (how many total chunks exist)
- `file_chunk_index` (which chunk within this specific entry)
- `total_file_chunks` (how many chunks this entry spans)
- `chunk_hash` (SHA-256 digest of this chunk's ciphertext)

You can scan the tags in **completely random order**. Ghost-Tag automatically slots each chunk into its correct index.

---

## 3. Decryption States & Error Handling

### Missing Chunks
If you tap `[All Chips Scanned]` before scanning all required tags:
```text
MORE TAGS NEEDED
Collected: 5 / 12 chunks
Missing: 7 chunks
Scan the remaining Ghost tags to decrypt the complete content.
[Scan More Tags]  [Cancel]
```

### Incorrect Passphrase
```text
DECRYPTION FAILED
The passphrase is incorrect or the data was encrypted with a different Ghost account.
[Try Again]
```

### Tampered Tag Data
If a tag's ciphertext was modified, sector corrupted, or authentication tag fails:
```text
DATA TAMPERED OR INVALID
One or more scanned Ghost records failed integrity verification.
[Scan More Tags]  [Cancel]
```

---

## 4. Volatile Session Data

In accordance with strict security rules, scanned chunks and decrypted entries are held exclusively in volatile memory. Tapping `[ Clear Temporary Data ]` or closing the browser window immediately zeros out all buffers and resets the session.
