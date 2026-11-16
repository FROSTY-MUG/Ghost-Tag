# Batch Read

Ghost-Tag v2.0.5 allows users to scan physical NFC tags in any order, reassemble multi-chip chunks, authenticate the ciphertext, and decrypt the recovered entries with a single action.

```
 +--------------------+       +--------------------+
 |   Tag 3 Scanned    |  ...  |   Tag 1 Scanned    |  (Any Order)
 +---------+----------+       +---------+----------+
           |                            |
           +--------------+-------------+
                          |
                  Volatile Assembly
             (Indexed by globalChunkIndex)
                          |
              [ All Chips Scanned ]
                          |
                  Passphrase Unlock
               (PBKDF2 / Argon2id KEK)
                          |
 +------------------------v------------------------+
 |              Reassembled Payload                |
 |  [Text Note]  [Document.pdf]  [Photo]  [URL]    |
 +-------------------------------------------------+
```

---

## 1. Overview of the Batch Read Flow

1. **Tag Scanning (Order-Independent)**:
   - The user opens **Decrypt** and starts scanning tags.
   - Tags can be tapped in **any order** (e.g. Tag 4, Tag 1, Tag 3, Tag 2).
   - Ghost-Tag parses each tag's `GTAG` envelope:
     - Extracts `vaultId`, `fileId`, `globalChunkIndex`, and `totalVaultChunks`.
     - Validates the 32-byte SHA-256 chunk hash against the ciphertext chunk.
     - Places the chunk into volatile session memory (zero persistent cache).
   - The UI shows real-time tally:
     ```
     SCANNED CHIPS: 3 / 4
     COLLECTED CHUNKS: 0, 2, 3 (Chunk 1 missing)
     ```

2. **Completion Trigger**:
   - When all required chunks are collected, or when the user taps **All Chips Scanned**, the **Decrypt Now** button becomes active.
   - If missing chunks remain, Ghost-Tag displays:
     ```
     MORE TAGS NEEDED
     Collected: 3 / 4 chunks
     Missing: 1 chunk
     Scan the remaining Ghost tags to decrypt the complete content.
     ```

3. **Passphrase Decryption**:
   - The user enters their master vault passphrase.
   - Ghost-Tag derives the AES-256-GCM key and authenticates the AAD and GCM tag.
   - If passphrase or integrity fails: Displays **DECRYPTION FAILED** or **DATA TAMPERED OR INVALID**.
   - If valid: Displays **DECRYPTION COMPLETE** and lists recovered entries.

4. **Viewer, Download, & Individual Entry Deletion**:
   - **View**: Inspect plaintext note or view recovered image/document in-browser.
   - **Download**: Export the verified decrypted file to local storage.
   - **Delete Entry**: On Android, prompts with the physical rewrite corruption warning before rewriting remaining chunks across the tags.
   - **Clear Temporary Data**: Instantly purges all recovered plaintext and session chunks from RAM.

---

## 2. Invariants & Security Guarantees

- **No Scanned-Chunk Cache**: Chunks exist strictly in volatile RAM during the active session. If the user navigates away or closes the browser tab, all cached chunk bytes are immediately wiped.
- **Double Cryptographic Verification**:
  1. Per-chunk SHA-256 hash check prevents corrupt or misaligned sector reads.
  2. End-to-end AES-256-GCM authentication prevents unauthorized tampering or forgery.
- **Cross-Platform Compatibility**: A batch write created on an Android phone using the APK can be read and decrypted seamlessly by the web client (or desktop Ghost Bridge), and vice versa.
