# Batch Read (`v2.1.0` Random-Order Scan & Reconstruction)

Ghost-Tag `v2.1.0` lets you scan distributed vault tags in **any order**.

```text
Random Tag Tap ─> Parse GTAG v2 (134B overhead, 74B AAD) ─> Verify 32B SHA-256 CHUNK_HASH
      │
      ▼
Store Encrypted Chunk in Volatile RAM ChunkCacheManager (72h TTL Map, Duplicate-Safe)
      │
      ▼  (When >= K unique shards collected)
Invert K x K Cauchy Sub-Matrix in GF(2^8) ─> Reassemble Ciphertext ─> AES-256-GCM Decrypt
```

- **Random Order**: `VAULT_ID`, `FILE_ID`, `GLOBAL_CHUNK_INDEX`, `TOTAL_VAULT_CHUNKS`, `FILE_CHUNK_INDEX`, and `TOTAL_FILE_CHUNKS` are AAD-bound in every tag header (`0..73`).
- **Volatile RAM Cache**: `ChunkCacheManager` keeps encrypted chunks in volatile in-memory `Map` storage (`259,200,000 ms` / 72-hour TTL). Closing the app or letting TTL expire wipes RAM without touching data stored on physical tags.
- **Fault Tolerance**: Any $K$ valid chunks of $K + M$ can reconstruct lost or damaged tags before decryption and SAF export.
