# Bulk Verification

Before completing a multi-tag write or accepting a scanned chunk, Ghost-Tag verifies per-chunk integrity using the `32`-byte SHA-256 `CHUNK_HASH` inside the `v2` envelope header (`134B` overhead) and `74B` AAD.

## Verification Steps
1. **Per-Chunk Hash**: Each `v2` chunk carries a `32`-byte SHA-256 digest checked during read/write ([src/nfc/bulkNdefBuilder.ts](../../src/nfc/bulkNdefBuilder.ts)).
2. **Read-Back Check**: Batch write verifies written tag bytes against the expected serialized NDEF payload ([Batch-Write.md](Batch-Write.md)).
3. **Vault Consistency**: Cross-tag `vaultId`, `chunkIndex`, and `totalChunks` metadata are validated before reconstruction ([src/vault/bulkVaultManager.ts](../../src/vault/bulkVaultManager.ts)).

## Canonical Sources
- [src/vault/bulkVaultManager.ts](../../src/vault/bulkVaultManager.ts)
- [src/__tests__/bulkOperations.test.ts](../../src/__tests__/bulkOperations.test.ts)
