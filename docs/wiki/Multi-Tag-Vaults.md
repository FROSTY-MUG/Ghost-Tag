# Multi-Tag Vaults

Multi-Tag Vaults split larger encrypted payloads across multiple **NTAG215** or **NTAG216** tags using the **Ghost v2** bulk envelope (`134` bytes overhead, `74` bytes AAD, `32` bytes SHA-256 `CHUNK_HASH`).

## Key Capabilities
- **Order-Independent Scanning**: Tags can be tapped in any order; headers identify vault ID, chunk index, and total chunk count ([src/nfc/bulkNdefBuilder.ts](../../src/nfc/bulkNdefBuilder.ts)).
- **Cauchy Reed-Solomon Erasure Coding**: Optional `M` parity tags allow reconstruction from any `K` of `K + M` tags ([src/vault/erasureCoding.ts](../../src/vault/erasureCoding.ts)).
- **72-Hour Volatile RAM Cache**: Partial scans are held in volatile memory only (up to 72h) and never written unencrypted to disk ([src/vault/bulkVaultManager.ts](../../src/vault/bulkVaultManager.ts)).

## Canonical Sources
- [Batch-Write.md](Batch-Write.md)
- [Batch-Read.md](Batch-Read.md)
- [docs/bulk-scanning-v2.md](../bulk-scanning-v2.md)
