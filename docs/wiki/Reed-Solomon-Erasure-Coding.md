# Reed-Solomon Erasure Coding

Ghost-Tag `v2` bulk vaults use **Cauchy Reed-Solomon erasure coding** over `GF(2^8)` ([src/vault/erasureCoding.ts](../../src/vault/erasureCoding.ts)) to survive physical tag loss or damage.

## How `K`-of-`K + M` Works
- Data is split into `K` data shards and `M` parity shards.
- Any `K` valid shards (in any order) are sufficient to reconstruct the original encrypted payload.
- Verified in [src/__tests__/fileEncryptionAndErasure.test.ts](../../src/__tests__/fileEncryptionAndErasure.test.ts) and [src/__tests__/bulkOperations.test.ts](../../src/__tests__/bulkOperations.test.ts).

## Canonical Sources
- [src/vault/erasureCoding.ts](../../src/vault/erasureCoding.ts)
- [Multi-Tag-Vaults.md](Multi-Tag-Vaults.md)
- [docs/bulk-scanning-v2.md](../bulk-scanning-v2.md)
