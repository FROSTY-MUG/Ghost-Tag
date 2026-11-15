# Ghost-Tag v2.0.5 Release Notes

Ghost-Tag is a minimal, dark, premium encrypted NFC storage system featuring an Android APK and lightweight cross-platform web client.

## Highlights
- **12-Word BIP-39 Recovery**: Cross-platform 12-word mnemonic recovery phrase with 4-bit SHA-256 checksum and 3-word verification.
- **Volatile In-Memory Reconstruction**: Zero persistent disk caching of decrypted or intermediate chunks.
- **Mixed NFC Capacity Engine**: Automatic detection and optimal chunk allocation across NTAG213, NTAG215, and NTAG216 tags.
- **Single-Tag & Multi-Tag Modes**: Native single-tag storage with 54B envelope overhead and multi-tag sharding with 134B chunk overhead.
- **Opt-In Zero-Knowledge Cloud Sync**: Anonymous Supabase encrypted metadata backup relay; zero knowledge of keys, passphrases, or payloads.

## Verification
- SHA-256 checksums verified
- 140/140 unit and integration tests passing (100%)
- Strict TypeScript invariant compilation verified
