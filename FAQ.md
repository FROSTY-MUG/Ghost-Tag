# Ghost-Tag FAQ

**70 evidence-backed questions and answers aligned with the `v2.1.0` codebase (`FROSTY-MUG/Ghost-Tag`).**  
Every answer reflects current repository files, security hardening, and verified test runs. Unverified hardware or undeployed cloud steps are marked explicitly as pending.

---

## 1. Architecture & Offline-First Design

### Q1. What is Ghost-Tag?
Ghost-Tag is a local-first, zero-knowledge NFC encryption platform for storing secrets and arbitrary files on standard NFC Forum Type 2 tags (`NTAG213`, `NTAG215`, `NTAG216`). Clients include a React Native Android app with a native C++17 NDK/JNI security core (`android/`), an experimental Vite web companion (`web/`), a local desktop PC/SC + PN532 bridge (`desktop/`), optional Supabase metadata recovery (`supabase/`), and foundation iOS scaffolding (`ios/`).  
**Citations**: `package.json`, `README.md`, `android/app/src/main/cpp/security_core.cpp`, `desktop/src/server.js`.

### Q2. Does Ghost-Tag work without an internet connection?
Yes. Vault setup, Argon2id key derivation, AES-256-GCM encryption/decryption, Cauchy Reed-Solomon erasure coding, local NFC read/write operations, and 12-word BIP-39 local key unwrapping operate offline without network calls. Cloud synchronization to Supabase is strictly opt-in.  
**Citations**: `src/cloud/supabaseClient.ts`, `src/operations/scanOperation.ts`, `src/operations/writeOperation.ts`, `src/vault/recoveryManager.ts`.

### Q3. Why does `AndroidManifest.xml` include `android.permission.INTERNET` if Ghost-Tag is offline-first?
`android/app/src/main/AndroidManifest.xml` declares `<uses-permission android:name="android.permission.INTERNET" />` so optional user-configured Supabase cloud metadata sync and React Native debug Metro connectivity can operate when enabled, while `res/xml/network_security_config.xml` forbids cleartext HTTP and default offline vaults transmit zero telemetry.  
**Citations**: `android/app/src/main/AndroidManifest.xml`, `android/app/src/main/res/xml/network_security_config.xml`.

### Q4. Where do plaintext secrets live during normal operation?
Only in volatile RAM while an authenticated session is active, bounded by an inactivity auto-lock timer (`5 minutes` default in `VaultSession`) and zeroized via `zeroize` / `secureWipeBuffer` (`0xAA`, `0x55`, CSPRNG, `0x00` + compiler barrier in C++ `secure_memory.cpp`) upon lock, completion, or panic wipe.  
**Citations**: `src/vault/session.ts`, `src/security/secureWipe.ts`, `android/app/src/main/cpp/secure_memory.cpp`.

### Q5. What happens if someone steals or clones an encrypted NFC tag?
They capture only authenticated AES-256-GCM ciphertext (`GTAG` v1 or v2 binary envelope), Key ID (`16B`), nonces, and chunk metadata. Without the Master Passphrase (to derive the KEK) or the wrapped DEK, physical tag dumps reveal no plaintext. However, NFC Type 2 physical tag cloning, overwriting, or erasure by someone with physical access is an inherent hardware property Ghost-Tag cannot prevent.  
**Citations**: `docs/security.md`, `src/ui/screens/BulkVaultCreationScreen.tsx`, `src/crypto/envelope.ts`.

### Q6. Does Ghost-Tag prevent tag cloning or replay attacks?
No. Standard NTAG21x EEPROM UIDs and NDEF sectors are readable without authentication unless hardware password/lock bits are configured externally, and Ghost-Tag treats physical cloning, overwriting, and replay of previously written tags as outside cryptographic secrecy guarantees.  
**Citations**: `src/ui/screens/BulkVaultCreationScreen.tsx`, `docs/CANONICAL-SPECIFICATION.md`.

### Q7. How is code organized under `src/`?
Layers obey strict downward dependency boundaries: `src/contracts/` (zero internal imports) -> `src/crypto/`, `src/security/`, `src/vault/`, `src/nfc/`, `src/cloud/` -> `src/operations/` -> `src/ui/`.  
**Citations**: `src/README.md`, `src/index.ts`, `docs/architecture.md`.

### Q8. What UI screens currently exist in the React Native app?
`RootNavigator.tsx` registers 9 screens (`Home`, `ReadTag`, `WriteTag`, `BulkVaultCreation`, `BulkWrite`, `BulkScan`, `Reconstruction`, `Passphrase`, `Settings`) plus `DeleteEntryModal`. Interactive screens validate hardware state through `ghostNfcManager`, `checkDeviceIntegrity`, and `DEFAULT_KDF_PARAMETERS_BY_TIER` without fabricated sample files or fake NFC detections.  
**Citations**: `src/ui/navigation/RootNavigator.tsx`, `src/ui/screens/ReadTagScreen.tsx`, `src/ui/screens/SettingsScreen.tsx`.

---

## 2. Hardware, NFC Tags & Desktop Readers

### Q9. Which NFC chips are supported?
NFC Forum Type 2 ISO 14443-3A NTAG family chips (`NTAG213`, `NTAG215`, `NTAG216`) are supported, with `NTAG215` and `NTAG216` required for bulk distributed vaults (`v2`). MIFARE Classic is explicitly rejected because of non-Type-2 framing and legacy Crypto-1 weaknesses.  
**Citations**: `src/nfc/tagInfo.ts`, `desktop/src/apdu.js`, `desktop/firmware/esp32_pn532/ghost_pn532_firmware.ino`.

### Q10. Why does NTAG213 work for single-tag v1 vaults (`54B`) but NOT for bulk v2 vaults (`134B`)?
`NTAG213` provides `144 bytes` of user EEPROM (`137 bytes` NDEF usable after Type 2 TLV/capability framing). Adding NDEF MIME header bytes plus the `134-byte` v2 bulk envelope overhead leaves `<= 0 bytes` for ciphertext (`calculateBulkChunkCapacity` and `calculateTagCapacity` both return `fits: false`, `0 bytes` usable). `NTAG213` works only for short single-tag v1 secrets (`52B` in `TagInfo.ts` / `56B` max ciphertext in `desktop/src/apdu.js`).  
**Citations**: `src/nfc/tagInfo.ts`, `desktop/src/apdu.js`, `desktop/test/bridge.test.js`.

### Q11. What are the exact verified NTAG213, NTAG215, and NTAG216 payload capacities?
Exact framing calculations depend slightly on conservative TLV/MIME reservation in React Native (`src/nfc/tagInfo.ts`) vs exact PC/SC APDU record calculation (`desktop/src/apdu.js`):
- **NTAG213 (`144B` user EEPROM)**: v1 single = `52B` (`TagInfo.ts`) / `56B` (`apdu.js`); v2 bulk = **Does not fit (`0B`, `fits: false`)**.
- **NTAG215 (`504B` user EEPROM)**: v1 single = `404B` (`TagInfo.ts`) / `411B` (`apdu.js`); v2 bulk = `326B` (`TagInfo.ts`) / `333B` (`apdu.js`).
- **NTAG216 (`888B` user EEPROM)**: v1 single = `784B` (`TagInfo.ts`) / `795B` (`apdu.js`); v2 bulk = `706B` (`TagInfo.ts`) / `717B` (`apdu.js`).  
**Citations**: `src/nfc/tagInfo.ts`, `desktop/src/apdu.js`, `desktop/test/bridge.test.js`.

### Q12. Why did older documents mention `370B` / `754B` or `10B` for v2 tags?
Those earlier notes subtracted `134` directly from raw user EEPROM (`504 - 134 = 370`, `888 - 134 = 754`, `144 - 134 = 10`) without deducting Type 2 NDEF TLV framing and MIME header bytes (`application/vnd.ghost.bulk`). Code and tests enforce real framed capacities (`326B`/`333B`, `706B`/`717B`, and `0B` / incompatible on NTAG213).  
**Citations**: `desktop/test/bridge.test.js`, `src/nfc/tagInfo.ts`.

### Q13. Has Ghost-Tag been verified on physical Android NFC phones and USB readers?
Not yet in this cycle. Android debug/release launch was verified on an Android emulator (`Medium_Phone_API_37.0`) and `desktop/` bridges are verified via unit and protocol tests, while physical NFC handset taps, physical ACS ACR122U USB readers, and physical ESP32+PN532 hardware remain open hardware validation gates.  
**Citations**: `PROJECT-STATUS.md`, `desktop/test/pn532_serial.test.js`, `desktop/test/bridge.test.js`.

### Q14. Does desktop browser use have a "simulation mode" for NFC tags?
No. Synthetic or simulated NFC events, mock UIDs, and `simulate_tag` actions are explicitly forbidden and rejected by both `web/app.js` and `desktop/src/server.js`. Desktop browsers connect strictly to physical NFC hardware via the local **Ghost Bridge** daemon on `127.0.0.1:41789`.  
**Citations**: `desktop/src/server.js`, `web/app.js`.

### Q15. Which desktop NFC hardware interfaces are implemented?
`desktop/src/server.js` supports PC/SC readers (such as ACS ACR122U) via `desktop/src/apdu.js`, and `desktop/src/transports/serialTransport.js` implements a framed serial protocol targeting `desktop/firmware/esp32_pn532/ghost_pn532_firmware.ino` on ESP32 + PN532 hardware.  
**Citations**: `desktop/README.md`, `desktop/src/apdu.js`, `desktop/src/transports/serialTransport.js`.

### Q16. What does `GhostNfcManager` do if a device has NFC disabled or unsupported?
`startListening()` checks `isNfcSupported()` and `isNfcEnabled()`, throws typed `GhostTagError` codes (`createNfcUnsupportedError` / `createNfcDisabledError`), and UI screens display explicit hardware errors instead of continuing or simulating data.  
**Citations**: `src/nfc/nfcManager.ts`, `src/ui/screens/ReadTagScreen.tsx`, `src/ui/screens/WriteTagScreen.tsx`.

---

## 3. Cryptography, Key Hierarchy & Memory Defense

### Q17. Which symmetric cipher and authentication mode does Ghost-Tag use?
AES-256-GCM (authenticated encryption with associated data) with unique 12-byte (96-bit) CSPRNG nonces per encryption call and 16-byte (128-bit) authentication tags verified in constant time.  
**Citations**: `src/crypto/aesGcm.ts`, `src/crypto/random.ts`.

### Q18. Why does Ghost-Tag use a 2-tier KEK / DEK key hierarchy?
A Master Passphrase derives an ephemeral 256-bit Key Encryption Key (KEK) via Argon2id. Randomly generated 256-bit Data Encryption Keys (DEKs) encrypt payloads and are wrapped under the KEK (AES-256-GCM with 19-byte domain-separated AAD) and optionally under a recovery KEK. This lets users rotate passphrases or perform emergency recovery without re-encrypting every physical tag.  
**Citations**: `src/contracts/keyHierarchy.ts`, `src/crypto/keyWrap.ts`, `src/vault/dekManager.ts`.

### Q19. What are the exact Argon2id KDF tiers for primary vault unlocking?
Defined in `DEFAULT_KDF_PARAMETERS_BY_TIER` (`src/contracts/keyHierarchy.ts`):
- `LOW_END`: `16,384 KiB` (`16 MiB`), `t = 2`, `p = 1`, `v = 0x13`
- `STANDARD` (default): `32,768 KiB` (`32 MiB`), `t = 3`, `p = 2`, `v = 0x13`
- `HIGH_END`: `65,536 KiB` (`64 MiB`), `t = 4`, `p = 4`, `v = 0x13`
All primary salts are 16 bytes CSPRNG (`PRIMARY_KDF_SALT_BYTE_LENGTH`).  
**Citations**: `src/contracts/keyHierarchy.ts`, `src/ui/screens/SettingsScreen.tsx`.

### Q20. What are the Argon2id parameters for recovery derivation and cloud verifiers?
- Local recovery key unwrapping (`DEFAULT_RECOVERY_KDF_CONFIG` in `src/contracts/keyHierarchy.ts`): `65,536 KiB` (`64 MiB`), `t = 5`, `p = 4`, `v = 0x13`, `32B` salt.
- Cross-platform v2.1.0 cloud auth/verifier (`supabase/functions/_shared/recoveryCrypto.ts`, Web `argon2.umd.min.js`): `32,768 KiB` (`32 MiB`), `t = 3`, `p = 2`, `h = 32 bytes`, `v = 0x13`, `32B` server-generated CSPRNG salt.  
**Citations**: `src/contracts/keyHierarchy.ts`, `supabase/functions/_shared/recoveryCrypto.ts`, `web/supabase.js`.

### Q21. Does `src/crypto/argon2.ts` guard against KDF parameter downgrade attacks?
Yes. Before deriving keys or unwrapping wrapped DEKs, parameters are validated against minimum memory, iteration, parallelism, and salt length thresholds to reject weakened metadata headers.  
**Citations**: `src/crypto/argon2.ts`.

### Q22. How does native Android protect keys and UI memory?
`MainActivity.kt` enforces `WindowManager.LayoutParams.FLAG_SECURE` in `onCreate` and `onResume` to block screenshots and task-switcher previews; `KeyStoreMasterKey.kt` wraps keys via `AndroidKeyStore` hardware TEE/StrongBox; and `android/app/src/main/cpp/` implements `ptrace` anti-debug, `/proc/self/maps` hook detection, `su` root checks, `mlock()` page locking, and 4-pass memory wiping with compiler barriers.  
**Citations**: `android/app/src/main/java/com/ghosttag/MainActivity.kt`, `android/app/src/main/java/com/ghosttag/security/KeyStoreMasterKey.kt`, `android/app/src/main/cpp/security_core.cpp`, `android/app/src/main/cpp/secure_memory.cpp`.

### Q23. How does Ghost-Tag prevent timing side channels during verification?
Buffer comparisons across envelope authentication tags, key wrap checks, and server-side challenge/verifier comparisons use constant-time equality (`timingSafeEqual` in `src/security/antiLeak.ts`, `crypto.timingSafeEqual` in desktop Node, and constant-time checks in Supabase Edge Functions).  
**Citations**: `src/security/antiLeak.ts`, `desktop/src/server.js`, `supabase/functions/_shared/recoverVaultHandler.ts`.

### Q24. How are secret leaks prevented in error logs?
`redactSensitiveData()` and `SanitizedLogger` in `src/security/antiLeak.ts` scrub 64-character hex secrets, 32-character hex identifiers, and encoded payloads before errors reach logs or diagnostics.  
**Citations**: `src/security/antiLeak.ts`, `src/__tests__/auditSanitizer.test.ts`.

---

## 4. Binary Envelopes & NDEF Wire Formats

### Q25. What is the magic header of Ghost-Tag binary envelopes?
Four ASCII bytes `"GTAG"` (`0x47, 0x54, 0x41, 0x47`), present at offsets `0..3` in both v1 and v2 binary envelopes (`GHTG` and `GTBK` are obsolete mistakes corrected across all documentation).  
**Citations**: `src/contracts/envelope.ts`, `src/contracts/bulkEnvelope.ts`, `desktop/src/apdu.js`.

### Q26. What is the exact layout of a Ghost v1 Single-Tag Envelope (`54B` overhead)?
- MIME type: `application/vnd.ghost.secure`
- Endianness: Little-Endian integers
- Layout: `MAGIC (4B: GTAG)` + `VERSION (1B: 0x01)` + `PURPOSE (1B)` + `KEY_ID (16B)` + `CIPHERTEXT_LENGTH (4B)` = **26B AAD**; followed by `NONCE (12B)` + `CIPHERTEXT (N B)` + `GCM_TAG (16B)` = **`54 + N` bytes total**.  
**Citations**: `src/contracts/envelope.ts`, `src/crypto/envelope.ts`.

### Q27. What is the exact layout of a Ghost v2 Bulk Chunk Envelope (`134B` overhead)?
- MIME type: `application/vnd.ghost.bulk`
- Endianness: Little-Endian integers
- Layout: `MAGIC (4B: GTAG)` + `VERSION (1B: 0x02)` + `RECORD_TYPE (1B: 0x10)` + `VAULT_ID (16B)` + `FILE_ID (16B)` + `KEY_ID (16B)` + `GLOBAL_CHUNK_INDEX (4B)` + `TOTAL_VAULT_CHUNKS (4B)` + `FILE_CHUNK_INDEX (4B)` + `TOTAL_FILE_CHUNKS (4B)` + `CHUNK_CIPHERTEXT_LENGTH (4B)` = **74B AAD (bytes `0..73`)**; followed by `CHUNK_HASH (32B SHA-256 of ciphertext)` at `74..105` + `NONCE (12B)` at `106..117` + `CHUNK_CIPHERTEXT (N B)` + `GCM_TAG (16B)` = **`134 + N` bytes total**.  
**Citations**: `src/contracts/bulkEnvelope.ts`, `src/crypto/bulkEnvelope.ts`.

### Q28. Is Ghost v2 protected by a binary Merkle tree?
No. Each v2 chunk independently stores a full 32-byte `SHA-256(CHUNK_CIPHERTEXT)` inside `CHUNK_HASH` (bytes `74..105`) authenticated via AES-256-GCM over the `74-byte` AAD header (`0..73`), alongside per-file SHA-256 manifest verification. There is no Merkle tree structure in the protocol.  
**Citations**: `src/contracts/bulkEnvelope.ts`, `src/crypto/bulkEnvelope.ts`, `src/operations/reconstructionEngine.ts`.

### Q29. What happens if `CHUNK_CIPHERTEXT_LENGTH` is modified on a physical tag?
Because bytes `70..73` (`CHUNK_CIPHERTEXT_LENGTH`) form part of the authenticated `74-byte` AAD (`0..73`) and length bounds are checked against actual envelope size before decrypting, any truncation or extension triggers immediate rejection (`INVALID_ENVELOPE` / `GCM_AUTH_FAILED`).  
**Citations**: `src/crypto/bulkEnvelope.ts`, `src/__tests__/bulkEnvelope.test.ts`.

### Q30. What NDEF MIME media types are valid?
Only `application/vnd.ghost.secure` (v1 single-tag) and `application/vnd.ghost.bulk` (v2 distributed chunk). `desktop/src/server.js` rejects any other MIME type during write commands.  
**Citations**: `src/nfc/ndefBuilder.ts`, `src/nfc/bulkNdefBuilder.ts`, `desktop/src/server.js`.

---

## 5. Bulk Vaults & Cauchy Reed-Solomon

### Q31. How does Bulk Scanning v2 tolerate missing, lost, or damaged NFC tags?
File ciphertexts are partitioned into $K$ data shards and encoded over $\mathrm{GF}(2^8)$ (primitive polynomial $0\text{x}11\text{d}$) with a Cauchy-Vandermonde generator matrix producing $M$ optional parity shards. Any $K$ of $K+M$ valid chunks reconstructs the original ciphertext stream before decryption.  
**Citations**: `src/crypto/erasureCoding.ts`, `src/__tests__/fileEncryptionAndErasure.test.ts`.

### Q32. Do distributed vault tags need to be scanned in sequential order during recovery?
No. Tags may be tapped in any arbitrary order because every envelope carries `VAULT_ID`, `FILE_ID`, `GLOBAL_CHUNK_INDEX`, `TOTAL_VAULT_CHUNKS`, `FILE_CHUNK_INDEX`, and `TOTAL_FILE_CHUNKS` inside its authenticated `74B` AAD.  
**Citations**: `src/contracts/bulkEnvelope.ts`, `src/operations/bulkScanOperation.ts`.

### Q33. How does duplicate tag detection work while bulk-writing and bulk-scanning?
During bulk writes (`bulkWriteOperation.ts`), rescanning an already-written tag is rejected (`CHUNK_ALREADY_WRITTEN`) so previous shards are not overwritten. During bulk scans (`bulkScanOperation.ts` / `chunkCache.ts`), duplicate shards are rejected without duplicating cache entries.  
**Citations**: `src/operations/bulkWriteOperation.ts`, `src/operations/bulkScanOperation.ts`, `src/vault/chunkCache.ts`.

### Q34. What is the "extra tag exclusion" rule in Bulk Write?
If the user supplies more blank tags than required for $K+M$ chunks, the writer instructs the user to set aside surplus tags and refuses to write beyond the exact required count (`BulkWriteScreen.tsx`).  
**Citations**: `src/ui/screens/BulkWriteScreen.tsx`, `src/operations/bulkWriteOperation.ts`.

### Q35. Where are partially scanned chunks stored during multi-session bulk scans?
In volatile RAM (`Map`) inside `ChunkCacheManager` (`src/vault/chunkCache.ts`) storing encrypted chunk buffers with a `72-hour` (`259,200,000 ms`) TTL. Closing the app purges the in-memory map, and expired records are removed by `purgeExpiredChunks()` without damaging source data remaining on the physical tags.  
**Citations**: `src/vault/chunkCache.ts`, `docs/CANONICAL-SPECIFICATION.md`.

### Q36. Does Ghost-Tag export reconstructed files insecurely to public temp folders?
Reassembled files are meant to be viewed via ephemeral memory buffers or exported strictly via user-scoped Android Storage Access Framework (`ACTION_CREATE_DOCUMENT`), followed by multi-pass buffer wiping.  
**Citations**: `src/operations/fileViewerAndExporter.ts`, `src/ui/screens/ReconstructionScreen.tsx`.

---

## 6. Recovery Phrases & Zero-Knowledge Cloud Recovery

### Q37. Is Ghost-Tag's primary recovery phrase 12 words or 24 words?
**12-word BIP-39 English mnemonic** (`128 bits` entropy + `4 bits` SHA-256 checksum = `132 bits`) is the canonical primary format across Android, Web, iOS, and Supabase cloud recovery. Local `RecoveryManager` retains backward-compatible support for `24-word` phrases (`256-bit` entropy) for offline local DEK unwrapping only.  
**Citations**: `README.md`, `src/contracts/recovery.ts`, `src/vault/recoveryManager.ts`, `src/ui/screens/PassphraseScreen.tsx`.

### Q38. How does v2.1.0 cloud recovery authentication differ from legacy v2.0.5 Option A?
Legacy v2.0.5 ("Option A") derived `recovery_salt` deterministically from `SHA-256("ghost-recovery-salt-v2.0.5:" || phrase)` and posted `{ account_id, recovery_verifier }` directly. **Production `v2.1.0`** replaces that with:
1. Server-generated 32-byte CSPRNG `recovery_salt` provisioned during `account-auth` creation/setup.
2. Two-stage Argon2id derivation (`m=32768, t=3, p=2, h=32, v=0x13`) yielding `recovery_auth_secret` then `recovery_verifier`.
3. Interactive two-step challenge/response (`recover-vault` issues a random challenge nonce + server timestamp; client proves knowledge by submitting a `76-byte` HMAC-SHA256-based proof bound to challenge/nonce/account/timestamp after passing Cloudflare Turnstile verification).  
**Citations**: `supabase/functions/_shared/recoveryCrypto.ts`, `supabase/functions/_shared/recoverVaultHandler.ts`, `supabase/functions/_shared/accountAuthHandler.ts`, `src/__tests__/recoveryChallengeProof.test.ts`.

### Q39. Why do `test-fixtures/recovery/recoveryVectors.json` and `crossPlatformCryptoCompatibility.test.ts` still reference Option A vectors?
They preserve deterministic cross-platform regression coverage for the historical v2.0.5 fixture codec alongside dedicated v2.1.0 tests (`recoveryChallengeProof.test.ts`, `rlsUserAccounts.test.ts`, `rlsGhostVaults.test.ts`, `rateLimitAndSchema.test.ts`, `antiEnumeration.test.ts`, `captchaAndAuthResponsibility.test.ts`).  
**Citations**: `test-fixtures/README.md`, `src/__tests__/recoveryChallengeProof.test.ts`.

### Q40. Does Supabase ever receive plaintext files, passphrases, BIP-39 phrases, or unwrapped DEKs?
No. Supabase tables (`user_accounts`, `vault_metadata`, `recovery_challenges`) store encrypted envelopes (`encrypted_recovery_envelope`, `encrypted_metadata`), CSPRNG `recovery_salt`, and `recovery_verifier` hashes only. Client secrets never leave the device.  
**Citations**: `supabase/migrations/`, `supabase/functions/_shared/syncMetadataHandler.ts`, `src/cloud/supabaseClient.ts`.

### Q41. What protects `recover-vault` against online brute-force attacks and account enumeration?
Cloudflare Turnstile CAPTCHA gate (`verify-captcha` / `turnstile.ts`), atomic PostgreSQL advisory-locked 15-minute sliding-window rate limits per `account_id`, user, and hashed IP (`IP_HASH_SALT`), uniform anti-enumeration error responses tested by `antiEnumeration.test.ts`, and short-lived single-use `recovery_challenges`.  
**Citations**: `supabase/functions/_shared/turnstile.ts`, `src/__tests__/rateLimitAndSchema.test.ts`, `src/__tests__/antiEnumeration.test.ts`.

### Q42. Why was legacy `ghost_vaults` locked down in v2.1.0?
To prevent authenticated clients from reading or tampering with `recovery_verifier`, `recovery_salt`, or `encrypted_vault_blob` directly via Supabase PostgREST. Direct client table access to `ghost_vaults` and sensitive recovery columns on `user_accounts` is revoked; non-sensitive metadata exposure is restricted through hardened RLS and `ghost_vault_status` view/Edge Functions.  
**Citations**: `supabase/migrations/`, `src/__tests__/rlsGhostVaults.test.ts`, `src/__tests__/rlsUserAccounts.test.ts`.

### Q43. Is Supabase already deployed for production v2.1.0?
**No.** Schema migrations and Edge Functions exist and pass mocked/policy tests in the repository, but live deployment to a hosted Supabase project remains pending operator credentials and secrets.  
**Citations**: `PROJECT-STATUS.md`, `supabase/README.md`.

### Q44. How does account deletion work in v2.1.0?
`deletionHandlers.ts` and `deletionPurgeWorker.test.ts` implement soft-deletion scheduling and delayed purge handling controlled exclusively via authenticated service-role Edge Functions (`account_status`, `deletion_scheduled_at`), preventing unprivileged direct column mutation.  
**Citations**: `supabase/functions/_shared/deletionHandlers.ts`, `src/__tests__/deletionPurgeWorker.test.ts`, `src/__tests__/rlsUserAccounts.test.ts`.

---

## 7. Security Hardening, RLS & CodeQL

### Q45. Were any CodeQL alerts open on the repository prior to this finalization pass, and how were they resolved?
Yes. CodeQL High alerts `#75` and `#76` (`js/user-controlled-bypass` on `desktop/src/server.js`) flagged unauthenticated `msg.action` guards around `writeTagNdefAndVerify`. PR `#34` fixed them by introducing per-connection CSPRNG `sessionToken` authentication (`crypto.timingSafeEqual`), an immutable `actionHandlers` `Map` (plus `Map.has` and `typeof === 'function'` guards resolving follow-up alert `#78`), `envelopeBytes` bounds checks (`<= 8192`), and strict MIME allowlisting, plus adding `desktop/**` to `.github/workflows/codeql.yml`.  
**Citations**: `desktop/src/server.js`, `.github/workflows/codeql.yml`, `desktop/test/bridge.test.js`.

### Q46. Did PR #34 use CodeQL alert dismissal or inline suppression comments?
No. All alerts (`#75`, `#76`, `#78`) were fixed cleanly in source logic and verified by CodeQL scanning on PR `#34`. Zero alerts were suppressed or dismissed.  
**Citations**: `.github/workflows/codeql.yml`, `desktop/src/server.js`.

### Q47. What CORS policy protects Ghost Bridge and Supabase Edge Functions?
- **Ghost Bridge (`127.0.0.1:41789`)**: `isBridgeOriginAllowed()` permits `https://frosty-mug.github.io`, explicitly configured `GHOST_APPROVED_ORIGINS` (`https:` only, no wildcards), and non-production loopback `http://localhost:<port>` / `http://127.0.0.1:<port>`, rejecting unauthorized origins with HTTP `403 FORBIDDEN_ORIGIN` on both `/status` and WebSocket upgrades.
- **Supabase Edge Functions**: `supabase/functions/_shared/cors.ts` rejects wildcards and unapproved origins, verified by `src/__tests__/corsValidation.test.ts`.  
**Citations**: `desktop/src/server.js`, `docs/cors-policy.md`, `src/__tests__/corsValidation.test.ts`.

### Q48. Are any signing passwords or developer paths hardcoded in build scripts?
Not anymore. `scripts/package_release_apk.py` requires `ANDROID_KEY_ALIAS` and `ANDROID_KEYSTORE_PASSWORD` from environment variables (failing closed when absent), and `scripts/generate_android_branding.py` uses portable relative paths with an optional `GHOST_TAG_BRANDING_PREVIEW_PATH` override.  
**Citations**: `scripts/package_release_apk.py`, `scripts/generate_android_branding.py`.

### Q49. What dependency vulnerabilities currently exist in npm?
`npm audit --audit-level=moderate` and `npm --prefix web audit --audit-level=moderate` both report `0` vulnerabilities. `desktop/` has no independent `package-lock.json` (`ws` / dependencies are workspace-resolved at root `package-lock.json`), so `npm --prefix desktop audit` requires root lockfile auditing.  
**Citations**: `package.json`, `package-lock.json`, `web/package-lock.json`.

---

## 8. Web Client & Ghost Bridge

### Q50. What technologies power the `web/` companion app?
HTML5, CSS3, ES modules / script bundles built by Vite (`vite@6.4.6`), WebCrypto AES-256-GCM + SHA-256, vendored `hash-wasm` Argon2id WebAssembly (`web/vendor/argon2.umd.min.js`), Cloudflare Turnstile integration (`web/supabase.js`), Web NFC (`NDEFReader`) on Chrome Android, and WebSocket RPC to Ghost Bridge (`web/app.js`).  
**Citations**: `web/package.json`, `web/vite.config.ts`, `web/index.html`, `web/app.js`.

### Q51. How does the Web client connect to desktop USB NFC hardware?
1. User runs `desktop/bin/ghost-bridge.js` locally (`127.0.0.1:41789`).
2. `web/app.js` opens a WebSocket to `ws://127.0.0.1:41789`.
3. Ghost Bridge validates `Origin`, issues a fresh 24-byte hex `sessionToken` in the initial `bridge_status` frame, and requires matching `sessionToken` via `timingSafeEqual` on every `read_tag` and `write_tag` request.  
**Citations**: `web/app.js`, `desktop/src/server.js`, `desktop/test/bridge.test.js`.

### Q52. Where is the web showcase deployed and how is it built?
`.github/workflows/deploy-pages.yml` builds and publishes `web/` to GitHub Pages (`https://frosty-mug.github.io/Ghost-Tag/`). Local production builds run `npm --prefix web run build` outputting to `web/dist/`.  
**Citations**: `.github/workflows/deploy-pages.yml`, `web/README.md`, `web/vite.config.ts`.

### Q53. Does the Web client work in iOS Safari?
No for physical NFC. Apple iOS Safari does not expose the Web NFC API (`NDEFReader`). Users must use Chrome on Android (`>= 89`) over HTTPS, the native Android APK, or desktop Chrome/Edge with Ghost Bridge + USB NFC hardware. Native iOS support (`#25`) remains deferred to `iOS Beta`.  
**Citations**: `web/README.md`, `docs/wiki/Web-App.md`.

### Q54. What Android APK download link is currently live on `web/index.html`?
`web/index.html` points users to the latest published GitHub Release (`v2.0.6` at `https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.6`). A local staging build `web/assets/Ghost-Tag-v2.1.0.apk` (`39.45 MB`, SHA-256 `077ecdb3ec3c052b5c30ec52d884e56461209cf92eb0cc1fe93ddd8214723952`) exists in `web/assets/`, while `v2.1.0` itself is not yet tagged/released on GitHub.  
**Citations**: `web/index.html`, `web/assets/release-meta.json`, `web/assets/Ghost-Tag-v2.1.0.apk.sha256`.

---

## 9. Release Readiness, Build Tooling & Testing

### Q55. What tests run in the default Jest suite and what were the latest verified counts?
`npm test -- --ci --maxWorkers=2` runs **26 test suites / 347 tests** (100% pass, including `desktop/test/bridge.test.js`), covering crypto, bulk envelopes, RS erasure coding, mocked NFC operations, vault lifecycle, RLS isolation specs, rate-limit schema checks, Turnstile auth boundaries, challenge/proof recovery, CORS validation, and web syntax/build checks. Overall measured code coverage: `56.06% Statements`, `46.44% Branches`, `54.67% Functions`, `57.16% Lines`.  
**Citations**: `tests/README.md`, `jest.config.js`.

### Q56. What additional desktop test suite exists beyond the default Jest test pattern?
`npx jest desktop/test/pn532_serial.test.js` runs **1 suite / 22 tests** covering PN532 serial protocol framing, timeouts, disconnect handling, read-back verification, and refusing synthetic events — bringing combined JS/TS unit test coverage to **369 tests across 27 suites**.  
**Citations**: `desktop/test/pn532_serial.test.js`, `tests/README.md`.

### Q57. What JDK is needed to run Android Gradle builds locally on Windows?
Gradle 9 / AGP requires JDK 17+ (`JAVA_HOME` pointing to Android Studio JBR `OpenJDK 25.0.4` or Eclipse Adoptium JDK 17). A default Windows system `java.exe` on `PATH` from JRE 8 will fail Gradle startup. Note that `./gradlew.bat test --no-daemon` builds cleanly (`BUILD SUCCESSFUL`), while `:app:testDebugUnitTest` currently reports `NO-SOURCE` because no JVM unit tests exist under `android/app/src/test`.  
**Citations**: `android/README.md`, `android/app/build.gradle`.

### Q58. How did Android emulator launch verification go?
After fixing `MainActivity.kt` / NDK/branding configuration, the Android v2.1.0 app installed and launched cleanly on Android emulator `Medium_Phone_API_37.0` with Ghost-Tag custom branding (`#000000` / `#FFFFFF` / `#DC2626`) and zero startup crashes (`logcat` clean). Real physical handset NFC antenna testing remains pending.  
**Citations**: `PROJECT-STATUS.md`, `android/app/src/main/java/com/ghosttag/MainActivity.kt`.

### Q59. Are iOS Xcode versions synchronized with Android?
Yes. In `ios/GhostTag.xcodeproj/project.pbxproj`, both Debug and Release configurations now specify `MARKETING_VERSION = 2.1.0;` and `CURRENT_PROJECT_VERSION = 7;` (`Info.plist` resolves `CFBundleShortVersionString` and `CFBundleVersion` from those variables), matching `android/app/build.gradle` (`versionName "2.1.0"`, `versionCode 7`).  
**Citations**: `ios/GhostTag.xcodeproj/project.pbxproj`, `ios/GhostTag/Info.plist`, `android/app/build.gradle`.

### Q60. Are dead-code and static security/quality scripts wired in CI?
Yes: `node tests/scan-unused.cjs` scans `web/` and `desktop/` for unused top-level declarations; `.github/workflows/ci.yml`, `agent-quality-gate.yml`, `agent-security-audit.yml`, and `codeql.yml` enforce TypeCheck, Lint, Jest, unused checks, secret audits, version sync, and CodeQL analysis on every PR to `main`.  
**Citations**: `.github/workflows/ci.yml`, `scripts/quality_audit_agent.py`, `scripts/security_audit_agent.py`.

### Q61. Why are GitHub `v2.1.0` tags, Releases, and npm publishes NOT created yet?
`v2.1.0` remains unreleased until physical hardware NFC validation (Android real phone NFC, ACR122U USB reader, ESP32/PN532) and live Supabase schema/Edge Function deployment are completed cleanly.  
**Citations**: `PROJECT-STATUS.md`, `RELEASE-NOTES.md`.

### Q62. Where does `.devcontainer/devcontainer.json` run and what Node version does it use?
It provides a standardized VS Code Dev Container targeting Node.js 22 LTS + Android/tooling extensions consistent with `package.json` (`engines.node >= 20`) and CI.  
**Citations**: `.devcontainer/devcontainer.json`, `package.json`.

---

## 10. Governance, PR Triage & Contributions

### Q63. How was PR #24 (`bulk-scanning-v2`) resolved?
PR `#24` (`Skeletor-Pirate`) was audited and safely merged onto `main` after verifying test alignment (`bulkVaultVerification.test.ts`).  
**Citations**: `PROJECT-STATUS.md`.

### Q64. How was PR #2 (`prettier` `2.8.8 -> 3.10.1`) resolved?
Rebased onto `main`, verified locally on a detached worktree (`npm run lint`, `npm run typecheck`, `npm test`), passed all 4 required CI checks (`Analyze Code`, `Autonomous Quality Assurance Agent`, `Autonomous Security Auditor Agent`, `TypeCheck & Automated Test Suite`), and merged cleanly via squash.  
**Citations**: `package.json`, `package-lock.json`, `PROJECT-STATUS.md`.

### Q65. Why is PR #25 (`ios/ghost-tag-support`) deferred?
Classified `defer_with_documented_plan` (`iOS Beta` milestone) because of: (1) merge conflicts with `main` (`README.md`, `package-lock.json`) plus duplicate history from merged PR `#24`; (2) missing `GhostTag.entitlements` + Xcode `CODE_SIGN_ENTITLEMENTS` linkage; (3) directory packaging bug in `scripts/package_release_ipa.py` (`z.write` adding an empty directory entry instead of recursive `os.walk` over `GhostTag.app`); (4) legacy single-POST `SupabaseRecoveryClient.swift`; and (5) unavailability of macOS Xcode / physical iPhone CoreNFC validation on this Windows host.  
**Citations**: `ios/README.md`, `PROJECT-STATUS.md`.

### Q66. Why is PR #21 (`vite` `6.4.6 -> 8.3.8` in `/web`) deferred?
Classified `defer_with_documented_plan` (`v2.2+`) because its branch conflicts on `web/package.json` & `web/package-lock.json` (predating `v2.1.0` and omitting `hash-wasm: ^4.13.0`), and testing `vite@8.3.8` against current `main` emits CommonJS `configLoader: 'native'` deprecation warnings on `web/vite.config.ts`. Current `vite@^6.4.6` builds cleanly with zero audit vulnerabilities.  
**Citations**: `web/package.json`, `web/vite.config.ts`, `PROJECT-STATUS.md`.

### Q67. Why is PR #9 (`typescript` `6.0.3 -> 7.0.2`) deferred?
Classified `defer_with_documented_plan` (`v2.2+`) because installing `typescript@7.0.2` over current `main` breaks `npm run lint` (exit 2: `@typescript-eslint/parser@8.73.0` peer bound `<6.1.0` fails `.eslintrc.js` `@react-native/eslint-config` overrides) and breaks `npx tsc -p tsconfig.build.json --noEmit` (exit 1: `TS5108: Option 'moduleResolution=node10' has removed`).  
**Citations**: `.eslintrc.js`, `tsconfig.build.json`, `PROJECT-STATUS.md`.

### Q68. Why are required status checks enforced on `main`?
Repository branch ruleset (`Main Branch Protection`, ID `27314670`) enforces linear history, no direct pushes or force pushes, and 4 required status checks (`Analyze Code (javascript-typescript)`, `Autonomous Quality Assurance Agent`, `Autonomous Security Auditor Agent`, `TypeCheck & Automated Test Suite`). Every change lands via topic-branch pull requests.  
**Citations**: `CONTRIBUTING.md`, `.github/PULL_REQUEST_TEMPLATE.md`.

### Q69. What is the disclosure process for security vulnerabilities?
Report privately to `aryanarora26110@gmail.com` or via GitHub Security Advisories following `SECURITY.md` (`72-hour` acknowledgment SLA). Never commit secrets, keystores, `.env` files, or API tokens.  
**Citations**: `SECURITY.md`, `SUPPORT.md`.

### Q70. Where can contributors find architecture decisions and agent role specs?
Architecture Decision Records live in `docs/adr/0001..0004`, agent specialization guides live in `AGENT.md` and `agents/`, and contribution standards live in `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md`.  
**Citations**: `AGENT.md`, `CONTRIBUTING.md`, `docs/adr/`.
