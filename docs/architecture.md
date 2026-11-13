# Ghost-Tag System Architecture

Ghost-Tag is structured into six decoupled, single-responsibility subsystems communicating through strictly-typed contracts.

```
+-------------------------------------------------------------------------+
|                        Terminal User Interface                          |
|    (Black background, monospace, real-time status lines, zero-delay)     |
+------------------------------------+------------------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                      Tag Operations Engine                              |
|   (ScanOperation, WriteOperation, WipeOperation, Verify, Diagnostics)    |
+----------+-------------------------+--------------------------+---------+
           |                         |                          |
           v                         v                          v
+----------+------------+ +----------+------------+ +-----------+---------+
|      Local Vault      | |   Cryptographic Core  | |    NFC Abstraction  |
|  (MMKV / SQLCipher)   | | (Argon2id, AES-GCM)   | |  (Hardware / NDEF)  |
|  - Encrypted DB       | | - CSPRNG              | | - Foreground Dispatch|
|  - Wrapped DEKs       | | - Envelope Codec      | | - Read/Write Verify |
|  - Session Lifecycle  | | - Key Wrap / Unwrap   | | - Page Overwrite    |
|  - Recovery Envelope  | | - Memory Zeroization  | | - Capacity Formulas |
|  - Audit Log          | | - RFC 9106 Work       | | - Tag Matrix Checks |
+-----------------------+ +-----------------------+ +---------------------+
           |                         |                          |
           +-------------------------+--------------------------+
                                     |
                                     v
+------------------------------------+------------------------------------+
|                         Shared Contracts                                |
|         (Binary Envelopes, Error Codes, State Machines, Schemas)        |
+-------------------------------------------------------------------------+
```

---

## Subsystem Breakdown

### 1. Shared Contracts (`src/contracts/`)
Defines the authoritative types and invariant constants across the entire stack:
- **`envelope.ts`**: Binary layout, 54-byte overhead constants, AAD calculation specification.
- **`errors.ts`**: 26 canonical error codes, severity levels, and `GhostTagError` hierarchy.
- **`keyHierarchy.ts`**: KEK/DEK specifications, Argon2id parameters, and wrapped key schemas.
- **`vault.ts`**: Database schemas, manifest HMAC structures, and forbidden field lists.
- **`recovery.ts`**: 24-word BIP39 mnemonic configurations and recovery envelope schemas.
- **`tags.ts`**: Hardware capacity lookup tables, page layouts, and exclusions.
- **`states.ts`**: Deterministic finite state machines for Scan, Write, and Wipe flows.

### 2. Cryptographic Core (`src/crypto/`)
Implements zero-dependency, audited cryptographic operations:
- **`random.ts`**: High-entropy CSPRNG accessing OS entropy pools via `react-native-quick-crypto`.
- **`argon2.ts`**: RFC 9106 Argon2id key derivation with device benchmarking and downgrade detection.
- **`aesGcm.ts`**: AES-256-GCM authenticated encryption and constant-time tag verification.
- **`envelope.ts`**: Strict Little-Endian binary serializer, validator, and deserializer.
- **`keyWrap.ts`**: NIST SP 800-38D AES-GCM key wrapping with 19-byte domain separation AAD.
- **`secureMemory.ts`**: In-place zeroization routines wiping memory buffers.

### 3. Local Vault (`src/vault/`)
Secures persistent state and cryptographic sessions:
- **`database.ts`**: AES-256 encrypted key-value storage layer via `react-native-mmkv`.
- **`vaultManager.ts`**: Vault lifecycle coordinator (setup, open, lock, metadata, manifest).
- **`session.ts`**: Volatile KEK storage with 5-minute auto-lock and background task wiping.
- **`dekManager.ts`**: Generates and manages wrapped 256-bit Data Encryption Keys.
- **`recoveryManager.ts`**: BIP39 24-word mnemonic phrase derivation and restoration engine.
- **`manifest.ts`**: HMAC-SHA-256 tamper-evident integrity protection for vault metadata.
- **`auditLog.ts`**: Append-only audit logger with rolling SHA-256 hash chaining.

### 4. NFC Abstraction Layer (`src/nfc/`)
Encapsulates RF communications and NDEF framing:
- **`nfcManager.ts`**: Android foreground dispatch lifecycle and hardware transceiver checks.
- **`tagReader.ts`**: NDEF discovery and binary envelope extraction.
- **`tagWriter.ts`**: NDEF MIME record transmission coupled with mandatory read-back verification.
- **`tagInfo.ts`**: Tag family identification and granular usable space calculation.
- **`tagWiper.ts`**: Low-level 4-byte page overwrite engine with CC protection.
- **`ndefBuilder.ts`**: Native NDEF MIME record (`application/vnd.ghost.secure`) assembler.
- **`errors.ts`**: Native Android NFC error translation into typed GhostTag errors.

### 5. Tag Operations Engine (`src/operations/`)
Coordinates end-to-end workflows:
- **`scanOperation.ts`**: Step-by-step tag detection, envelope reading, DEK resolution, and decryption.
- **`writeOperation.ts`**: Capacity validation, DEK generation, AES-GCM encryption, and atomic write-verify.
- **`wipeOperation.ts`**: Multi-pass user-memory overwrite and verification.
- **`verifyOperation.ts`**: Passive envelope inspection without disclosing decrypted data.
- **`repairOperation.ts`**: Tag re-encryption and key rotation.
- **`diagnosticsExporter.ts`**: Scrubbed system and tag diagnostics export.
- **`operationCoordinator.ts`**: High-level unified facade for UI screens.

### 6. Terminal User Interface (`src/ui/`)
High-contrast terminal experience:
- Black `#000000` background with monospace typography.
- Status lines with bracketed tags: `[SCAN]`, `[PARSE]`, `[KEY]`, `[CRYPTO]`, `[RESULT]`, `[ERROR]`.
- Explicit error codes and zero decorative animations that delay operation feedback.
- Background blurring and memory clearing upon app task switching.
