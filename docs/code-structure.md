# Ghost-Tag Codebase Structure & File Guide

This document provides a comprehensive directory and file tour of the entire Ghost-Tag codebase across all programming languages (**C++17**, **Kotlin/Java**, and **TypeScript**).

---

## 1. Complete Repository Directory Tree

```
Ghost-Tag/
├── ci/                                  # Continuous Integration & release pipeline specifications
│   └── build-and-release.yml            # CI test, Android APK build, and GitHub Pages deploy specs
├── android/                             # Android native platform and build files
│   ├── app/
│   │   ├── build.gradle                 # App-level build config, CMake linking, R8 rules
│   │   ├── debug.keystore               # Development signing key
│   │   ├── proguard-rules.pro           # Strict R8 obfuscation and package-flattening rules
│   │   └── src/main/
│   │       ├── AndroidManifest.xml      # NFC permissions, allowBackup=false, network config
│   │       ├── cpp/                     # Native C++17 Security Core
│   │       │   ├── CMakeLists.txt       # CMake build config for libghosttag_security.so
│   │       │   ├── security_core.h      # Declarations for anti-debug, anti-hook, root checks
│   │       │   ├── security_core.cpp    # ptrace, /proc/self/status, /proc/self/maps, su checks
│   │       │   ├── secure_memory.h      # Declarations for mlock, volatile zeroize, timingSafe
│   │       │   ├── secure_memory.cpp    # Kernel page locking and compiler clobber barriers
│   │       │   └── jni_bridge.cpp       # JNI exports to Kotlin SecurityBridgeModule
│   │       ├── java/com/ghosttag/
│   │       │   ├── MainActivity.kt      # Enforces FLAG_SECURE against screen capture/task switcher
│   │       │   ├── MainApplication.kt  # React Native host setup and SecurityPackage loader
│   │       │   └── security/            # Android platform security & KeyStore wrappers
│   │       │       ├── KeyStoreMasterKey.kt    # Hardware-backed KeyStore AES-256-GCM (TEE/StrongBox)
│   │       │       ├── SecurityBridgeModule.kt # React Native bridge module exposing native status
│   │       │       └── SecurityPackage.kt      # ReactPackage registering SecurityBridgeModule
│   │       └── res/xml/
│   │           └── network_security_config.xml # Rejection of cleartext HTTP traffic
│   ├── build.gradle                     # Project-level Gradle build configuration
│   ├── gradle.properties                # JVM memory settings and AndroidX flags
│   └── settings.gradle                  # Gradle project and subproject inclusion
├── docs/                                # Authoritative project documentation suite
│   ├── README.md                        # Documentation portal, roadmap by persona, design invariants
│   ├── architecture.md                  # Subsystem decomposition, interaction, dependency graph
│   ├── bulk-scanning-v2.md              # Bulk distributed vault, Cauchy RS, 72h chunk cache
│   ├── code-structure.md                # This file: complete codebase map and file inventory
│   ├── cryptography.md                  # Argon2id work factors, 2-tier key hierarchy, AES-GCM
│   ├── envelope-specification.md        # v1 (54B) & v2 (134B) Little-Endian binary envelope specs
│   ├── nfc-tag-matrix.md                # Type 2 tag hardware matrix, page layouts, locks, capacities
│   ├── security-hardening.md            # Multi-language defense: ptrace, mlock, FLAG_SECURE, R8
│   └── user-flow.md                     # UX walkthroughs, state machines, background workflows
├── ios/                                 # iOS platform scaffolding (deferred target)
├── src/                                 # Core TypeScript application source code
│   ├── contracts/                       # Shared type declarations, enums, canonical layouts
│   │   ├── envelope.ts                  # Single-payload envelope constants, offsets, and types
│   │   ├── bulkEnvelope.ts              # 134-byte bulk chunk envelope wire format and AAD types
│   │   ├── bulkVault.ts                 # Multi-file manifest, private tag mappings, cache schemas
│   │   ├── errors.ts                    # 38 canonical error codes, severity tiers, GhostTagError
│   │   ├── keyHierarchy.ts              # KEK, DEK, WrappedDEK, and device-tier KDF types
│   │   ├── recovery.ts                  # BIP39 recovery envelope and mnemonic types
│   │   ├── states.ts                    # FSM state definitions for Scan, Write, Bulk, Wipe
│   │   ├── tags.ts                      # Supported tag families, capacities, and exclusion rules
│   │   ├── vault.ts                     # Database schemas, manifest HMAC, and audit types
│   │   └── index.ts                     # Barrel export for contracts
│   ├── crypto/                          # Cryptographic primitives and codec engines
│   │   ├── random.ts                    # CSPRNG wrappers (generateNonce, generateSalt, generateDEK)
│   │   ├── argon2.ts                    # Argon2id RFC 9106 KDF, device benchmarking, downgrade guard
│   │   ├── aesGcm.ts                    # AES-256-GCM authenticated encryption/decryption
│   │   ├── erasureCoding.ts             # Cauchy-Vandermonde Reed-Solomon over GF(2^8)
│   │   ├── fileEncryption.ts            # Opaque file encryption, chunk slicing, reassembly
│   │   ├── envelope.ts                  # v1 Little-Endian 54-byte binary envelope serializer/parser
│   │   ├── bulkEnvelope.ts              # v2 Little-Endian 134-byte chunk serializer, parser, validator
│   │   ├── keyWrap.ts                   # NIST SP 800-38D AES-GCM key wrapping with 19B AAD
│   │   ├── secureMemory.ts              # In-place buffer zeroization helpers
│   │   ├── __tests__/
│   │   │   └── crypto.test.ts           # Crypto core unit tests
│   │   └── index.ts                     # Barrel export for crypto
│   ├── security/                        # Hardened application integrity & memory protection
│   │   ├── deviceIntegrity.ts           # Fail-closed integrity gate & anti-tamper assertions
│   │   ├── secureWipe.ts                # 4-pass memory wiping (0xAA, 0x55, CSPRNG, 0x00)
│   │   ├── antiLeak.ts                  # Constant-time compare, secret redaction, sanitized logger
│   │   └── index.ts                     # Barrel export for security
│   ├── vault/                           # Local encrypted storage and session orchestration
│   │   ├── database.ts                  # Encrypted MMKV key-value adapter
│   │   ├── vaultManager.ts              # Single-payload vault lifecycle coordinator
│   │   ├── bulkVaultManager.ts          # Multi-file vault manager & private tag mapping
│   │   ├── chunkCache.ts                # 72-hour temporary encrypted chunk cache with TTL
│   │   ├── journalManager.ts            # Write and scan crash-resilient transaction journals
│   │   ├── session.ts                   # Ephemeral KEK lifecycle with 5-minute auto-lock
│   │   ├── dekManager.ts                # Wrapped 256-bit DEK generation, storage, and rotation
│   │   ├── recoveryManager.ts           # 24-word BIP39 mnemonic derivation & disaster recovery
│   │   ├── manifest.ts                  # HMAC-SHA-256 tamper-evident metadata authentication
│   │   ├── auditLog.ts                  # Append-only hash-chained operational audit log
│   │   ├── wordlist.ts                  # Canonical 2048-word BIP39 English dictionary
│   │   └── index.ts                     # Barrel export for vault
│   ├── nfc/                             # NFC hardware abstraction layer
│   │   ├── nfcManager.ts                # Android foreground dispatch and adapter lifecycle
│   │   ├── tagReader.ts                 # NDEF tag discovery and binary envelope extractor
│   │   ├── tagWriter.ts                 # Atomic NDEF writer with read-back verification
│   │   ├── tagInfo.ts                   # Type 2 tag identification & bulk capacity calculation
│   │   ├── tagWiper.ts                  # Destructive multi-pass page sanitization
│   │   ├── ndefBuilder.ts               # Single-envelope MIME record encoder/decoder
│   │   ├── bulkNdefBuilder.ts           # Bulk chunk MIME (application/vnd.ghost.bulk) builder
│   │   ├── errors.ts                    # Native Android NFC error translation
│   │   └── index.ts                     # Barrel export for nfc
│   ├── operations/                      # Workflow orchestration engines & state machines
│   │   ├── scanOperation.ts             # Single-tag scan, NDEF extract, DEK unwrap, decrypt
│   │   ├── writeOperation.ts            # Single-tag capacity check, encrypt, write-verify
│   │   ├── bulkWriteOperation.ts        # Multi-tag chunk write with extra-tag exclusion
│   │   ├── bulkScanOperation.ts         # Random-order tag scanning & duplicate rejection
│   │   ├── reconstructionEngine.ts      # Cauchy RS decode, ciphertext join, full decryption
│   │   ├── fileViewerAndExporter.ts     # SAF file export & disposable zeroization
│   │   ├── wipeOperation.ts             # Destructive page overwrite and honesty checks
│   │   ├── verifyOperation.ts           # Passive envelope validation without decryption
│   │   ├── repairOperation.ts           # Re-encryption and key rotation pipeline
│   │   ├── diagnosticsExporter.ts       # Scrubbed system health and audit export
│   │   ├── operationCoordinator.ts      # Central facade connecting all subsystems
│   │   └── index.ts                     # Barrel export for operations
│   ├── ui/                              # High-contrast monospace terminal interface
│   │   ├── screens/
│   │   │   ├── HomeScreen.tsx           # Terminal dashboard & operational navigation hub
│   │   │   ├── ReadTagScreen.tsx        # Single-tag NFC read, Argon2id derivation & decryption
│   │   │   ├── WriteTagScreen.tsx       # Single-tag purpose, capacity meter, encrypt & lock
│   │   │   ├── BulkVaultCreationScreen.tsx # Multi-file selection & tag requirement calculator
│   │   │   ├── BulkWriteScreen.tsx      # Sequential tag write orchestrator with extra-tag exclusion
│   │   │   ├── BulkScanScreen.tsx       # Random-order tag scanner with cache TTL countdown
│   │   │   ├── ReconstructionScreen.tsx # File assembly visualizer, integrity check, SAF export
│   │   │   ├── PassphraseScreen.tsx     # Master passphrase update & 24-word BIP39 recovery
│   │   │   ├── SettingsScreen.tsx       # Platform defense matrix, Argon2id tuning & panic wipe
│   │   │   └── index.ts                 # Barrel export for screens
│   │   ├── navigation/
│   │   │   ├── RootNavigator.tsx        # React Navigation native stack container
│   │   │   ├── types.ts                 # Type-safe navigation parameters
│   │   │   └── index.ts                 # Barrel export for navigation
│   │   └── theme/
│   │       └── index.ts                 # Terminal color palette (#000000 bg, #00ff41 green)
│   ├── utils/                           # Cross-platform polyfills and helpers
│   │   ├── polyfills.ts                 # Buffer global attachment
│   │   └── index.ts                     # Barrel export for utils
│   └── __tests__/                       # Subsystem automated test suites
│       ├── security.test.ts             # Integrity assertions, secure wipe, anti-leak redaction
│       ├── bulkEnvelope.test.ts         # v2 134B binary envelope layout & fuzzing
│       ├── fileEncryptionAndErasure.test.ts # Multi-type file encryption & Cauchy RS decode
│       ├── bulkOperations.test.ts       # End-to-end bulk write, scan, cache, reconstruction
│       ├── nfc.test.ts                  # NFC hardware abstraction & read-back verify tests
│       ├── vault.test.ts                # Vault, sessions, auto-lock, and recovery tests
│       └── operations.test.ts           # Tag operations workflow & FSM tests
├── web/                                 # Official responsive web showcase & interactive simulator
│   ├── index.html                       # Web showcase landing page & interactive workspace
│   ├── styles.css                       # Cyber-terminal high-contrast stylesheet
│   ├── crypto-simulator.js              # In-browser WebCrypto AES-GCM, Cauchy RS GF(2^8), Web NFC
│   └── app.js                           # UI controller, single-tag & bulk reconstruction simulators
├── __tests__/                           # Root-level test suites
│   ├── App.test.tsx                     # App root rendering integration test
│   └── crypto.test.ts                   # Cryptographic core unit tests
├── CONTRIBUTING.md                      # Contribution guide, PR requirements, ethical boundaries
├── LICENSE                              # MIT License with ethical usage clause
├── README.md                            # Primary project documentation & quick start
├── SECURITY.md                          # Security policy, threat model, vulnerability reporting
├── babel.config.js                      # Babel presets for React Native
├── index.js                             # React Native application entry point
├── jest.config.js                       # Jest test runner configuration & module mocks
├── metro.config.js                      # Metro bundler configuration
├── package.json                         # Project metadata, dependencies, scripts
└── tsconfig.json                        # TypeScript strict compiler configuration
```

---

## 2. Directory-by-Directory Breakdown

### 2.1 Native C++ Core (`android/app/src/main/cpp/`)
- **Language**: C++17
- **Target**: Compiled into `libghosttag_security.so` for `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`.
- **Purpose**: Runs low-level Linux kernel syscalls that bypass Java/Dalvik method hooking frameworks (Frida, Xposed) and disassemblers (Jadx).
- **Key Files**:
  - `CMakeLists.txt`: Build configuration with hidden symbol visibility (`-fvisibility=hidden`), stack canary guards, and `-D_FORTIFY_SOURCE=2`.
  - `security_core.h` / `security_core.cpp`: Implements `ptrace(PTRACE_TRACEME)` debugger detection, `/proc/self/status` `TracerPid` parser, `/proc/self/maps` Frida/Xposed/Substrate scanner, socket check to Frida default port 27042, and `su` binary searches.
  - `secure_memory.h` / `secure_memory.cpp`: Implements `mlock()` to lock sensitive key memory into physical RAM (forbidding swap/flash paging) and 4-pass volatile zeroization with `asm volatile("" : : "r"(addr) : "memory")` compiler clobber barriers.
  - `jni_bridge.cpp`: JNI exports exposing native checks to Kotlin `SecurityBridgeModule`.

### 2.2 Kotlin Android Platform Layer (`android/app/src/main/java/com/ghosttag/`)
- **Language**: Kotlin
- **Purpose**: Integrates directly with Android OS security controls.
- **Key Files**:
  - `MainActivity.kt`: Sets `WindowManager.LayoutParams.FLAG_SECURE` in `onCreate()` and `onResume()` to block screenshots, screen recordings, and recent-app task switcher thumbnail leakage.
  - `MainApplication.kt`: Bootstraps React Native and loads `SecurityPackage`.
  - `security/KeyStoreMasterKey.kt`: Uses the `AndroidKeyStore` provider to generate a hardware-isolated AES-256-GCM master key backed by Trusted Execution Environment (TEE) or StrongBox Keymaster.
  - `security/SecurityBridgeModule.kt`: React Native bridge module exposing native C++ integrity checks to JavaScript.
  - `security/SecurityPackage.kt`: Registers `SecurityBridgeModule` with the React Native runtime.

### 2.3 Shared Contracts (`src/contracts/`)
- **Language**: TypeScript
- **Purpose**: Centralized source of truth for interfaces, constants, and layouts. Has **zero internal or external dependencies**.
- **Key Files**:
  - `envelope.ts`: Fixed 54-byte v1 envelope layout (`GTAG`), categorical purposes, and AAD calculations.
  - `bulkEnvelope.ts`: Fixed 134-byte v2 bulk envelope layout (`GTBK`), 74-byte AAD specification, and chunk flags.
  - `bulkVault.ts`: Multi-file manifest records, private physical tag mappings, chunk cache schemas, and transaction journals.
  - `errors.ts`: Canonical registry of 38 error codes, severity levels, and the primary `GhostTagError` class.
  - `keyHierarchy.ts`: KEK, DEK, WrappedDEK, and device-tier calibrated Argon2id parameter profiles.
  - `recovery.ts`: 24-word BIP39 mnemonic configurations and recovery envelope schemas.
  - `tags.ts`: Supported Type 2 Tag hardware matrix, page capacities, dynamic lock bytes, and exclusions.
  - `states.ts`: Deterministic finite state machine definitions for Scan, Write, Bulk, and Wipe operations.
  - `vault.ts`: Vault database schemas, HMAC manifest structures, and forbidden field lists.

### 2.4 Cryptographic Core (`src/crypto/`)
- **Language**: TypeScript (wrapping `react-native-quick-crypto`)
- **Purpose**: Zero-dependency cryptographic primitives, envelope serialization, and key derivation.
- **Key Files**:
  - `argon2.ts`: RFC 9106 Argon2id key derivation, device benchmarking, and parameter downgrade protection.
  - `aesGcm.ts`: AES-256-GCM authenticated encryption/decryption with 12-byte random nonces and constant-time tag checks.
  - `erasureCoding.ts`: Cauchy-Vandermonde Reed-Solomon erasure coding over $\text{GF}(2^8)$ to tolerate lost or damaged NFC tags.
  - `fileEncryption.ts`: Opaque binary file encryption, chunk partitioning, and reassembly.
  - `envelope.ts`: v1 Little-Endian 54-byte binary envelope serializer, validator, and deserializer.
  - `bulkEnvelope.ts`: v2 Little-Endian 134-byte chunk binary envelope serializer, validator, and deserializer with SHA-256 chunk verification.
  - `keyWrap.ts`: NIST SP 800-38D AES-GCM key wrapping with 19-byte domain separation AAD.
  - `random.ts`: High-entropy CSPRNG accessing OS entropy pools (`generateNonce`, `generateSalt`, `generateDEK`).
  - `secureMemory.ts`: In-place buffer sanitization re-exported from `src/security/`.

### 2.5 Hardened Security & Anti-Leak Layer (`src/security/`)
- **Language**: TypeScript
- **Purpose**: Application-level fail-closed integrity coordination, multi-pass memory scrubbing, and log redaction.
- **Key Files**:
  - `deviceIntegrity.ts`: Coordinates integrity checks with native C++ layer. If any compromise (debugger, hooking, root, tampering) is detected, `assertDeviceIntegrity()` executes a panic wipe of in-memory keys and throws a fatal `GhostTagError`.
  - `secureWipe.ts`: 4-pass memory wiping (`0xAA` $\rightarrow$ `0x55` $\rightarrow$ CSPRNG random bytes $\rightarrow$ `0x00`) with recursive object scrubbing.
  - `antiLeak.ts`: Constant-time byte comparison (`timingSafeEqual`), secret redaction filter masking 64-char hex keys and 32-char IVs, and sanitized logging wrappers (`SanitizedLogger`).

### 2.6 Local Vault (`src/vault/`)
- **Language**: TypeScript
- **Purpose**: Encrypted storage, ephemeral key lifecycle, and disaster recovery.
- **Key Files**:
  - `database.ts`: Fast AES-256 encrypted storage adapter backed by `react-native-mmkv`.
  - `vaultManager.ts`: Primary single-payload vault lifecycle coordinator (setup, open, lock, rotate).
  - `bulkVaultManager.ts`: Multi-file distributed vault manager, private tag mappings, and file addition pipeline.
  - `chunkCache.ts`: Offline 72-hour encrypted chunk cache with TTL countdown and auto-purge.
  - `journalManager.ts`: Crash-resilient write and scan transaction journals.
  - `session.ts`: In-memory ephemeral KEK lifecycle with 5-minute auto-lock and background task wiping.
  - `dekManager.ts`: Generates, stores, and rotates wrapped 256-bit Data Encryption Keys.
  - `recoveryManager.ts`: 24-word BIP39 mnemonic generation, derivation, and disaster recovery.
  - `manifest.ts`: HMAC-SHA-256 tamper-evident integrity protection for vault metadata.
  - `auditLog.ts`: Append-only audit logger with rolling SHA-256 hash chaining.
  - `wordlist.ts`: Canonical 2048-word BIP39 English dictionary.

### 2.7 NFC Abstraction Layer (`src/nfc/`)
- **Language**: TypeScript (wrapping `react-native-nfc-manager`)
- **Purpose**: Low-level NFC hardware communication, NDEF record framing, and page sanitization.
- **Key Files**:
  - `nfcManager.ts`: Android foreground dispatch lifecycle and NFC controller state monitoring.
  - `tagReader.ts`: NDEF discovery and binary envelope extraction.
  - `tagWriter.ts`: Atomic NDEF write pipeline with mandatory read-back verification.
  - `tagInfo.ts`: Type 2 tag identification, lock-byte inspection, and usable capacity calculation.
  - `tagWiper.ts`: Destructive page-by-page overwrite engine with CC protection.
  - `ndefBuilder.ts`: Single-envelope MIME record builder (`application/vnd.ghost.secure`).
  - `bulkNdefBuilder.ts`: Bulk chunk MIME record builder (`application/vnd.ghost.bulk`).
  - `errors.ts`: Native Android NFC error translation into typed GhostTag error codes.

### 2.8 Tag Operations Engine (`src/operations/`)
- **Language**: TypeScript
- **Purpose**: Finite state machines orchestrating multi-step cryptographic and RF operations.
- **Key Files**:
  - `scanOperation.ts`: Single-tag detection, envelope extraction, DEK unwrap, and decryption.
  - `writeOperation.ts`: Capacity validation, DEK generation, encryption, write, and verify.
  - `bulkWriteOperation.ts`: Multi-tag sequential write, chunk tracking, and extra-tag exclusion.
  - `bulkScanOperation.ts`: Random-order tag scanning, duplicate rejection, and cache aggregation.
  - `reconstructionEngine.ts`: Cauchy RS decode, ciphertext concatenation, and SHA-256 validation.
  - `fileViewerAndExporter.ts`: Storage Access Framework (SAF) export and disposable zeroization.
  - `wipeOperation.ts`: Multi-pass user-memory overwrite with honesty checks.
  - `verifyOperation.ts`: Passive envelope validation without decrypting plaintext.
  - `repairOperation.ts`: Re-encryption and key rotation workflow.
  - `diagnosticsExporter.ts`: Sanitized audit and system diagnostics export.
  - `operationCoordinator.ts`: High-level unified facade connecting UI screens to subsystems.

### 2.9 User Interface (`src/ui/`)
- **Language**: TypeScript / React Native JSX
- **Purpose**: Monospace terminal user interface with zero decorative delays.
- **Key Files**:
  - `screens/HomeScreen.tsx`: Main dashboard and operational hub.
  - `screens/BulkVaultCreationScreen.tsx`: File selection and tag requirement calculator.
  - `screens/BulkWriteScreen.tsx`: Sequential tag write orchestrator with extra-tag exclusion.
  - `screens/BulkScanScreen.tsx`: Random-order tag scanner with cache TTL countdown.
  - `screens/ReconstructionScreen.tsx`: File assembly visualizer, integrity check, SAF export.
  - `navigation/RootNavigator.tsx`: React Navigation native stack container.
  - `navigation/types.ts`: Type-safe navigation routes and parameters.
  - `theme/index.ts`: High-contrast terminal color palette (`#000000` bg, `#00ff41` green).

### 2.10 Web Showcase & Interactive Simulator (`web/`)
- **Language**: HTML5, CSS3, JavaScript (ES6+ / WebCrypto / Web NFC)
- **Purpose**: Official responsive product website, interactive cryptographic simulator, and Web NFC client for Android Chrome.
- **Key Files**:
  - `index.html`: Responsive single-page application showcasing features, simulators, documentation, and APK download.
  - `styles.css`: High-contrast cyber-terminal theme with responsive card layouts and hex dump styling.
  - `crypto-simulator.js`: In-browser cryptographic engine implementing AES-256-GCM, Cauchy Reed-Solomon over GF(2^8), SHA-256, 4-pass memory zeroization, and Web NFC NDEF read/write.
  - `app.js`: UI controller for single-tag simulation, bulk file partitioning, random-order tag scanning, 72h offline cache countdown, and file reconstruction.

---

## 3. Automated Test Suite Inventory

Ghost-Tag maintains **178 automated tests across 10 test suites with 100% pass rate**:

| Test Suite File | Test Count | Target Subsystems & Features Tested |
| :--- | :--- | :--- |
| `src/__tests__/security.test.ts` | 13 | 4-pass memory wiping, object scrub, `timingSafeEqual`, anti-leak redaction, debugger/hooking/root fail-closed assertions, vault auto-lock abort. |
| `src/__tests__/bulkEnvelope.test.ts` | 18 | v2 134-byte binary chunk envelope layout, 74-byte AAD binding, corrupt chunk rejection, SHA-256 chunk integrity verification. |
| `src/__tests__/fileEncryptionAndErasure.test.ts` | 19 | Multi-type file encryption (PDF, MP4, TXT, ZIP), chunk splitting, Cauchy RS erasure encoding & decoding over $\text{GF}(2^8)$, damaged tag recovery. |
| `src/__tests__/bulkOperations.test.ts` | 18 | End-to-end bulk vault creation, sequential write with extra-tag exclusion, random-order scanning, 72h chunk cache TTL, full-file reassembly. |
| `src/__tests__/nfc.test.ts` | 37 | NFC adapter lifecycle, tag discovery, tag capacity formulas, NDEF framing, atomic read-back verification, multi-pass wipe. |
| `src/__tests__/vault.test.ts` | 12 | Vault initialization, Argon2id benchmark, DEK generation, KEK wrap/unwrap, 5-minute auto-lock, BIP39 24-word recovery. |
| `src/__tests__/operations.test.ts` | 11 | FSM workflows: ScanOperation, WriteOperation, WipeOperation, VerifyOperation, DiagnosticsExporter. |
| `src/crypto/__tests__/crypto.test.ts` | 39 | AES-256-GCM encryption/decryption, Argon2id KDF derivation, downgrade rejection, key wrap AAD binding, CSPRNG nonces. |
| `__tests__/crypto.test.ts` | 9 | Root crypto regression tests. |
| `__tests__/App.test.tsx` | 2 | Root application container mounting and navigation smoke tests. |

---

## 4. Architectural Dependency Rules

```
Contracts (Zero Dependencies)
   ▲
   │
   ├───────────────┬────────────────┬────────────────┐
   │               │                │                │
Crypto          Security          Vault             NFC
   ▲               ▲                ▲                ▲
   │               │                │                │
   └───────────────┼────────────────┴────────────────┘
                   │
              Operations
                   ▲
                   │
                  UI
```

To preserve code cleanliness and maintainability:
1. **Unidirectional Import Rule**: Modules may only import from layers directly below them or from `contracts`. No module ever imports upwards.
2. **Zero Circular Dependencies**: Enforced by TypeScript strict mode and automated build linters.
3. **Contracts Independence**: `src/contracts/` must never import from any other subsystem.
4. **Operations as Single Gate**: The UI layer communicates solely with `src/operations/operationCoordinator.ts` and never calls `src/crypto/` or `src/nfc/` directly.
