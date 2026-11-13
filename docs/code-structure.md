# Ghost-Tag Codebase Structure & File Guide

This document provides a comprehensive directory and file tour of the entire Ghost-Tag codebase.

```
Ghost-Tag/
├── android/                    # Android native project files & Gradle build
│   ├── app/src/main/cpp/       # C++17 Native Security & Anti-Reverse Engineering Core
│   │   ├── CMakeLists.txt      # Native build definition for libghosttag_security.so
│   │   ├── security_core.h/cpp # ptrace, /proc/self/status, /proc/self/maps, Frida/Xposed/su checks
│   │   ├── secure_memory.h/cpp # mlock page locking, volatile zeroize, timingSafeCompare
│   │   └── jni_bridge.cpp      # JNI bridge exports to Kotlin SecurityBridgeModule
│   ├── app/src/main/java/com/ghosttag/
│   │   ├── MainActivity.kt     # Enforces window FLAG_SECURE against screen capture/task switcher
│   │   ├── MainApplication.kt # Registers SecurityPackage and React Native hosts
│   │   └── security/           # Kotlin security bridge & hardware KeyStore wrapper
│   │       ├── SecurityBridgeModule.kt # React Native module exposing native C++ checks
│   │       ├── SecurityPackage.kt      # Native package registration
│   │       └── KeyStoreMasterKey.kt    # Android KeyStore TEE/StrongBox AES-GCM master key
│   └── app/src/main/
│       ├── AndroidManifest.xml # Permissions, network security config, allowBackup=false
│       └── res/xml/network_security_config.xml # Cleartext traffic rejection
├── ios/                        # iOS platform scaffolding (deferred target)
├── docs/                       # Exhaustive project documentation
│   ├── security-hardening.md   # Multi-language anti-reverse engineering, memory locking & anti-leak
│   ├── bulk-scanning-v2.md     # Bulk distributed vault & Cauchy erasure coding
│   ├── architecture.md         # Subsystem architecture & interaction diagrams
│   ├── cryptography.md         # Argon2id, AES-GCM, and key wrapping specs
│   ├── envelope-specification.md # Canonical binary envelope formats (v1 & v2)
│   ├── nfc-tag-matrix.md       # Type 2 tag hardware matrix & memory maps
│   ├── user-flow.md            # Step-by-step UX & backend flow walkthroughs
│   └── code-structure.md       # This file
├── src/                        # Core TypeScript source code
│   ├── security/               # Hardened Security & Anti-Leak Application Layer
│   │   ├── deviceIntegrity.ts  # Fail-closed integrity coordinator & anti-tamper enforcement
│   │   ├── secureWipe.ts       # 4-pass memory overwrite (0xAA, 0x55, random, 0x00) & object scrub
│   │   ├── antiLeak.ts         # Constant-time comparison, secret redaction, sanitized logger
│   │   └── index.ts            # Barrel export
│   ├── contracts/              # Shared types, enums, specifications
│   │   ├── envelope.ts         # Single-payload envelope constants and interfaces
│   │   ├── bulkEnvelope.ts     # 134-byte bulk chunk binary wire layout & AAD
│   │   ├── bulkVault.ts        # Bulk multi-file manifest, journals, and cache schemas
│   │   ├── errors.ts           # 33 canonical error codes, severity tiers, GhostTagError
│   │   ├── keyHierarchy.ts     # KEK, DEK, WrappedDEK, and KDF parameter types
│   │   ├── recovery.ts         # BIP39 recovery envelope and state definitions
│   │   ├── states.ts           # FSM states for Scan, Write, and Wipe workflows
│   │   ├── tags.ts             # Supported tag matrix and capacity lookup tables
│   │   ├── vault.ts            # Persistent vault schema and audit definitions
│   │   └── index.ts            # Barrel export
│   ├── crypto/                 # Cryptographic core
│   │   ├── random.ts           # CSPRNG wrappers (generateNonce, generateDEK)
│   │   ├── argon2.ts           # Argon2id KDF derivation and device tier calibration
│   │   ├── aesGcm.ts           # AES-256-GCM authenticated encryption/decryption
│   │   ├── envelope.ts         # v1 Little-endian envelope serializer and parser
│   │   ├── bulkEnvelope.ts     # v2 134-byte chunk serializer, parser, validator, AAD
│   │   ├── erasureCoding.ts    # Cauchy-Vandermonde Reed-Solomon over GF(2^8)
│   │   ├── fileEncryption.ts   # Arbitrary binary file encryption, splitting, reassembly
│   │   ├── keyWrap.ts          # NIST SP 800-38D AES-GCM key wrapping routines
│   │   ├── secureMemory.ts     # In-place buffer zeroization helpers
│   │   └── index.ts            # Barrel export
│   ├── vault/                  # Encrypted local storage and keys
│   │   ├── database.ts         # Encrypted MMKV key-value storage adapter
│   │   ├── vaultManager.ts     # Primary single-payload vault manager
│   │   ├── bulkVaultManager.ts # Multi-file vault manager & private tag mapping
│   │   ├── chunkCache.ts       # 72-hour temporary encrypted chunk cache with TTL
│   │   ├── journalManager.ts   # Persistent write & scan session journal recovery
│   │   ├── session.ts          # In-memory ephemeral KEK lifecycle with auto-lock
│   │   ├── dekManager.ts       # 256-bit DEK generation, storage, and rotation
│   │   ├── recoveryManager.ts  # 24-word BIP39 phrase generation and restoration
│   │   ├── manifest.ts         # HMAC-SHA-256 vault metadata authentication
│   │   ├── auditLog.ts         # Tamper-evident hash-chained operational log
│   │   ├── wordlist.ts         # Canonical 2048-word BIP39 English dictionary
│   │   └── index.ts            # Barrel export
│   ├── nfc/                    # NFC hardware abstraction layer
│   │   ├── nfcManager.ts       # Android foreground dispatch and adapter lifecycle
│   │   ├── tagReader.ts        # NDEF reader and envelope extractor
│   │   ├── tagWriter.ts        # Atomic NDEF writer with read-back verification
│   │   ├── tagInfo.ts          # Type 2 tag identification & bulk capacity calculation
│   │   ├── tagWiper.ts         # Destructive multi-pass page sanitization
│   │   ├── ndefBuilder.ts      # Single-envelope MIME record encoder/decoder
│   │   ├── bulkNdefBuilder.ts  # Bulk chunk MIME (application/vnd.ghost.bulk) builder
│   │   ├── errors.ts           # Native Android NFC error mapper
│   │   └── index.ts            # Barrel export
│   ├── operations/             # Workflow orchestration engine
│   │   ├── scanOperation.ts    # Single-tag scan, NDEF parse, and decrypt
│   │   ├── writeOperation.ts   # Single-tag capacity check, encrypt, and verify
│   │   ├── bulkWriteOperation.ts # Multi-tag chunk write with extra-tag exclusion
│   │   ├── bulkScanOperation.ts  # Random-order tag scanning & duplicate suppression
│   │   ├── reconstructionEngine.ts # Erasure decode, ciphertext join, full decryption
│   │   ├── fileViewerAndExporter.ts # SAF file export & disposable zeroization
│   │   ├── wipeOperation.ts    # Destructive page overwrite and honesty checks
│   │   ├── verifyOperation.ts  # Passive envelope validation without decryption
│   │   ├── repairOperation.ts  # Re-encryption and key rotation pipeline
│   │   ├── diagnosticsExporter.ts # Scrubbed system health and audit export
│   │   ├── operationCoordinator.ts # Central facade connecting all subsystems
│   │   └── index.ts            # Barrel export
│   ├── ui/                     # Monospace terminal-style user interface
│   │   ├── components/         # StatusLine, TerminalOutput, ActionButton
│   │   ├── screens/            # Scanner, Write, Wipe, BulkVault, BulkScan, etc.
│   │   ├── navigation/         # React Navigation stack & RootNavigator
│   │   └── theme/              # High-contrast monospace terminal color palette
│   ├── utils/                  # Polyfills and cross-platform helpers
│   │   └── polyfills.ts        # Buffer attachment to globalThis
│   └── __tests__/              # Automated test suites (160 tests passing, 100%)
│       ├── bulkEnvelope.test.ts # v2 134B binary envelope layout & fuzzing
│       ├── fileEncryptionAndErasure.test.ts # Multi-type file encryption & RS decoding
│       ├── bulkOperations.test.ts # End-to-end bulk write, scan, cache, reconstruction
│       ├── nfc.test.ts         # 37 NFC hardware abstraction tests
│       ├── vault.test.ts       # 12 vault and recovery subsystem tests
│       └── operations.test.ts  # 11 tag operations workflow tests
├── __tests__/                  # Root-level test suites
│   ├── App.test.tsx            # App container integration test
│   └── crypto.test.ts          # 39 cryptographic core unit tests
├── CONTRIBUTING.md             # Contribution guidelines & contact details
├── LICENSE                     # MIT License with ethical use notice
├── README.md                   # Master project README
├── SECURITY.md                 # Security policy, threat model, and disclosure
├── package.json                # Project dependencies and script declarations
└── tsconfig.json               # TypeScript strict compilation rules
```

---

## Component Dependency Graph

```
Contracts (No Dependencies)
   ▲
   │
   ├───────────────┬────────────────┐
   │               │                │
Crypto           Vault             NFC
   ▲               ▲                ▲
   │               │                │
   └───────────────┼────────────────┘
                   │
              Operations
                   ▲
                   │
                   UI
```

No circular dependencies exist between any layer. Every module imports exclusively downwards or sideways through the contracts layer.
