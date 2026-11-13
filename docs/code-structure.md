# Ghost-Tag Codebase Structure & File Guide

This document provides a comprehensive directory and file tour of the entire Ghost-Tag codebase.

```
Ghost-Tag/
├── android/                    # Android native project files & Gradle build
│   └── app/src/main/
│       └── AndroidManifest.xml # NFC permissions and intent filter declarations
├── ios/                        # iOS platform scaffolding (deferred target)
├── docs/                       # Exhaustive project documentation
│   ├── architecture.md         # Subsystem architecture & interaction diagrams
│   ├── cryptography.md         # Argon2id, AES-GCM, and key wrapping specs
│   ├── envelope-specification.md # Canonical 54B binary envelope format
│   ├── nfc-tag-matrix.md       # Type 2 tag hardware matrix & memory maps
│   ├── user-flow.md            # Step-by-step UX & backend flow walkthroughs
│   └── code-structure.md       # This file
├── src/                        # Core TypeScript source code
│   ├── contracts/              # Phase 1: Shared types, enums, specifications
│   │   ├── envelope.ts         # Binary envelope constants, offsets, and interfaces
│   │   ├── errors.ts           # 26 error codes, severity tiers, GhostTagError class
│   │   ├── keyHierarchy.ts     # KEK, DEK, WrappedDEK, and KDF parameter types
│   │   ├── recovery.ts         # BIP39 recovery envelope and state definitions
│   │   ├── states.ts           # FSM states for Scan, Write, and Wipe workflows
│   │   ├── tags.ts             # Supported tag matrix and capacity lookup tables
│   │   ├── vault.ts            # Persistent vault schema and audit definitions
│   │   └── index.ts            # Barrel export
│   ├── crypto/                 # Phase 2: Cryptographic core
│   │   ├── random.ts           # CSPRNG wrappers (generateNonce, generateDEK)
│   │   ├── argon2.ts           # Argon2id KDF derivation and device tier calibration
│   │   ├── aesGcm.ts           # AES-256-GCM authenticated encryption/decryption
│   │   ├── envelope.ts         # Little-endian envelope serializer and parser
│   │   ├── keyWrap.ts          # NIST SP 800-38D AES-GCM key wrapping routines
│   │   ├── secureMemory.ts     # In-place buffer zeroization helpers
│   │   └── index.ts            # Barrel export
│   ├── vault/                  # Phase 3: Encrypted local storage and keys
│   │   ├── database.ts         # Encrypted MMKV key-value storage adapter
│   │   ├── vaultManager.ts     # Primary vault lifecycle & session manager
│   │   ├── session.ts          # In-memory ephemeral KEK lifecycle with auto-lock
│   │   ├── dekManager.ts       # 256-bit DEK generation, storage, and rotation
│   │   ├── recoveryManager.ts  # 24-word BIP39 phrase generation and restoration
│   │   ├── manifest.ts         # HMAC-SHA-256 vault metadata authentication
│   │   ├── auditLog.ts         # Tamper-evident hash-chained operational log
│   │   ├── wordlist.ts         # Canonical 2048-word BIP39 English dictionary
│   │   └── index.ts            # Barrel export
│   ├── nfc/                    # Phase 4: NFC hardware abstraction layer
│   │   ├── nfcManager.ts       # Android foreground dispatch and adapter lifecycle
│   │   ├── tagReader.ts        # NDEF reader and envelope extractor
│   │   ├── tagWriter.ts        # Atomic NDEF writer with read-back verification
│   │   ├── tagInfo.ts          # Type 2 tag identification and capacity calculator
│   │   ├── tagWiper.ts         # Destructive multi-pass page sanitization
│   │   ├── ndefBuilder.ts      # MIME Media NDEF record encoder/decoder
│   │   ├── errors.ts           # Native Android NFC error mapper
│   │   └── index.ts            # Barrel export
│   ├── operations/             # Phase 5: Workflow orchestration engine
│   │   ├── scanOperation.ts    # Tag scan, NDEF parse, DEK resolve, and decrypt
│   │   ├── writeOperation.ts   # Capacity check, DEK assign, encrypt, and verify
│   │   ├── wipeOperation.ts    # Destructive page overwrite and honesty checks
│   │   ├── verifyOperation.ts  # Passive envelope validation without decryption
│   │   ├── repairOperation.ts  # Re-encryption and key rotation pipeline
│   │   ├── diagnosticsExporter.ts # Scrubbed system health and audit export
│   │   ├── operationCoordinator.ts # Central facade connecting all subsystems
│   │   └── index.ts            # Barrel export
│   ├── ui/                     # Phase 6: Terminal-style user interface
│   │   ├── components/         # StatusLine, TerminalOutput, ActionButton
│   │   ├── screens/            # Scanner, Write, Wipe, Keys, Settings, etc.
│   │   ├── navigation/         # React Navigation stack & RootNavigator
│   │   └── theme/              # High-contrast monospace terminal color palette
│   ├── utils/                  # Polyfills and cross-platform helpers
│   │   └── polyfills.ts        # Buffer attachment to globalThis
│   └── __tests__/              # Automated test suites
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
