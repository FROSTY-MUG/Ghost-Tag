# Ghost-Tag Shared TypeScript Core (`src/`)

## 1. Overview
`src/` contains the canonical TypeScript contracts, cryptographic engines, security memory defenses, vault orchestration, NFC hardware abstraction, optional Supabase client helpers, React Native UI screens, and 24 core automated Jest suites.

## 2. Directory Structure

```text
src/
├── cloud/          # Opt-in Supabase recovery & metadata client + URL sanitizer
├── contracts/      # Shared wire protocols, error taxonomy (38 codes), KDF/recovery/tag types
├── crypto/         # AES-256-GCM, Argon2id RFC 9106, Cauchy RS GF(2^8), 54B/134B codecs, keyWrap
├── nfc/            # Hardware manager, NTAG21x capacity calculations, NDEF framing, wipe/verify
├── operations/     # Finite state machines: scan, write, bulkWrite, bulkScan, reconstruct, wipe
├── security/       # Device integrity checks, 4-pass secureWipe, constant-time compare, redaction
├── ui/             # React Navigation stack, monochrome terminal theme, 9 screens + DeleteEntryModal
├── utils/          # Buffer polyfills and shared runtime utilities
├── vault/          # Session auto-lock, DEK manager, 72h RAM ChunkCache, journal, BIP-39 wordlist
└── __tests__/      # 24 automated Jest test suites (plus 1 desktop & 1 cors/integration suite)
```

## 3. Canonical Constants in `src/contracts/`
- **v1 Single-Tag Envelope (`contracts/envelope.ts`)**: `GTAG` magic, version `0x01`, `54B` overhead (`26B` AAD), MIME `application/vnd.ghost.secure`.
- **v2 Bulk Distributed Envelope (`contracts/bulkEnvelope.ts`)**: `GTAG` magic, version `0x02`, `RECORD_TYPE = 0x10`, `134B` overhead (`74B` AAD, bytes `0..73`), full `32B` SHA-256 `CHUNK_HASH` at `74..105`, MIME `application/vnd.ghost.bulk`.
- **Argon2id Tiers (`contracts/keyHierarchy.ts`)**: `LOW_END` (`16 MiB`, `t=2`, `p=1`), `STANDARD` (`32 MiB`, `t=3`, `p=2`), `HIGH_END` (`64 MiB`, `t=4`, `p=4`), `DEFAULT_RECOVERY_KDF_CONFIG` (`64 MiB`, `t=5`, `p=4`, `32B` salt).
- **NTAG21x Capacities (`nfc/tagInfo.ts`)**:
  - `NTAG213` (`144B`): v1 `52B`; v2 bulk **`0B` (does not fit)**.
  - `NTAG215` (`504B`): v1 `404B`; v2 bulk `326B`.
  - `NTAG216` (`888B`): v1 `784B`; v2 bulk `706B`.

## 4. Build, Lint & Test

```bash
npm run typecheck
npx tsc -p tsconfig.build.json --noEmit
npm run lint
npm test -- --ci --maxWorkers=2
```

All UI screens under `src/ui/screens/` avoid simulated tag events or hardcoded sample files and check real hardware availability via `ghostNfcManager` and `checkDeviceIntegrity`. Physical NFC testing on real handset hardware remains pending (`../PROJECT-STATUS.md`, [`../FAQ.md`](../FAQ.md)).
