# Ghost-Tag

**Ghost-Tag** is designed for offline-first encrypted NFC vaults, with optional zero-knowledge cloud recovery. It turns ordinary NFC tags into local-first encrypted NFC vaults.

It combines AES-256-GCM authenticated encryption, Argon2id key derivation, a KEK/DEK key hierarchy, BIP-39 recovery, and Reed-Solomon erasure coding to distribute encrypted data across multiple NTAG tags.

Ghost-Tag uses 12-word BIP-39 recovery phrases as the primary recovery format. 24-word recovery support is retained for compatibility where implemented.

Ghost-Tag is designed for people who want sensitive data to remain under their control: encrypted locally, recoverable without trusting a cloud provider with plaintext, and physically portable.

[![CI](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/ci.yml/badge.svg)](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/ci.yml)
[![CodeQL](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/codeql.yml/badge.svg)](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/codeql.yml)
[![Security Audit](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/agent-security-audit.yml/badge.svg)](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/agent-security-audit.yml)
[![Quality Gate](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/agent-quality-gate.yml/badge.svg)](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/agent-quality-gate.yml)
[![Android Build](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/android-build.yml/badge.svg)](https://github.com/FROSTY-MUG/Ghost-Tag/actions/workflows/android-build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> **Status:** Ghost-Tag v2.1.0 is an unreleased local staging version. Android, iOS, Ghost Bridge, and PN532 hardware support are not yet physically validated. Supabase is not deployed.

## Why Ghost-Tag?

Most password managers and cloud vaults require trusting a hosted service with metadata, availability, and sometimes recovery workflows.

Ghost-Tag takes a different approach:

- Your master passphrase stays on your device.
- Your recovery phrase stays offline.
- Your data is encrypted before it reaches an NFC tag.
- Cloud recovery stores only a verifier and encrypted metadata—not your passphrase, keys, or plaintext.
- Large files can be split across multiple physical NFC tags.
- Reed-Solomon parity can allow recovery if some tags are lost or damaged.

Ghost-Tag does not replace a hardware security key. It is a portable, encrypted, offline-first data vault built around commodity NFC hardware.

## How it works

```text
Master passphrase
       |
       v
   Argon2id
       |
       v
  KEK (Key Encryption Key)
       |
       +-----------------------------+
       |                             |
       v                             v
  Wrap DEK with AES-GCM      Encrypt vault data with DEK
       |                             |
       v                             v
  Wrapped DEK metadata        Encrypted chunks
                                     |
                                     v
                       Reed-Solomon parity encoding
                                     |
                                     v
                     Distributed across NFC tags
```

When you unlock a vault:

1. Ghost-Tag derives a Key Encryption Key (KEK) from your passphrase using Argon2id.
2. The KEK unwraps a randomly generated Data Encryption Key (DEK).
3. The DEK decrypts the vault payload using AES-256-GCM.
4. AES-GCM authentication fails immediately if the ciphertext or authenticated metadata has been tampered with.

Changing your passphrase re-wraps the DEK under a new KEK. It does not require rewriting every encrypted NFC tag.

## Core features

- **AES-256-GCM authenticated encryption** for confidentiality and tamper detection.
- **Argon2id key derivation** for passphrase-based KEK generation.
- **KEK/DEK separation** so passphrase changes do not require re-encrypting every tag.
- **BIP-39 recovery phrases** for disaster recovery.
- **Reed-Solomon erasure coding** for multi-tag resilience.
- **Out-of-order NFC tag scanning** for distributed vault reconstruction.
- **SHA-256 integrity verification** for individual chunks and reconstructed ciphertext.
- **DEK-free vault verification** to check whether enough valid chunks are present before decryption.
- **Cross-platform architecture** for Android, web, desktop Ghost Bridge, and proposed iOS support.
- **Zero-knowledge Supabase recovery design** that stores encrypted metadata and a recovery verifier, not plaintext secrets.

## Supported NFC tags

| Tag | Usable memory | Intended use |
|---|---:|---|
| NTAG213 | 144 bytes | Small single-tag Ghost v1 vaults |
| NTAG215 | 504 bytes | Single-tag vaults and bulk multi-tag vaults |
| NTAG216 | 888 bytes | Single-tag vaults and bulk multi-tag vaults |

MIFARE Classic tags are not supported.

## Ghost v1: single-tag vaults

Ghost v1 stores a small encrypted payload on one NFC tag.

```text
application/vnd.ghost.secure
```

The envelope includes:

- A `GTAG` magic header.
- A format version.
- A purpose identifier.
- Payload length.
- Argon2id salt.
- AES-256-GCM nonce.
- AES-256-GCM ciphertext.
- A 128-bit GCM authentication tag.

The fixed envelope overhead is **54 bytes**. The first **26 bytes** are bound as Additional Authenticated Data (AAD), preventing tampering with critical envelope metadata.

## Ghost v2: multi-tag bulk vaults

Ghost v2 splits a larger encrypted payload into chunks and distributes them across multiple NFC tags.

```text
application/vnd.ghost.bulk
```

Each chunk carries:

- Vault, file, and key identifiers.
- Global and file-specific chunk indexes.
- Chunk and total-chunk counts.
- Chunk ciphertext length.
- A SHA-256 hash of the chunk ciphertext.
- AES-256-GCM nonce, ciphertext, and authentication tag.

The fixed envelope overhead is **134 bytes**. The first **74 bytes** are authenticated as AAD.

Bulk verification uses a flat two-tier SHA-256 scheme:

1. Each chunk ciphertext is checked against its stored SHA-256 hash.
2. The reconstructed ciphertext is checked against the file-level SHA-256 hash.

This is not a binary Merkle tree.

## Reed-Solomon recovery

Ghost-Tag uses Cauchy-Reed-Solomon erasure coding over GF(2^8).

A vault can be configured with:

- `k` data chunks.
- `m` parity chunks.

Any `k` valid chunks from the `k + m` total chunks can reconstruct the original encrypted payload.

For example, with `k = 4` and `m = 2`:

```text
Original encrypted data
          |
          v
   4 data chunks + 2 parity chunks
          |
          v
  Distributed across 6 NFC tags
```

You can lose up to `m` tags and still reconstruct the vault, provided the remaining chunks are valid and sufficient.

Chunks can be scanned in any order. Duplicate scans are ignored, and corrupted or truncated chunks fail integrity verification.

## Security model

Ghost-Tag is designed around these principles:

- **Local-first cryptography:** Passphrases, recovery phrases, KEKs, and DEKs are not sent to Supabase.
- **Authenticated encryption:** AES-256-GCM detects tampering with ciphertext or authenticated metadata.
- **Memory-hard key derivation:** Argon2id makes offline passphrase guessing more expensive.
- **Explicit zeroization:** Sensitive ephemeral buffers are wiped where supported.
- **Fail-closed parsing:** Malformed, truncated, unsupported, or tampered envelopes are rejected.
- **Rate-limited recovery:** Supabase recovery is designed with layered rate limits and constant-time verifier comparison.

### What Ghost-Tag cannot protect against

Ghost-Tag cannot prevent every physical or device-level attack.

- A compromised or unlocked phone can expose data displayed in the app.
- A passive NFC tag can be physically cloned; cloning copies ciphertext, not plaintext.
- Ghost-Tag cannot guarantee silicon-level forensic erasure.
- A lost passphrase and lost recovery phrase mean the data is unrecoverable.
- Replay of an older valid tag version may be possible unless monotonic hardware counters are available.
- Supabase recovery requires the recovery verifier; it does not eliminate the need to protect recovery phrases.

## Platform support

| Platform | NFC read | NFC write | Status |
|---|---|---|---|
| Android | Implemented in source | Implemented in source | Pending physical-device validation |
| Web companion | Web NFC where supported | Not a primary supported flow | Local staging |
| Desktop Ghost Bridge | PC/SC APDU transport | PC/SC APDU transport | Pending physical-reader validation |
| iOS | Proposed CoreNFC read-only integration | Not implemented | PR #25 open and unmerged |

### Android

Ghost-Tag uses React Native with native Android modules and a C++ cryptographic core.

- Foreground NFC dispatch.
- Native Argon2id bridge.
- Secure screen capture prevention with `FLAG_SECURE`.
- Encrypted local storage.
- Android Keystore-oriented security controls.

Android NFC has not yet been validated on a physical handset.

### iOS

iOS support is proposed through PR #25.

- CoreNFC-based read-only scanning.
- `NFCReaderUsageDescription` and NFC reader-session entitlements.
- No iOS tag writing is implemented.
- Requires a macOS build host, Xcode, and a physical iPhone for real validation.

iOS has not been built or physically tested in the current verification environment.

### Desktop Ghost Bridge

Ghost Bridge is a local desktop companion for PC/SC-compatible readers such as the ACS ACR122U.

- Local-only service boundary.
- ISO/IEC 7816-4 APDU-based NFC operations.
- Browser companion interoperability.
- PN532 serial transport support.

Physical ACR122U and PN532 hardware have not yet been validated.

### Web companion

The web companion is a client-side Vite application.

- Web NFC reading where the browser supports it.
- Local cryptographic operations.
- No telemetry or third-party analytics.
- GitHub Pages deployment workflow.

Web NFC availability varies by browser and platform. It is primarily available in supported Android Chrome environments.

## Supabase recovery

Ghost-Tag’s Supabase integration is designed to avoid sending secrets to the cloud.

```text
Recovery phrase
      |
      v
Derive account_id, recovery_auth_secret, and recovery_salt
      |
      v
Argon2id recovery verifier
      |
      v
Supabase stores verifier and encrypted vault metadata
```

Supabase stores:

- An account identifier.
- A recovery salt.
- A recovery verifier.
- Encrypted vault metadata.

Supabase does **not** store:

- Your recovery phrase.
- Your master passphrase.
- Your KEK.
- Your DEK.
- Plaintext vault data.
- Plaintext NFC contents.

**Supabase is not deployed.** The schema, Edge Functions, and migration RPC are implemented and locally tested, but have not been deployed to a live Supabase project.

## Installation

### Prerequisites

- Node.js 20 LTS or newer
- npm 10 or newer
- Python 3.11 or newer for repository audit agents
- JDK 17 and Android SDK for Android builds

### Clone and install

```bash
git clone https://github.com/FROSTY-MUG/Ghost-Tag.git
cd Ghost-Tag
npm ci
npm --prefix web ci
```

### Run the web companion

```bash
cd web
npm run dev
```

### Run desktop tests

```bash
cd desktop
npm install
npm test
```

## Testing

Run the full verification suite:

```bash
npm run verify
```

Run Jest with coverage:

```bash
npm test -- --ci --coverage --maxWorkers=2
```

Run the repository audit agents:

```bash
python scripts/quality_audit_agent.py
python scripts/security_audit_agent.py
```

### Current quality signals

- **346 automated Jest tests pass across 26 suites** (covering cryptography, key wrap codecs, RLS & rate-limit security, Turnstile CAPTCHA, challenge-proof recovery, anti-enumeration, deletion purge worker, desktop Ghost Bridge & PN532 serial, and web build checks).
- **TypeScript strict check passes.**
- **ESLint passes.**
- **Web production build passes.**
- **Android release build passes in CI.**
- **Zero open CodeQL, Dependabot, and secret-scanning alerts.**

Measured coverage:

| Metric | Coverage |
|---|---:|
| Statements | 56.90% |
| Branches | 47.28% |
| Functions | 55.46% |
| Lines | 57.93% |

A high test-pass rate does not mean 100% code coverage.

## Repository architecture

```text
Ghost-Tag
├── android/         React Native Android app and native modules
├── desktop/         Ghost Bridge, PC/SC, and PN532 transport
├── docs/            Cryptography, envelope, and security documentation
├── ios/             Proposed CoreNFC integration
├── scripts/         Build, audit, and release tooling
├── src/             Shared React Native / TypeScript domain logic
├── supabase/        Zero-knowledge recovery schema and Edge Functions
└── web/             Browser companion application
```

## Contributing

Contributions are welcome.

Before opening a pull request:

1. Fork the repository.
2. Create a topic branch.
3. Install dependencies.
4. Run the verification suite.
5. Ensure TypeScript, ESLint, tests, and relevant builds pass.
6. Open a pull request with a clear description and test evidence.

Direct pushes to `main` are blocked by repository rules. All changes must go through pull requests.

Do not commit:

- Secrets, tokens, credentials, or private keys.
- Recovery phrases or passphrases.
- Generated APK, AAB, IPA, or build artifacts.
- Synthetic NFC or hardware-test evidence.

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## Security reporting

Do **not** open a public GitHub issue for a security vulnerability.

Report vulnerabilities privately through [GitHub Security Advisories](https://github.com/FROSTY-MUG/Ghost-Tag/security/advisories/new).

Include:

- A clear description.
- Affected version or commit.
- Reproduction steps.
- Potential impact.
- Suggested remediation, if available.

See [SECURITY.md](SECURITY.md).

## Roadmap

- Validate the Android APK on a physical Android device.
- Review and merge PR #24 after final evidence review.
- Rebase and validate PR #25 on macOS and a physical iPhone.
- Validate Ghost Bridge with a physical ACR122U reader.
- Validate PN532 serial transport with physical hardware.
- Deploy and validate Supabase recovery in a controlled environment.
- Add offline web support through a service worker.
- Prepare a future Ghost-Tag core package for reusable cryptographic and envelope utilities.

## FAQ

### Is Ghost-Tag anonymous?

No. Ghost-Tag is a privacy-focused encrypted vault, not an anonymity tool. Network metadata, device identifiers, and Supabase account data may still be observable depending on how you use the system.

### Can someone clone my NFC tag?

Yes. Passive NFC tags can be physically cloned. However, a clone contains encrypted ciphertext, not plaintext. Without the correct passphrase or recovery phrase, the cloned data cannot be decrypted.

### What happens if I lose a tag?

If the vault uses Reed-Solomon parity, you may still recover it if enough valid chunks remain. With `k` data chunks and `m` parity chunks, up to `m` tags can be unavailable, assuming the remaining `k` chunks are valid.

### Does Ghost-Tag upload my secrets?

No. The intended design sends only a recovery verifier and encrypted vault metadata to Supabase. Plaintext secrets, passphrases, KEKs, DEKs, and NFC contents are not sent to the cloud.

### Does iOS support writing tags?

No. Ghost-Tag’s iOS integration is read-only. Tag writing is not implemented.

### Is Ghost-Tag production-ready?

Not yet. Ghost-Tag v2.1.0 is unreleased staging software. Physical Android, iOS, Ghost Bridge, and PN532 validation remain pending.

## License

Ghost-Tag is released under the [MIT License](LICENSE).

Ghost-Tag is an independent open-source project. It is not affiliated with, endorsed by, or sponsored by NXP Semiconductors, Apple, Google, ACS, or any other hardware vendor.
