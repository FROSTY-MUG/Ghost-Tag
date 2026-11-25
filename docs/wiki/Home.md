<p align="center">
  <img src="../../web/assets/logo.svg" alt="Ghost-Tag Brutalist Logo" width="64" height="64" />
</p>

# Ghost-Tag Wiki

Welcome to the official **Ghost-Tag** (`v2.1.0` unreleased staging) wiki chapters. Notice that the latest published GitHub Release is **`v2.0.6`**; physical NFC handset, ACR122U, ESP32/PN532, iOS CoreNFC, and live hosted Supabase deployment remain open release gates ([`../../PROJECT-STATUS.md`](../../PROJECT-STATUS.md)).

> **Core Promise**:
> Encrypted NFC storage.
> Create. Encrypt. Scan. Decrypt.

---

## Implemented vs. Proposed & Offline vs. Cloud Boundaries
- **Offline Implemented**: Client-side Argon2id / AES-256-GCM encryption (`54B` v1 single-tag & `134B` v2 Cauchy RS bulk), Android native UI/NDK (`emulator-verified`, physical NFC pending), Web Companion (`live GitHub Pages verified`, Chrome WebNFC hardware pending), and Desktop Ghost Bridge (`mock PC/SC + PN532 verified`, physical readers pending).
- **Cloud-Dependent & Undeployed (`supabase/`)**: Opt-in cross-device recovery (`account-auth`, `recover-vault`, `verify-captcha`, `sync-vault-metadata`) is implemented and verified under mocked Jest suites, **not yet deployed to live hosted Supabase**.
- **Deferred (`iOS Beta`)**: iOS CoreNFC PR `#25` remains deferred pending macOS build, entitlements, `.ipa` packaging fix, and physical iPhone testing.

---

## Documentation Index (Canonical Chapters)

| Section | Focus & Verification State |
| :--- | :--- |
| **[Getting Started](Getting-Started.md)** | Offline setup, core concepts, and client selection |
| **[Architecture](Architecture.md)** | Strict `contracts` -> core -> `operations` -> `ui` / native C++ topology |
| **[Android Installation](Android-Installation.md)** | Signed APK installation (`v2.1.0` emulator-verified; physical handset pending) |
| **[iOS Status](iOS-Status.md)** | `v2.1.0` Xcode foundation & deferred PR `#25` CoreNFC checklist (`iOS Beta`) |
| **[Web App](Web-App.md)** | GitHub Pages companion, WASM Argon2id, and Web NFC boundaries |
| **[Ghost Bridge](Ghost-Bridge.md)** | Authenticated `127.0.0.1:41789` PC/SC & ESP32/PN532 desktop bridge (hardware pending) |
| **[Creating an Account](Creating-an-Account.md)** | Local `>=16`-char passphrase and identity initialization |
| **[Recovery Phrase](Recovery-Phrase.md)** | Canonical 12-word BIP-39 phrase (`24`-word local unwrapping compat) |
| **[Recovery System](Recovery.md)** | Offline restoration vs. `v2.1.0` Turnstile + HMAC challenge-proof recovery |
| **[Supabase Backend](Supabase-Backend.md)** | Undeployed SQL migrations, RLS lockdown, and Edge Functions (`mock-tested`) |
| **[Encrypt Flow](Encrypt.md)** | Single-tag `v1` (`54B`) encryption and read-back verification |
| **[Decrypt Flow](Decrypt.md)** | Scanning tags in any order, constant-time GCM verification, and decryption |
| **[Batch Write](Batch-Write.md)** | Multi-tag `v2` (`134B`) distribution with Cauchy RS (`NTAG215`/`NTAG216` only) |
| **[Batch Read](Batch-Read.md)** | Order-independent scanning, 72h volatile RAM cache, and `K`-of-`K+M` reconstruction |
| **[NFC Compatibility](NFC-Compatibility.md)** | Exact framed limits (`NTAG213` v1-only, `NTAG215`/`216` v1+v2) |
| **[Technical Format](Technical-Format.md)** | Little-Endian `GTAG` headers, AAD offsets, and MIME types |
| **[Security Model](Security-Model.md)** | Argon2id tiers, AES-256-GCM, C++ `mlock`/`ptrace`, and limitations |
| **[Testing & CI](Testing-and-CI.md)** | Automated Jest/CodeQL/audit coverage vs. unexecuted hardware tests |
| **[Security Reporting](Security-Reporting.md)** | Private coordinated disclosure & zero-secrets rules (`72h` SLA) |
| **[Contributing](Contributing.md)** | PR workflow, branch protection, and verification gates |
| **[Roadmap](Roadmap.md)** | Physical hardware gate, live Supabase gate, `iOS Beta`, and `v2.2+` |
| **[Release History](Release-History.md)** | Published `v2.0.6` baseline vs. unreleased `v2.1.0` staging state |
| **[FAQ](FAQ.md)** | Pointer to root [`../../FAQ.md`](../../FAQ.md) (`70` cited Q&As) |

---

## Live Links
- **Web App**: [https://frosty-mug.github.io/Ghost-Tag/](https://frosty-mug.github.io/Ghost-Tag/)
- **Technical Specifications**: [https://frosty-mug.github.io/Ghost-Tag/technical.html](https://frosty-mug.github.io/Ghost-Tag/technical.html)
- **Releases & APK Downloads**: [https://github.com/FROSTY-MUG/Ghost-Tag/releases](https://github.com/FROSTY-MUG/Ghost-Tag/releases)
- **Repository**: [https://github.com/FROSTY-MUG/Ghost-Tag](https://github.com/FROSTY-MUG/Ghost-Tag)
