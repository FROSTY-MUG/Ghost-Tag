# Ghost-Tag Comprehensive Frequently Asked Questions (FAQ)

> This document provides technical, evidence-backed answers to 80 architectural, cryptographic, and operational questions regarding Ghost-Tag. Every answer cites source files, test suites, or documentation and explicitly distinguishes implemented features from proposed features, mock-tested layers from physical hardware, and local offline capabilities from cloud recovery.

---

## 1. Vault Concepts & Storage

### Q1: What is Ghost-Tag?
**Answer**: Ghost-Tag is designed for offline-first encrypted NFC vaults, with optional zero-knowledge cloud recovery. It turns ordinary NFC tags (NTAG213, NTAG215, NTAG216) into local-first encrypted vaults. It uses AES-256-GCM authenticated encryption, Argon2id key derivation, a KEK/DEK key hierarchy, BIP-39 recovery, and Cauchy-Reed-Solomon erasure coding to distribute encrypted data across multiple physical tags.  
**Citation**: `README.md:3-7`, `src/contracts/envelope.ts:1-19`.

### Q2: What can I store on a Ghost-Tag?
**Answer**: In Ghost v1, you can store short text strings, credentials, passwords, or recovery tokens up to the tag's physical memory limit minus 54 bytes overhead. In Ghost v2, you can store arbitrary binary files (images, PDFs, keys, archives) chunked and distributed across multiple tags.  
**Citation**: `src/crypto/fileEncryption.ts:8-15`, `docs/envelope-specification.md:20-35`.

### Q3: What NFC tags are supported?
**Answer**: Passive NXP NTAG213, NTAG215, and NTAG216 tags operating at 13.56 MHz (ISO/IEC 14443 Type A) with NDEF formatting are supported.  
**Citation**: `src/contracts/tags.ts:10-35`, `README.md:104-110`.

### Q4: Which NFC tags should I use for a single-tag vault?
**Answer**: NTAG213 (144 bytes usable, 90 bytes payload), NTAG215 (504 bytes usable, 450 bytes payload), or NTAG216 (888 bytes usable, 834 bytes payload). For passwords and short notes, NTAG213 or NTAG215 is recommended.  
**Citation**: `src/contracts/tags.ts:20-40`, `desktop/test/bridge.test.js:41-60`.

### Q5: Which NFC tags should I use for a multi-tag vault?
**Answer**: NTAG215 or NTAG216 tags are recommended for multi-tag vaults because their larger capacity accommodates the 134-byte v2 envelope overhead while leaving 370 bytes (NTAG215) or 754 bytes (NTAG216) per chunk for ciphertext.  
**Citation**: `src/contracts/bulkEnvelope.ts:45-50`, `README.md:104-110`.

### Q6: How many tags do I need?
**Answer**: For a single-tag vault (Ghost v1), exactly 1 tag. For a bulk multi-tag vault (Ghost v2), a minimum of $K$ data tags (where $K = \lceil \text{ciphertextSize} / \text{chunkPayloadSize} \rceil$), plus optional $M$ parity tags for redundancy ($K + M$ total).  
**Citation**: `src/crypto/erasureCoding.ts:250-275`.

### Q7: Can I use NTAG213 for a bulk vault?
**Answer**: Technically yes, but practically discouraged. NTAG213 provides only 144 bytes of usable memory; subtracting the 134-byte fixed v2 overhead leaves only 10 bytes of payload per tag, requiring dozens of tags for small files.  
**Citation**: `src/contracts/bulkEnvelope.ts:46`, `src/contracts/tags.ts:22`.

### Q8: What happens if I lose one NFC tag?
**Answer**: If the vault was created with systematic Reed-Solomon redundancy ($M \ge 1$), the missing tag's data is mathematically reconstructed from the remaining $K$ tags. If $M = 0$ (no parity), the loss of any single tag prevents full file reconstruction.  
**Citation**: `src/operations/reconstructionEngine.ts:140-185`, `src/crypto/erasureCoding.ts:320-370`.

### Q9: What happens if I lose multiple NFC tags?
**Answer**: You can lose up to $M$ tags without data loss. If you lose $M + 1$ or more tags, fewer than $K$ chunks remain, and Cauchy-Reed-Solomon matrix inversion is mathematically impossible; the file cannot be reconstructed.  
**Citation**: `src/crypto/erasureCoding.ts:330-345`, `src/__tests__/erasureCoding.test.ts`.

### Q10: What happens if a tag is damaged?
**Answer**: Physical damage preventing NFC RF communication renders the tag unreadable. It is treated as a missing chunk and recovered via parity if $M \ge 1$.  
**Citation**: `README.md:180-195`.

### Q11: What happens if a tag is wiped?
**Answer**: An empty or erased tag lacks the `GTAG` magic header and `application/vnd.ghost.bulk` MIME type. Ghost-Tag rejects it during scanning and does not ingest it into the reconstruction cache.  
**Citation**: `src/nfc/bulkNdefBuilder.ts:52-62`.

### Q12: What happens if a tag is cloned?
**Answer**: Passive NFC tags lack cryptographic challenge-response authentication; an attacker with physical access can clone the NDEF bytes onto another chip. However, the clone contains only AES-256-GCM encrypted ciphertext; without the passphrase or DEK, the attacker cannot read the plaintext.  
**Citation**: `README.md:200-215`, `SECURITY.md:45-55`.

### Q13: Can someone read my data by tapping the tag?
**Answer**: No. Tapping the tag yields only the binary envelope containing AES-256-GCM ciphertext, cryptographic salts, and authenticated headers. Decryption requires deriving the KEK via Argon2id using your secret passphrase.  
**Citation**: `src/crypto/aesGcm.ts:140-180`, `src/crypto/argon2.ts:30-65`.

### Q14: Do I need to scan NFC tags in the same order?
**Answer**: No. Ghost-Tag bulk vaults support fully out-of-order scanning. Each chunk envelope contains explicit 128-bit `FILE_ID` and 32-bit `FILE_CHUNK_INDEX` headers that allow the engine to assemble chunks regardless of tap sequence.  
**Citation**: `src/contracts/bulkEnvelope.ts:15-18`, `src/vault/chunkCache.ts:40-75`.

### Q15: Can I scan tags out of order?
**Answer**: Yes. Out-of-order scanning is an explicitly tested core feature. Chunks are indexed by `fileChunkIndex` and reordered during reassembly.  
**Citation**: `src/__tests__/bulkVaultVerification.test.ts:30-80`.

### Q16: Can I scan the same tag twice?
**Answer**: Yes. Duplicate scans are safely ignored. The local `ChunkCacheManager` and `BulkVaultManager` index chunks by `tagUidHex` and `fileChunkIndex`, ignoring duplicate taps in $O(1)$ time.  
**Citation**: `src/vault/chunkCache.ts:80-110`, `src/__tests__/bulkVaultVerification.test.ts:120-150`.

### Q17: What happens if I scan a duplicate tag?
**Answer**: The duplicate payload is recognized via cache index lookup and discarded without modifying the assembly journal or corrupting reconstruction state.  
**Citation**: `src/vault/bulkVaultManager.ts:140-160`.

### Q18: What happens if I scan a corrupted tag?
**Answer**: A corrupted tag fails either NDEF header parsing, the 74-byte AAD authentication check, or the 32-byte SHA-256 chunk hash check. It is rejected immediately before reaching decryption.  
**Citation**: `src/contracts/bulkEnvelope.ts:87-92`, `src/operations/reconstructionEngine.ts:170-195`.

### Q19: What happens if I scan a tag from another vault?
**Answer**: The envelope's 16-byte `VAULT_ID` does not match the active vault session. The chunk is filtered out and ignored during reconstruction.  
**Citation**: `src/operations/reconstructionEngine.ts:141-143`.

### Q20: How many parity tags should I create?
**Answer**: A standard recommendation is $M = 1$ or $M = 2$ (e.g., $K=4, M=2$ allows 2 lost tags out of 6). Increasing $M$ provides higher disaster tolerance at the cost of requiring more physical tags.  
**Citation**: `README.md:175-190`.

### Q21: How much data can I store on one tag?
**Answer**: In Ghost v1: 90 bytes on NTAG213, 450 bytes on NTAG215, 834 bytes on NTAG216. In Ghost v2: 10 bytes on NTAG213, 370 bytes on NTAG215, 754 bytes on NTAG216 per tag.  
**Citation**: `docs/nfc-tag-matrix.md:10-30`.

### Q22: How much data can I store across multiple tags?
**Answer**: Multi-tag vaults have no hard architectural limit; files of several megabytes can be split across dozens of tags, limited primarily by user scanning convenience and local cache storage.  
**Citation**: `src/contracts/bulkVault.ts:30-55`.

---

## 2. Accounts, Authentication & Recovery

### Q23: Do I need an account to encrypt or decrypt a tag?
**Answer**: No. Ghost-Tag's primary mode is completely account-free and offline. Tag encryption, formatting, scanning, and decryption operate entirely between your device and physical NFC tags.  
**Citation**: `README.md:20-30`, `src/operations/scanOperation.ts:35-80`.

### Q24: Do I need an account to use offline NFC features?
**Answer**: No. All core NFC scanning, writing, chunk reassembly, and erasure decoding features function without any network connectivity or account credentials.  
**Citation**: `README.md:20-30`.

### Q25: Do I need an account for Supabase recovery?
**Answer**: Yes. Cloud recovery synchronization requires registering an account identity derived from your BIP-39 recovery phrase.  
**Citation**: `supabase/README.md:10-25`, `web/supabase.js:40-80`.

### Q26: What do I need to create an account?
**Answer**: Ghost-Tag uses 12-word BIP-39 recovery phrases as the primary recovery format. 24-word recovery support is retained for compatibility where implemented in native core. Combined with a master passphrase, the client derives a blinded `account_id` and recovery verifier locally.  
**Citation**: `web/app.js:180-210`, `src/vault/recoveryManager.ts:40-70`.

### Q27: What happens if I forget my passphrase?
**Answer**: If you forget your passphrase, you cannot unlock local vaults directly. However, if you retained your BIP-39 recovery phrase, you can regenerate the recovery KEK, unwrap the DEK from the recovery container, and set a new passphrase.  
**Citation**: `src/vault/recoveryManager.ts:180-230`.

### Q28: What happens if I lose my recovery phrase?
**Answer**: As long as you remember your master passphrase, your local vaults and NFC tags remain accessible. However, you will be unable to restore access via emergency recovery if the passphrase is later forgotten.  
**Citation**: `src/vault/recoveryManager.ts:250-290`.

### Q29: What happens if I lose both my passphrase and recovery phrase?
**Answer**: Your data is permanently unrecoverable. Ghost-Tag is a zero-knowledge system with no administrative backdoors, master keys, or escrow services.  
**Citation**: `README.md:210-220`, `SECURITY.md:30-40`.

### Q30: Can I change my passphrase?
**Answer**: Yes. You can change your passphrase at any time through the key management interface.  
**Citation**: `src/contracts/keyHierarchy.ts:80-110`.

### Q31: Does changing my passphrase rewrite every NFC tag?
**Answer**: No. Because Ghost-Tag uses a two-tier KEK/DEK hierarchy, changing your passphrase only derives a new KEK and re-wraps the 32-byte DEK stored in the local manifest. The encrypted tags (which were encrypted using the DEK) do not need to be rewritten.  
**Citation**: `README.md:65-75`, `src/crypto/keyWrap.ts:40-70`.

### Q32: How does recovery work?
**Answer**: The user inputs their BIP-39 recovery phrase. The app derives an independent recovery KEK using Argon2id, unwraps the emergency-wrapped DEK record, and restores vault access.  
**Citation**: `src/vault/recoveryManager.ts:190-240`.

### Q33: Does recovery require an internet connection?
**Answer**: Local recovery using an offline recovery envelope does not require internet. Cloud recovery via Supabase requires internet to fetch the encrypted vault container.  
**Citation**: `supabase/README.md:15-30`.

### Q34: Does recovery require a Supabase account?
**Answer**: Only if you are recovering from cloud backup. Offline recovery using local manifests or physical tags does not require Supabase.  
**Citation**: `supabase/README.md:20-35`.

### Q35: Does recovery work on a brand-new device?
**Answer**: Yes. If you have your recovery phrase and access to either physical NFC tags or your Supabase encrypted backup, you can restore your vault on a fresh installation.  
**Citation**: `web/app.js:310-360`.

### Q36: Can I recover my vault without my recovery phrase?
**Answer**: Only if you know your master passphrase and have your physical NFC tags.  
**Citation**: `src/operations/reconstructionEngine.ts:60-100`.

### Q37: Can I recover my vault without my passphrase?
**Answer**: Yes, provided you have your BIP-39 recovery phrase and recovery envelope.  
**Citation**: `src/vault/recoveryManager.ts:190-220`.

---

## 3. Cloud Synchronization & Supabase

### Q38: What does Supabase store?
**Answer**: Supabase stores only: 1) a blinded `account_id` UUID, 2) a `recovery_salt`, 3) an Argon2id `recovery_verifier` (or legacy PBKDF2 verifier), and 4) encrypted vault metadata / wrapped DEKs.  
**Citation**: `supabase/migrations/20261115000000_recovery_schema.sql:10-50`.

### Q39: Does Supabase see my plaintext data?
**Answer**: No. Plaintext data is encrypted locally with AES-256-GCM before any network transmission.  
**Citation**: `supabase/README.md:15-20`.

### Q40: Does Supabase see my passphrase?
**Answer**: No. Passphrases are never transmitted. Keys are derived locally on the client.  
**Citation**: `README.md:280-295`.

### Q41: Does Supabase see my recovery phrase?
**Answer**: No. The client derives a cryptographic recovery verifier via Argon2id; the recovery phrase itself never leaves the client device.  
**Citation**: `supabase/functions/recover-vault/index.ts:30-60`.

### Q42: Does Supabase see my encryption keys?
**Answer**: No. The DEK is encrypted (wrapped) with AES-256-GCM under the KEK before storage.  
**Citation**: `src/crypto/keyWrap.ts:30-65`.

### Q43: Is Ghost-Tag anonymous?
**Answer**: No. Ghost-Tag provides confidentiality and offline privacy, but not network anonymity. IP addresses and connection timestamps are observable by network intermediaries and Supabase endpoints.  
**Citation**: `README.md:410-415`.

### Q44: Is Ghost-Tag offline-first?
**Answer**: Yes. Ghost-Tag is architected from the ground up to operate completely offline. Network connectivity is an optional convenience used solely for encrypted recovery synchronization.  
**Citation**: `README.md:10-25`.

### Q45: Does Ghost-Tag work without internet?
**Answer**: Yes. 100% of core encryption, NFC tag reading, writing, erasure decoding, and vault reconstruction works without internet.  
**Citation**: `README.md:15-25`.

### Q46: Which features require internet?
**Answer**: Only two optional features: 1) synchronizing encrypted recovery envelopes to Supabase Cloud, and 2) downloading web companion assets if not previously cached.  
**Citation**: `supabase/README.md:12-25`.

---

## 4. Platform Support & Hardware Validation

### Q47: Does Ghost-Tag support iOS?
**Answer**: iOS support is currently proposed through PR #25 (`ios/ghost-tag-support`). It implements read-only CoreNFC scanning, but remains unmerged and unverified on physical hardware.  
**Citation**: `ios/README.md:10-25`, PR #25.

### Q48: Can iOS write NFC tags?
**Answer**: No. iOS tag writing is completely unimplemented. Ghost-Tag on iOS is strictly read-only.  
**Citation**: `README.md:240-245`, `ios/README.md:16`.

### Q49: Does Ghost-Tag support MIFARE Classic?
**Answer**: No. MIFARE Classic tags use proprietary framing and insecure crypto (Crypto-1) that are incompatible with standard NFC Forum NDEF APIs. Ghost-Tag explicitly rejects MIFARE Classic tags.  
**Citation**: `desktop/test/bridge.test.js:71-75`, `src/contracts/tags.ts:50-60`.

### Q50: Can someone copy my NFC tag?
**Answer**: Yes. Commodity passive NFC chips (NTAG21x) do not prevent byte copying or UID cloning with physical reader hardware (e.g., Proxmark3).  
**Citation**: `SECURITY.md:45-55`.

### Q51: Is copying a tag dangerous?
**Answer**: A clone duplicates the encrypted ciphertext. Unless the attacker also possesses your passphrase or recovery phrase, the cloned tag cannot be decrypted. However, cloning a tag allows the attacker to preserve the ciphertext for offline cryptanalysis.  
**Citation**: `SECURITY.md:50-60`.

### Q52: What are the security limitations?
**Answer**: Key limitations include: 1) physical tag cloning cannot be prevented by passive chips; 2) compromised host operating systems can inspect memory or screen contents; 3) loss of both passphrase and recovery phrase causes permanent data loss; and 4) replay of older valid tags is possible if hardware counters are absent.  
**Citation**: `README.md:200-220`.

### Q53: What happens if someone tampers with a tag?
**Answer**: Any modification to tag ciphertext or AAD metadata causes AES-256-GCM authentication failure during decryption, rejecting the payload.  
**Citation**: `src/crypto/aesGcm.ts:165-175`.

### Q54: What happens if someone modifies ciphertext?
**Answer**: The 128-bit GCM authentication tag verification fails, throwing a `CHUNK_CORRUPT` error.  
**Citation**: `src/crypto/aesGcm.ts:170-175`.

### Q55: What happens if someone reorders chunks?
**Answer**: Chunk envelopes contain explicit Little-Endian coordinate headers (`GLOBAL_CHUNK_INDEX`, `FILE_CHUNK_INDEX`). The reconstruction engine reorders chunks into correct sequence during reassembly.  
**Citation**: `src/contracts/bulkEnvelope.ts:15-18`, `src/operations/reconstructionEngine.ts:160-185`.

### Q56: What happens if someone truncates a chunk?
**Answer**: The payload size does not match `CHUNK_CIPHERTEXT_LENGTH`, or the fixed overhead is less than 134 bytes. The envelope parser throws `INVALID_ENVELOPE`.  
**Citation**: `src/contracts/bulkEnvelope.ts:85-95`.

### Q57: What happens if someone replaces a chunk with another vault’s chunk?
**Answer**: The 16-byte `VAULT_ID` or `FILE_ID` AAD will not match the active session. If the attacker rewrites the header, the GCM tag authentication check fails.  
**Citation**: `src/contracts/bulkEnvelope.ts:48-52`, `src/operations/reconstructionEngine.ts:140-150`.

---

## 5. Reed-Solomon Erasure Coding

### Q58: What is Reed-Solomon erasure coding?
**Answer**: A mathematical algorithm that treats data as polynomial coefficients over Galois Field $\text{GF}(2^8)$ and generates redundant parity symbols, allowing the original data to be recovered from any subset of symbols meeting the threshold.  
**Citation**: `src/crypto/erasureCoding.ts:1-30`.

### Q59: How does Reed-Solomon recovery work?
**Answer**: When $K$ chunks out of $K+M$ are collected, the engine inverts the $K \times K$ Cauchy generator sub-matrix over $\text{GF}(2^8)$ to reconstruct missing data chunks bit-for-bit.  
**Citation**: `src/crypto/erasureCoding.ts:320-370`.

### Q60: What is the difference between a data chunk and a parity chunk?
**Answer**: A data chunk contains a direct slice of the original file ciphertext. A parity chunk contains linear combinations of all data chunks computed via the Cauchy generator matrix.  
**Citation**: `src/crypto/erasureCoding.ts:250-285`.

### Q61: How many parity chunks should I create?
**Answer**: Typically 1 or 2 parity chunks ($M=1$ or $M=2$). For high-risk physical environments, $M=K$ (100% redundancy) allows losing half of all tags.  
**Citation**: `README.md:175-185`.

### Q62: Can I add more parity tags later?
**Answer**: Yes, if you retain the original DEK and file payload, you can re-encode the file with a higher $M$ value and write additional parity tags.  
**Citation**: `src/vault/bulkVaultManager.ts:100-140`.

### Q63: Can I remove a tag from a vault?
**Answer**: You can physically discard a tag, but unless the vault is re-encrypted with a new DEK and re-distributed, the discarded tag still holds valid encrypted ciphertext.  
**Citation**: `SECURITY.md:65-75`.

---

## 6. Cryptography & Key Management

### Q64: Can I rotate encryption keys?
**Answer**: Yes. Key rotation generates a new DEK, re-encrypts the files, and rewrites the tags. Passphrase rotation re-wraps the existing DEK under a new KEK without rewriting tags.  
**Citation**: `src/contracts/keyHierarchy.ts:80-110`.

### Q65: Can I change my passphrase without rewriting tags?
**Answer**: Yes. Because the DEK encrypts the tags and the KEK only wraps the DEK, changing the passphrase updates only the KEK and wrapped DEK in the local manifest. Tags remain untouched.  
**Citation**: `README.md:65-75`.

### Q66: What is a KEK?
**Answer**: Key Encryption Key. A 256-bit symmetric key derived from your passphrase via Argon2id used solely to encrypt (wrap) the Data Encryption Key.  
**Citation**: `src/contracts/keyHierarchy.ts:20-35`.

### Q67: What is a DEK?
**Answer**: Data Encryption Key. A high-entropy 256-bit random key generated via CSPRNG used directly to encrypt file payloads and chunk data.  
**Citation**: `src/contracts/keyHierarchy.ts:15-30`.

### Q68: Why does Ghost-Tag use a KEK/DEK hierarchy?
**Answer**: To decouple passphrase updates from tag storage, avoiding the need to physically locate, tap, and rewrite dozens of NFC tags every time a passphrase is changed.  
**Citation**: `README.md:65-75`.

### Q69: What encryption does Ghost-Tag use?
**Answer**: AES-256-GCM (Galois/Counter Mode) with 256-bit keys, 96-bit random nonces, and 128-bit authentication tags conforming to NIST SP 800-38D.  
**Citation**: `src/crypto/aesGcm.ts:15-40`.

### Q70: What key derivation function does Ghost-Tag use?
**Answer**: Argon2id conforming to RFC 9106 ($m=32768\text{ KiB}, t=3, p=2, \text{version}=0x13$).  
**Citation**: `src/contracts/keyHierarchy.ts:25-35`.

### Q71: What happens if I enter the wrong passphrase?
**Answer**: Argon2id derives an incorrect KEK. Attempting to unwrap the DEK fails AES-GCM tag verification, throwing a `DEK_UNWRAP_FAILED` error. Plaintext is never produced.  
**Citation**: `src/crypto/keyWrap.ts:70-95`.

---

## 7. Threat Model & Physical Attacks

### Q72: Does Ghost-Tag protect against a compromised phone?
**Answer**: No. If the host smartphone is infected with root malware, a keylogger, or memory-dumping trojan, plaintext displayed on the screen or passphrases entered via the keyboard can be intercepted.  
**Citation**: `README.md:200-215`, `SECURITY.md:20-35`.

### Q73: Does Ghost-Tag protect against malware?
**Answer**: While Android builds use `FLAG_SECURE` to block screenshots and native C++ implements ptrace anti-debugging, compromised OS kernels or root exploits bypass application-level protections.  
**Citation**: `android/app/src/main/java/com/ghosttag/MainActivity.kt:15-25`.

### Q74: Does Ghost-Tag protect against physical tag cloning?
**Answer**: No. Commodity NFC chips cannot prevent bit-level reading. Security relies on authenticated encryption of the ciphertext, not chip copy protection.  
**Citation**: `SECURITY.md:45-55`.

### Q75: Does Ghost-Tag protect against forensic recovery?
**Answer**: Sensitive buffers in RAM are wiped using multi-pass zeroization routines where supported; however, physical RAM remanence or flash wear-leveling artifacts cannot be guaranteed eliminated at the silicon level.  
**Citation**: `src/crypto/secureMemory.ts:1-14`.

---

## 8. Release Status & Hardware Reality

### Q76: Is Ghost-Tag production-ready?
**Answer**: No. Ghost-Tag v2.1.0 is unreleased staging software. While automated unit and integration tests pass, physical Android device execution, iOS CoreNFC execution, and desktop reader validation remain pending.  
**Citation**: `README.md:15-20`, `PROJECT-STATUS.md:130-150`.

### Q77: Is Ghost-Tag v2.1.0 released?
**Answer**: No. Ghost-Tag v2.1.0 is an unreleased local staging milestone. No Git tag or official GitHub Release exists for v2.1.0.  
**Citation**: `README.md:15-20`.

### Q78: Which platforms are physically validated?
**Answer**: Currently, zero platforms have completed physical hardware sign-off in the active test environment.  
**Citation**: `PROJECT-STATUS.md:130-150`.

### Q79: Which platforms are not physically validated?
**Answer**: Physical Android devices, physical iPhones, physical ACS ACR122U USB readers, physical PN532 serial transceivers, and live Supabase Cloud instances are not physically validated.  
**Citation**: `README.md:225-245`.

### Q80: How can I report a security vulnerability?
**Answer**: Security vulnerabilities should be reported privately via GitHub Security Advisories at https://github.com/FROSTY-MUG/Ghost-Tag/security/advisories/new. Do not open public GitHub issues for security vulnerabilities.  
**Citation**: `SECURITY.md:1-25`, `README.md:380-395`.
