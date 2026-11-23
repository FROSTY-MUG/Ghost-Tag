# Ghost-Tag Recovery Architecture & BIP-39 Standard

> [!NOTE]
> **CANONICAL SPECIFICATION ALIGNMENT**  
> For the complete, authoritative specification of identity, salt, and recovery verifier derivations across Android, Web, and iOS, refer to [CANONICAL-SPECIFICATION.md](file:///c:/Users/Aryan/Desktop/Projects/Ghost-Tag/docs/CANONICAL-SPECIFICATION.md).
> 
> **Canonical Standard**: **12-Word BIP-39 English Mnemonic** (128-bit entropy + 4-bit checksum). 24-word phrases are an internal legacy option supported in the local `RecoveryManager` engine for offline vault unwrapping, but cross-platform recovery, Web client, iOS foundation, and Supabase cloud metadata recovery strictly require 12 words.

This document details the cross-platform 12-word recovery phrase mechanism used to restore access to a Ghost-Tag vault on a new device or across Android and Web clients.

---

## 1. Cryptographic Entropy & Checksum Specification

Ghost-Tag adheres strictly to the BIP-39 mnemonic standard for 12-word recovery phrases:

1. **Initial Entropy**: 128 bits (16 bytes) generated via CSPRNG (`crypto.getRandomValues()` or Android `SecureRandom`).
2. **Checksum**: The initial 128-bit entropy is hashed using SHA-256. The first 4 bits of the hash form the checksum:
   $$\text{Checksum Length} = \frac{\text{Entropy Length}}{32} = \frac{128}{32} = 4\text{ bits}$$
3. **Total Bitstream**: $128 + 4 = 132\text{ bits}$.
4. **Mnemonic Mapping**: The 132-bit stream is divided into 12 groups of 11 bits each:
   $$\frac{132\text{ bits}}{11\text{ bits/word}} = 12\text{ words}$$
   Each 11-bit integer ($0 \le i < 2048$) indexes into the standard English BIP-39 wordlist.

---

## 2. Vault Initialization & Confirmation Workflow

To prevent user lockout caused by unrecorded recovery phrases:
1. **Passphrase Creation**: User sets a master passphrase (minimum 16 characters recommended).
2. **Phrase Presentation**: Ghost-Tag generates and displays the 12 words in a clear 4x3 grid.
3. **Interactive Confirmation**: Before the vault is initialized on disk, the application demands confirmation of 3 randomly chosen word indices (e.g., Word 4, Word 8, Word 11).
4. **Key Derivation & Wrap**: Upon successful verification, the Data Encryption Key (DEK) is generated, wrapped under the Key Encryption Key (KEK), and persisted locally.

---

## 3. Cross-Platform Recovery Flow

A user with a 12-word recovery phrase can restore access on any supported platform:

```
+-----------------------------------------------------------------------------------+
| 1. User launches Ghost-Tag on new device (Android APK or Web Client)             |
| 2. Selects "I Have a Recovery Phrase"                                            |
| 3. Enters the 12 English BIP-39 words                                             |
| 4. Client validates 11-bit word indices and 4-bit SHA-256 checksum                |
| 5. User establishes local passphrase for new device                              |
| 6. Master vault keys are deterministically reconstructed                        |
| 7. Scanned Ghost-Tag NFC chips decrypt seamlessly                                 |
+-----------------------------------------------------------------------------------+
```
