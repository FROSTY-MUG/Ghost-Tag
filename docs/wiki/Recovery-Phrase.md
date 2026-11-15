# Recovery Phrase Specification

The 12-word recovery phrase is the cryptographic cornerstone of your Ghost-Tag identity.

---

## 1. Cryptographic Structure

Ghost-Tag adheres strictly to the **BIP-39** standard:
- **Entropy Length**: 128 bits of cryptographically secure pseudorandom data.
- **Checksum**: SHA-256 hash of the entropy, taking the first 4 bits (`128 / 32 = 4`).
- **Total Bits**: 132 bits (`128 + 4`).
- **Word Encoding**: 132 bits split into 12 chunks of 11 bits each (`132 / 11 = 12`).
- **Dictionary**: The standard 2,048-word English BIP-39 wordlist.

---

## 2. Deterministic Account ID Derivation

Ghost-Tag does not upload the recovery phrase or use it directly as an identifier. Instead, a domain-separated KDF derives an RFC 4122 v4 UUID:

```text
normalized_phrase = join(lowercase(words), " ")
context_salt = "ghost-account-id-v2.0.5:" + normalized_phrase
hash = SHA-256(context_salt)

// Format first 16 bytes as UUIDv4:
bytes[6] = (bytes[6] & 0x0F) | 0x40  // Set version 4
bytes[8] = (bytes[8] & 0x3F) | 0x80  // Set variant 1
account_id = hex_format_uuid(bytes[0..16])
```

This guarantees:
1. One recovery phrase always produces the exact same `account_id` on any device or platform.
2. Even if someone intercepts your `account_id`, they cannot reverse the SHA-256 pre-image to discover your 12 recovery words.

---

## 3. Account Restoration Process

To restore your Ghost account on a new phone or clean browser:
1. Tap **I Already Have a Recovery Phrase** on the welcome screen.
2. Enter your 12 words separated by single spaces.
3. Ghost-Tag verifies the BIP-39 checksum (detects any misspelled or transposed words).
4. Ghost-Tag re-derives your `account_id` and restores your encrypted vault settings.
5. You can immediately scan and decrypt tags created on your previous device.
