# What Is Ghost-Tag

Ghost-Tag (`v2.1.0` unreleased staging; latest published release `v2.0.6`) is an **offline-first, zero-knowledge NFC encryption system** for storing encrypted text and file payloads on **NTAG213**, **NTAG215**, and **NTAG216** NFC tags.

## What You Can Store
- Short secrets, notes, and text credentials on a single NTAG213/215/216 tag (`v1` envelope, `54B` overhead).
- Larger binary files or multi-part payloads split across multiple NTAG215/NTAG216 tags with optional Cauchy Reed-Solomon parity (`v2` bulk envelope, `134B` overhead).

## What Ghost-Tag Does **Not** Do
- It never sends plaintext secrets, passphrases, recovery phrases, or decrypted payloads to any server.
- It does not simulate or fabricate NFC reads/writes in production runtime paths.
- It does not require an internet connection for encryption, decryption, or NFC tag operations.

## Canonical Sources
- [README.md](../../README.md)
- [docs/CANONICAL-SPECIFICATION.md](../CANONICAL-SPECIFICATION.md)
- [PROJECT-STATUS.md](../../PROJECT-STATUS.md)
