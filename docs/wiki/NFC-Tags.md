# NFC Tags

Ghost-Tag targets **ISO 14443-A NTAG21x** passive NFC tags formatted with **NDEF MIME** records (`application/x-ghosttag`).

## Supported Tag Families
- **NTAG213** (`144B` user memory, ~`137B` NDEF): Supported for **Ghost v1** single-tag payloads only (`54B` overhead).
- **NTAG215** (`504B` user memory, ~`490B` NDEF): Supported for **Ghost v1** and **Ghost v2** bulk chunks.
- **NTAG216** (`888B` user memory, ~`872B` NDEF): Supported for **Ghost v1** and **Ghost v2** bulk chunks.

> **Hardware Status**: Tag framing and NDEF serialization are verified via unit tests; physical NTAG213/215/216 tag reads/writes remain an open release gate ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)).

## Canonical Sources
- [NFC-Compatibility.md](NFC-Compatibility.md)
- [docs/nfc-tag-matrix.md](../nfc-tag-matrix.md)
- [docs/nfc-format.md](../nfc-format.md)
