# Single-Tag Vaults

Single-Tag Vaults use the **Ghost v1** envelope (`54` bytes fixed overhead, `26` bytes AAD) to store one encrypted payload on a single NTAG213, NTAG215, or NTAG216 tag.

## When to Use Single-Tag Mode
- Storing short text secrets, API keys, or compact notes that fit within a single tag's framed NDEF capacity.
- Using **NTAG213** tags (which cannot fit the `134B` Ghost v2 bulk header).

## Verification
- Read-back hash verification after write ensures tag integrity before completion ([src/nfc/ndefBuilder.ts](../../src/nfc/ndefBuilder.ts)).
- Covered by Jest suites ([src/__tests__/nfc.test.ts](../../src/__tests__/nfc.test.ts)) and PN532 serial protocol tests ([desktop/test/pn532_serial.test.js](../../desktop/test/pn532_serial.test.js)).

## Canonical Sources
- [Encrypt.md](Encrypt.md)
- [Decrypt.md](Decrypt.md)
- [docs/envelope-specification.md](../envelope-specification.md)
