# Passphrase

Ghost-Tag enforces a minimum **16-character passphrase** for local account initialization and vault encryption.

## Design Rules
- **Minimum Length**: `16` characters enforced in local validation and UI flows ([src/vault/accountManager.ts](../../src/vault/accountManager.ts)).
- **No Server Transmission**: Passphrases are processed locally via Argon2id (`t=4, m=65536, p=2`) and never sent over the network.
- **No Silent Fallback**: Wrong passphrases fail AES-256-GCM authentication with zero plaintext exposure (verified in [src/__tests__/crypto.test.ts](../../src/__tests__/crypto.test.ts) and [desktop/test/pn532_serial.test.js](../../desktop/test/pn532_serial.test.js)).

## Canonical Sources
- [Creating-an-Account.md](Creating-an-Account.md)
- [docs/cryptography.md](../cryptography.md)
