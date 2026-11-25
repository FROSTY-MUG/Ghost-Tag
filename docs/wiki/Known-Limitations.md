# Known Limitations

This page documents verified technical, hardware, recovery, and cloud limitations in Ghost-Tag `v2.1.0` staging.

## Hardware & Platform Limitations
- **NTAG213 Bulk Restriction**: NTAG213 (`144B` user memory) cannot store `v2` bulk chunks (`134B` overhead) and is strictly **v1-only**.
- **Physical NFC Pending**: Android emulator, mocked PC/SC, and mocked PN532 serial tests pass, but physical NTAG213/215/216, ACR122U, ESP32/PN532, and Chrome Web NFC hardware tests are pending ([Issue #36](https://github.com/FROSTY-MUG/Ghost-Tag/issues/36)).
- **iOS Deferred**: iOS CoreNFC support (`PR #25`) is deferred to `iOS Beta` ([Issue #38](https://github.com/FROSTY-MUG/Ghost-Tag/issues/38)); iOS CoreNFC cannot write Ghost-Tag NDEF payloads in the current scope.

## Cloud & Supabase Free-Tier Limitations
- **Supabase Undeployed**: Cloud recovery is not live until provisioned and deployed ([Issue #37](https://github.com/FROSTY-MUG/Ghost-Tag/issues/37)).
- **No Automated Backups / PITR on Free Tier**: Supabase Free Plan does not include automated daily backups or Point-in-Time Recovery (Pro/paid add-on required); manual `supabase db dump` is required on Free Tier.
- **Email Verification Disabled on Free Tier**: Supabase built-in Auth email is capped at `2` emails/hour without a custom SMTP provider; Ghost-Tag uses the anonymous/phrase-based account flow on Free Tier.
- **Inactivity Pausing**: Supabase Free Tier projects pause after `7` days of inactivity.

## Recovery & Security Limitations
- **Irrecoverable Passphrase + Phrase Loss**: Without both the passphrase/recovery phrase (and cloud metadata if synced), encrypted tags cannot be decrypted.
- **Compromised Endpoint**: Local encryption cannot protect plaintext on an OS actively compromised by a keylogger or memory scraper.

## Canonical Sources
- [PROJECT-STATUS.md](../../PROJECT-STATUS.md)
- [FAQ.md](../../FAQ.md)
- [Supabase-Backend.md](Supabase-Backend.md)
