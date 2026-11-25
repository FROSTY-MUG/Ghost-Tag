# Glossary

- **AAD (Additional Authenticated Data)**: Unencrypted header bytes authenticated by AES-256-GCM (`26B` in `v1`, `74B` in `v2`) so header tampering fails decryption.
- **AES-256-GCM**: Authenticated symmetric cipher used to encrypt all Ghost-Tag payloads.
- **Argon2id**: Memory-hard key derivation function (`t=4, m=65536, p=2` canonical tier) deriving keys from passphrases.
- **Cauchy Reed-Solomon**: Erasure coding over `GF(2^8)` enabling `K`-of-`K+M` multi-tag reconstruction.
- **Ghost Bridge**: Local WebSocket server (`127.0.0.1:41789`) connecting the Web Companion to desktop PC/SC and PN532 NFC hardware (`desktop/`).
- **Ghost v1 / v2**: Binary envelope formats (`54B` overhead single-tag `v1`; `134B` overhead bulk multi-tag `v2`).
- **NDEF MIME**: NFC Data Exchange Format record (`application/x-ghosttag`) stored on NTAG21x tags.
- **NTAG213 / 215 / 216**: NXP passive NFC Forum Type 2 tags (`144B` / `504B` / `888B` user memory).
- **PITR**: Point-in-Time Recovery (paid Supabase Pro add-on; unavailable on Free Tier).
- **RLS**: PostgreSQL Row-Level Security enforcing database access boundaries in `supabase/migrations/`.
- **Turnstile**: Cloudflare CAPTCHA widget (`verify-captcha`, `recover-vault`) protecting cloud endpoints against abuse.
