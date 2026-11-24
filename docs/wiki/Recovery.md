# Vault & Account Recovery (`v2.1.0`)

## 1. Local Offline Recovery
If you forget your Master Passphrase on your device:
1. Open **Passphrase & Recovery** and choose offline recovery.
2. Enter your **12-word BIP-39 recovery phrase** (or legacy 24-word offline vault phrase).
3. `RecoveryManager` validates the BIP-39 checksum, derives the recovery KEK (`DEFAULT_RECOVERY_KDF_CONFIG`: `64 MiB`, `t = 5`, `p = 4`), verifies the envelope HMAC, and unwraps your DEKs so you can establish a new Master Passphrase.

## 2. Opt-In Cloud Recovery (`v2.1.0` Challenge-Response)
When cloud backup is enabled and a Supabase deployment is configured:
1. Complete Cloudflare Turnstile verification (`verify-captcha`).
2. Request a challenge from `recover-vault` (`account_id`), enforcing atomic 15-minute sliding-window rate limits and anti-enumeration responses.
3. Derive `recovery_auth_secret` client-side using two-stage Argon2id (`m=32768, t=3, p=2`) with the returned CSPRNG `recovery_salt` (`32B`).
4. Submit the `76-byte` HMAC challenge proof to retrieve `encrypted_recovery_envelope` and decrypt wrapped DEKs strictly in local volatile RAM.

Physical NFC tags already written remain decryptable locally whenever the corresponding DEK or passphrase is available.
