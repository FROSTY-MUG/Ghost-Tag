# Ghost-Tag Cloud Recovery & Metadata Backend (`supabase/`, v2.1.0 Schema)

## 1. Purpose
Opt-in, zero-knowledge Supabase PostgreSQL schema, hardened Row-Level Security (RLS) policies, and Deno Edge Functions powering cross-device recovery and encrypted vault metadata backup. **Ghost-Tag works 100% offline without Supabase.**

## 2. Database Migrations (`supabase/migrations/`)

| Migration File | Purpose |
| :--- | :--- |
| [`20261115_ghost_vaults.sql`](migrations/20261115_ghost_vaults.sql) | Initial `ghost_vaults` metadata & rate-limit schema |
| [`20261122_cross_platform_recovery.sql`](migrations/20261122_cross_platform_recovery.sql) | Cross-platform Argon2id (`recovery_kdf_version = 2`) recovery extensions |
| [`20261125_lockdown_ghost_vaults.sql`](migrations/20261125_lockdown_ghost_vaults.sql) | Revokes direct client access to `ghost_vaults` sensitive columns and introduces restricted `ghost_vault_status` view |
| [`20261126_v210_account_security_schema.sql`](migrations/20261126_v210_account_security_schema.sql) | v2.1.0 hardened tables (`user_accounts`, `vault_metadata`, `recovery_challenges`), server-generated 32B CSPRNG `recovery_salt`, column/RLS lockdown, and atomic rate limits |

## 3. Edge Functions (`supabase/functions/`)
- [`verify-captcha`](functions/verify-captcha/index.ts): Verifies Cloudflare Turnstile widgets (`_shared/turnstile.ts`) and issues short-lived HMAC-signed verification tokens.
- [`account-auth`](functions/account-auth/index.ts): Provisions server-generated 32-byte CSPRNG `recovery_salt` and stores two-stage Argon2id (`m=32768, t=3, p=2, v=0x13`) recovery verifiers & `encrypted_recovery_envelope` via service-role only.
- [`recover-vault`](functions/recover-vault/index.ts): Issues single-use recovery challenges and verifies `76B` HMAC challenge proofs with Turnstile gating, constant-time checks, anti-enumeration uniform errors, and atomic 15-minute sliding-window rate limits.
- [`sync-vault-metadata`](functions/sync-vault-metadata/index.ts): Syncs client-side AEAD `encrypted_metadata` (`_shared/syncMetadataHandler.ts`).
- [`schedule-account-deletion`](functions/schedule-account-deletion/index.ts), [`cancel-account-deletion`](functions/cancel-account-deletion/index.ts), [`process-account-deletions`](functions/process-account-deletions/index.ts): Service-role controlled deletion lifecycle (`_shared/deletionHandlers.ts`).
- [`migrate-recovery-verifier`](functions/migrate-recovery-verifier/index.ts): Legacy `v1` verifier migration handler retained for backward schema transition.

## 4. Runtime Secrets & Deployment Status
- **Automated Policy Tests**: Verified locally via Jest (`rlsUserAccounts`, `rlsGhostVaults`, `rateLimitAndSchema`, `antiEnumeration`, `recoveryChallengeProof`, `captchaAndAuthResponsibility`, `corsValidation`, `auditSanitizer`, `deletionPurgeWorker`, `supabaseSecurity`, `supabaseSync`).
- **Required Supabase Edge Function Secrets** ([`functions/_shared/supabaseEdgeRuntime.ts`](functions/_shared/supabaseEdgeRuntime.ts) & [`functions/migrate-recovery-verifier/index.ts`](functions/migrate-recovery-verifier/index.ts)):
  - `CLOUDFLARE_TURNSTILE_SECRET_KEY` (fail-closed Turnstile widget verification)
  - `AUDIT_HMAC_SALT` (HMAC audit salt; falls back to `IP_HASH_SALT` where applicable)
  - `IP_HASH_SALT` (required by legacy `migrate-recovery-verifier` and audit IP hashing)
  - `SERVER_ENUMERATION_SECRET` (deterministic anti-enumeration challenge salt synthesis)
  - `DELETION_WORKER_CRON_SECRET` (`X-Ghost-Cron-Secret` constant-time cron guard)
  - `SUPABASE_SERVICE_ROLE_KEY` (service-role database access inside Edge Functions only)
- **Required Non-Secret Env Config**: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `GHOST_ENV=production`, `ALLOW_LOCALHOST_CORS=false`, `APPROVED_CORS_ORIGINS=https://frosty-mug.github.io`.
- **Target Hosting & Free-Tier Policy**:
  - **Target Project / Region**: `Ghost-Tag Production` in `ap-south-1` (Mumbai, India; `ap-southeast-1` Singapore fallback).
  - **Email Verification**: Disabled on the Supabase Free Tier (built-in Auth email is capped at `2` emails/hour without custom SMTP); Ghost-Tag uses the anonymous/phrase-based account flow.
  - **Backups & PITR**: Automated daily backups (Pro) and Point-in-Time Recovery (paid add-on) are unavailable on the Free Tier; operators must run manual `supabase db dump` exports.
- **GitHub Actions Deployment**: [`.github/workflows/supabase-deploy.yml`](../.github/workflows/supabase-deploy.yml) (`workflow_dispatch` gated with `confirm_deploy=DEPLOY`) requires encrypted GitHub secrets `SUPABASE_ACCESS_TOKEN`, `SUPABASE_PROJECT_ID`, `SUPABASE_DB_PASSWORD`, and `DELETION_WORKER_CRON_SECRET`.
- **Live Cloud Deployment Status**: Migrations and Edge Functions are staged in Git; **live deployment to hosted Supabase (`supabase db push` / `supabase functions deploy`) remains pending** project creation, Turnstile site key, operator secrets, and explicit authorization.
- Never commit `.env` files, service-role keys, or secrets ([`../SECURITY.md`](../SECURITY.md), [`../FAQ.md`](../FAQ.md)).
