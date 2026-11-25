# Supabase Cloud Recovery & Metadata Backend

> **Status Honesty**: Cloud sync and cross-device recovery are **optional** and **require internet connectivity** plus an operator-provisioned Supabase project. **Live deployment to hosted Supabase has not yet been executed** ([Issue #37](https://github.com/FROSTY-MUG/Ghost-Tag/issues/37)); schema and handlers are verified via mocked Jest security suites only. Without Supabase, all Ghost-Tag encryption, decryption, and NFC workflows run **100% offline**.

## Target Hosting & Free-Tier Policy
- **Target Project Name**: `Ghost-Tag Production`
- **Target Region**: `ap-south-1` (South Asia — Mumbai, India; `ap-southeast-1` Singapore fallback)
- **Email Verification**: **Disabled on Free Tier** — Supabase's built-in email provider is limited to `2` emails/hour without a custom SMTP provider. Ghost-Tag uses the **anonymous / phrase-based account flow** on the Free Tier.
- **Database Backups & PITR**: **Unavailable automatically on Free Tier** — Automated daily backups require Supabase Pro (`$25/month`), and Point-in-Time Recovery (PITR) is a paid add-on (`~$100+/month`). On the Free Tier, operators must run manual `supabase db dump` exports.
- **Turnstile Policy**: Enabled in **Managed** mode on `verify-captcha` and `recover-vault` only (never applied to offline NFC operations).

## Staged Database & Edge Functions (`supabase/`)
- **4 PostgreSQL Migrations (`supabase/migrations/`)**:
  - `20261115_ghost_vaults.sql` & `20261122_cross_platform_recovery.sql` (baseline + `recovery_kdf_version = 2`)
  - `20261125_lockdown_ghost_vaults.sql` (revokes direct client read/write of `ghost_vaults` sensitive columns; exposes restricted `ghost_vault_status` view)
  - `20261126_v210_account_security_schema.sql` (`user_accounts`, `vault_metadata`, `recovery_challenges`, 32-byte server-random `recovery_salt`, column-level RLS lockdown, advisory-locked 15m rate limits)
- **8 Edge Functions (`supabase/functions/`)**:
  - `verify-captcha` (fail-closed Cloudflare Turnstile + replay table)
  - `account-auth` (issues server `recovery_salt` & stores verifier/envelope via service role)
  - `recover-vault` (single-use challenge + `76B` HMAC proof + constant-time anti-enumeration)
  - `sync-vault-metadata`, `schedule-account-deletion`, `cancel-account-deletion`, `process-account-deletions`, `migrate-recovery-verifier`

## Required Operator Secrets (Never Commit to Git)
Configured solely via Supabase Edge Function secrets (`supabase secrets set`) or Supabase Dashboard (see [supabase/README.md](../../supabase/README.md)):
- `CLOUDFLARE_TURNSTILE_SECRET_KEY`
- `AUDIT_HMAC_SALT`
- `IP_HASH_SALT`
- `SERVER_ENUMERATION_SECRET`
- `DELETION_WORKER_CRON_SECRET`
- `SUPABASE_SERVICE_ROLE_KEY`

Non-secret configuration: `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `GHOST_ENV=production`, `ALLOW_LOCALHOST_CORS=false`, `APPROVED_CORS_ORIGINS=https://frosty-mug.github.io`.

GitHub Actions deployment ([.github/workflows/supabase-deploy.yml](../../.github/workflows/supabase-deploy.yml)) uses encrypted repository/environment secrets: `SUPABASE_ACCESS_TOKEN`, `SUPABASE_PROJECT_ID`, `SUPABASE_DB_PASSWORD`, `DELETION_WORKER_CRON_SECRET`.
