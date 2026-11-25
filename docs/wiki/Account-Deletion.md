# Account Deletion

> **Deployment Status**: Staged in `supabase/functions/` and verified under mocked Jest suites; **not yet deployed to live hosted Supabase**.

Ghost-Tag supports scheduled cloud account deletion with a **48-hour grace period** before permanent purge.

## Staged Edge Functions
- `schedule-account-deletion`: Marks the authenticated account for deletion after 48 hours (`deletion_scheduled_at`).
- `cancel-account-deletion`: Cancels a pending deletion within the 48-hour window.
- `process-account-deletions`: Scheduled purge worker authenticated via `DELETION_WORKER_CRON_SECRET` ([supabase/functions/_shared/deletionHandlers.ts](../../supabase/functions/_shared/deletionHandlers.ts)).

## Offline Vaults
Local-only vaults (without Supabase sync) store nothing in the cloud; wiping local app storage or destroying physical NFC tags removes them immediately.

## Canonical Sources
- [supabase/functions/_shared/deletionHandlers.ts](../../supabase/functions/_shared/deletionHandlers.ts)
- [Supabase-Backend.md](Supabase-Backend.md)
