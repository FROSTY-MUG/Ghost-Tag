/**
 * @file deletionPurgeWorker.test.ts
 * @summary Verifies 48-hour Grace Period Scheduling, Cancellation, Cron Authentication,
 * SKIP LOCKED Claim Semantics, Idempotent Auth 404, and Exponential Backoff Retries.
 */

import {
  ClaimedDeletionJob,
  MAX_PURGE_ATTEMPTS,
  handleCancelDeletion,
  handleProcessDeletions,
} from '../../supabase/functions/_shared/deletionHandlers';

declare const require: any;
declare const __dirname: string;
const fs = require('fs');
const path = require('path');

function makeReq(
  url: string,
  method: string,
  bodyObj?: unknown,
  headersMap: Record<string, string> = {}
): Request {
  const lowered = new Map<string, string>();
  for (const [k, v] of Object.entries(headersMap)) {
    lowered.set(k.toLowerCase(), v);
  }
  return {
    url,
    method,
    headers: {
      get: (k: string) => lowered.get(k.toLowerCase()) ?? null,
    },
    json: async () => bodyObj,
  } as unknown as Request;
}

describe('PR #3: 48-Hour Grace Period Deletion & Purge Worker', () => {
  const ROOT = path.resolve(__dirname, '../..');
  const CORS_OPTS = { environment: 'production', allowLocalhostCors: false };
  const ORIGIN = 'https://frosty-mug.github.io';
  const AUDIT_SALT = 'server-audit-hmac-salt-32-chars!!';
  const CRON_SECRET = 'cron-worker-high-entropy-secret-32chars!!';

  test('1. SQL schema enforces strict 48-hour grace period and FOR UPDATE SKIP LOCKED reclaim rules', () => {
    const sql: string = fs.readFileSync(
      path.join(ROOT, 'supabase/migrations/20261126_v210_account_security_schema.sql'),
      'utf8'
    );
    expect(sql).toMatch(/INTERVAL '48 hours'/i);
    expect(sql).toMatch(/r\.expires_at <= v_now/i);
    expect(sql).toMatch(/FOR UPDATE OF r SKIP LOCKED/i);
    expect(sql).toMatch(/r\.purge_attempts < 10/i);
  });

  test('2. Cancelling within grace period restores active status; cancelling mid-purge returns 409', async () => {
    const user = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };
    let cancellable = true;

    const okCancel = await handleCancelDeletion(
      makeReq(
        'https://proj.supabase.co/functions/v1/cancel-account-deletion',
        'POST',
        {},
        { Origin: ORIGIN, Authorization: 'Bearer jwt' }
      ),
      {
        corsOptions: CORS_OPTS,
        auditHmacSalt: AUDIT_SALT,
        authenticateUser: async () => user,
        cancelDeletionRpc: async () => cancellable,
        recordAudit: async () => {},
      }
    );
    expect(okCancel.status).toBe(200);
    expect(await okCancel.json()).toEqual({ cancelled: true, account_status: 'active' });

    cancellable = false;
    const lateCancel = await handleCancelDeletion(
      makeReq(
        'https://proj.supabase.co/functions/v1/cancel-account-deletion',
        'POST',
        {},
        { Origin: ORIGIN, Authorization: 'Bearer jwt' }
      ),
      {
        corsOptions: CORS_OPTS,
        auditHmacSalt: AUDIT_SALT,
        authenticateUser: async () => user,
        cancelDeletionRpc: async () => cancellable,
        recordAudit: async () => {},
      }
    );
    expect(lateCancel.status).toBe(409);
  });

  test('3. process-account-deletions rejects client JWTs or missing/wrong cron secrets with 403', async () => {
    const claimMock = jest.fn(async () => []);
    const baseDeps = {
      corsOptions: CORS_OPTS,
      cronSecret: CRON_SECRET,
      claimExpiredRequests: claimMock,
      deleteRecoveryChallenges: async () => {},
      deleteVaultMetadata: async () => {},
      deleteProvisioningSalts: async () => {},
      deleteAuthUser: async () => ({ ok: true }),
      markCompleted: async () => {},
      scheduleRetry: async () => {},
      recordAudit: async () => {},
    };

    const rNoSecret = await handleProcessDeletions(
      makeReq(
        'https://proj.supabase.co/functions/v1/process-account-deletions',
        'POST',
        {},
        { Authorization: 'Bearer regular-user-jwt' }
      ),
      baseDeps
    );
    expect(rNoSecret.status).toBe(403);
    expect(claimMock).not.toHaveBeenCalled();

    const rBadSecret = await handleProcessDeletions(
      makeReq(
        'https://proj.supabase.co/functions/v1/process-account-deletions',
        'POST',
        {},
        { 'X-Ghost-Cron-Secret': 'wrong-secret-value' }
      ),
      baseDeps
    );
    expect(rBadSecret.status).toBe(403);
    expect(claimMock).not.toHaveBeenCalled();
  });

  test('4. Worker executes strict destruction sequence and treats missing auth users (404) idempotently', async () => {
    const events: string[] = [];
    const job: ClaimedDeletionJob = {
      requestId: 'req-1',
      userId: 'user-1',
      scheduledAt: '2026-11-23T00:00:00.000Z',
      expiresAt: '2026-11-25T00:00:00.000Z',
      purgeAttempts: 0,
    };

    const resp = await handleProcessDeletions(
      makeReq(
        'https://proj.supabase.co/functions/v1/process-account-deletions',
        'POST',
        {},
        { 'X-Ghost-Cron-Secret': CRON_SECRET }
      ),
      {
        corsOptions: CORS_OPTS,
        cronSecret: CRON_SECRET,
        claimExpiredRequests: async () => [job],
        deleteRecoveryChallenges: async () => {
          events.push('deleteRecoveryChallenges');
        },
        deleteVaultMetadata: async () => {
          events.push('deleteVaultMetadata');
        },
        deleteProvisioningSalts: async () => {
          events.push('deleteProvisioningSalts');
        },
        deleteAuthUser: async () => {
          events.push('deleteAuthUser(404)');
          return { ok: true, notFound: true };
        },
        markCompleted: async () => {
          events.push('markCompleted');
        },
        scheduleRetry: async () => {
          events.push('scheduleRetry');
        },
        recordAudit: async (e) => {
          events.push(`audit:${e.event_type}`);
        },
      }
    );

    expect(resp.status).toBe(200);
    expect(await resp.json()).toEqual({
      processed: 1,
      purged: 1,
      retried: 0,
      failed_manual_review: 0,
    });
    expect(events).toEqual([
      'deleteRecoveryChallenges',
      'deleteVaultMetadata',
      'deleteProvisioningSalts',
      'deleteAuthUser(404)',
      'markCompleted',
      'audit:account_deletion_purged',
    ]);
  });

  test('5. Worker schedules exponential backoff retry on transient failure and escalates to manual review after max attempts', async () => {
    const scheduledRetries: any[] = [];
    const audits: any[] = [];

    // Transient failure at attempt 0 -> backoff retry
    const respRetry = await handleProcessDeletions(
      makeReq(
        'https://proj.supabase.co/functions/v1/process-account-deletions',
        'POST',
        {},
        { 'X-Ghost-Cron-Secret': CRON_SECRET }
      ),
      {
        corsOptions: CORS_OPTS,
        cronSecret: CRON_SECRET,
        nowMs: () => 1_750_000_000_000,
        claimExpiredRequests: async () => [
          {
            requestId: 'req-retry',
            userId: 'user-retry',
            scheduledAt: '2026-11-23T00:00:00.000Z',
            expiresAt: '2026-11-25T00:00:00.000Z',
            purgeAttempts: 0,
          },
        ],
        deleteRecoveryChallenges: async () => {},
        deleteVaultMetadata: async () => {},
        deleteProvisioningSalts: async () => {},
        deleteAuthUser: async () => ({ ok: false, errorCode: 'AUTH_500' }),
        markCompleted: async () => {},
        scheduleRetry: async (input) => {
          scheduledRetries.push(input);
        },
        recordAudit: async (e) => {
          audits.push(e);
        },
      }
    );

    expect(respRetry.status).toBe(200);
    expect(await respRetry.json()).toEqual({
      processed: 1,
      purged: 0,
      retried: 1,
      failed_manual_review: 0,
    });
    expect(scheduledRetries[0].nextAttempts).toBe(1);
    expect(scheduledRetries[0].terminalManualReview).toBe(false);
    expect(audits[0].event_type).toBe('account_deletion_retry_scheduled');

    // Final attempt reaching MAX_PURGE_ATTEMPTS -> failed_manual_review
    const respTerminal = await handleProcessDeletions(
      makeReq(
        'https://proj.supabase.co/functions/v1/process-account-deletions',
        'POST',
        {},
        { 'X-Ghost-Cron-Secret': CRON_SECRET }
      ),
      {
        corsOptions: CORS_OPTS,
        cronSecret: CRON_SECRET,
        claimExpiredRequests: async () => [
          {
            requestId: 'req-term',
            userId: 'user-term',
            scheduledAt: '2026-11-23T00:00:00.000Z',
            expiresAt: '2026-11-25T00:00:00.000Z',
            purgeAttempts: MAX_PURGE_ATTEMPTS - 1,
          },
        ],
        deleteRecoveryChallenges: async () => {},
        deleteVaultMetadata: async () => {},
        deleteProvisioningSalts: async () => {},
        deleteAuthUser: async () => ({ ok: false, errorCode: 'AUTH_500' }),
        markCompleted: async () => {},
        scheduleRetry: async (input) => {
          scheduledRetries.push(input);
        },
        recordAudit: async (e) => {
          audits.push(e);
        },
      }
    );

    expect(respTerminal.status).toBe(200);
    expect(await respTerminal.json()).toEqual({
      processed: 1,
      purged: 0,
      retried: 0,
      failed_manual_review: 1,
    });
    expect(scheduledRetries[1].nextAttempts).toBe(10);
    expect(scheduledRetries[1].terminalManualReview).toBe(true);
    expect(audits[1].event_type).toBe('account_deletion_failed_manual_review');
  });
});
