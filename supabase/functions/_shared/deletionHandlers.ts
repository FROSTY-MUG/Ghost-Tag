/**
 * Ghost-Tag v2.1.0 - Account Deletion Grace-Period & Purge Worker Handlers
 *
 * Implements:
 * - schedule-account-deletion: JWT + Cloudflare Turnstile CAPTCHA + rate limit -> 48h grace period
 * - cancel-account-deletion: JWT -> cancels active pending deletion before purge starts
 * - process-account-deletions: cron secret verified in constant time (rejects client JWTs),
 *   claims strictly expired (>= 48h) requests using FOR UPDATE SKIP LOCKED semantics,
 *   deletes recovery_challenges -> vault_metadata -> auth user (idempotent 404),
 *   and transitions deletion rows with exponential backoff retries up to 10 attempts.
 */

import { hashAuditIdentifier, sanitizeAuditEvent } from './audit.ts';
import { CorsPolicyOptions, evaluateCorsRequest } from './cors.ts';
import { constantTimeEqualSecrets } from './recoveryCrypto.ts';
import { TurnstileReplayStore, verifyTurnstileToken } from './turnstile.ts';

export const DELETION_GRACE_HOURS = 48;
export const MAX_PURGE_ATTEMPTS = 10;

export interface ScheduleDeletionDeps {
  corsOptions: CorsPolicyOptions;
  turnstileSecretKey: string | undefined;
  auditHmacSalt: string | undefined;
  replayStore: TurnstileReplayStore;
  fetchFn?: typeof fetch;
  authenticateUser(authHeader: string | null): Promise<{ id: string } | null>;
  checkRateLimit(
    bucketKey: string,
    action: 'account_deletion'
  ): Promise<{ allowed: boolean; retryAfterSeconds: number }>;
  scheduleDeletionRpc(userId: string): Promise<{
    requestId: string;
    scheduledAt: string;
    expiresAt: string;
    status: string;
  }>;
  recordAudit(event: ReturnType<typeof sanitizeAuditEvent>): Promise<void>;
}

export async function handleScheduleDeletion(
  req: Request,
  deps: ScheduleDeletionDeps,
  clientIp = '0.0.0.0'
): Promise<Response> {
  const origin = req.headers.get('Origin');
  const cors = evaluateCorsRequest(origin, deps.corsOptions);
  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: 'DELETION_SCHEDULE_FAILED' }), {
      status: 403,
      headers: { ...cors.headers, 'Content-Type': 'application/json' },
    });
  }
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: cors.headers });
  }
  const headers = { ...cors.headers, 'Content-Type': 'application/json' };
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }), {
      status: 405,
      headers,
    });
  }

  if (!deps.auditHmacSalt || deps.auditHmacSalt.length < 16) {
    return new Response(JSON.stringify({ error: 'DELETION_SCHEDULE_FAILED' }), {
      status: 500,
      headers,
    });
  }
  const ipHash = await hashAuditIdentifier(clientIp, deps.auditHmacSalt);

  const user = await deps.authenticateUser(req.headers.get('Authorization'));
  if (!user) {
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers,
    });
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    body = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    body = {};
  }

  const rlBucket = await hashAuditIdentifier(`del:${user.id}`, deps.auditHmacSalt);
  const rl = await deps.checkRateLimit(rlBucket, 'account_deletion');
  if (!rl.allowed) {
    return new Response(
      JSON.stringify({ error: 'RATE_LIMITED', retry_after_seconds: rl.retryAfterSeconds }),
      { status: 429, headers }
    );
  }

  const captcha = await verifyTurnstileToken({
    token: body.turnstile_token,
    secretKey: deps.turnstileSecretKey,
    expectedAction: 'account_deletion',
    remoteIp: clientIp,
    replayStore: deps.replayStore,
    fetchFn: deps.fetchFn,
  });

  if (!captcha.valid) {
    try {
      await deps.recordAudit(
        sanitizeAuditEvent({
          userId: user.id,
          eventType: 'captcha_verification_failed',
          ipHash,
          status: 'blocked',
          details: {
            error_code: 'TURNSTILE_REJECTED',
            reason: captcha.reason,
            action: 'account_deletion',
            http_status: 403,
          },
        })
      );
    } catch {
      // ignore audit failure
    }
    return new Response(JSON.stringify({ error: 'CAPTCHA_VERIFICATION_FAILED' }), {
      status: 403,
      headers,
    });
  }

  const scheduled = await deps.scheduleDeletionRpc(user.id);
  try {
    await deps.recordAudit(
      sanitizeAuditEvent({
        userId: user.id,
        eventType: 'account_deletion_scheduled',
        ipHash,
        status: 'success',
        details: { grace_hours: DELETION_GRACE_HOURS, http_status: 200 },
      })
    );
  } catch {
    // ignore
  }

  return new Response(
    JSON.stringify({
      scheduled: true,
      request_id: scheduled.requestId,
      account_status: 'deletion_pending',
      scheduled_at: scheduled.scheduledAt,
      expires_at: scheduled.expiresAt,
      grace_hours: DELETION_GRACE_HOURS,
    }),
    { status: 200, headers }
  );
}

export interface CancelDeletionDeps {
  corsOptions: CorsPolicyOptions;
  auditHmacSalt: string | undefined;
  authenticateUser(authHeader: string | null): Promise<{ id: string } | null>;
  cancelDeletionRpc(userId: string): Promise<boolean>;
  recordAudit(event: ReturnType<typeof sanitizeAuditEvent>): Promise<void>;
}

export async function handleCancelDeletion(
  req: Request,
  deps: CancelDeletionDeps,
  clientIp = '0.0.0.0'
): Promise<Response> {
  const origin = req.headers.get('Origin');
  const cors = evaluateCorsRequest(origin, deps.corsOptions);
  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: 'DELETION_CANCEL_FAILED' }), {
      status: 403,
      headers: { ...cors.headers, 'Content-Type': 'application/json' },
    });
  }
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: cors.headers });
  }
  const headers = { ...cors.headers, 'Content-Type': 'application/json' };
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }), {
      status: 405,
      headers,
    });
  }

  const user = await deps.authenticateUser(req.headers.get('Authorization'));
  if (!user) {
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers,
    });
  }

  const cancelled = await deps.cancelDeletionRpc(user.id);
  if (!cancelled) {
    return new Response(JSON.stringify({ error: 'DELETION_NOT_CANCELLABLE' }), {
      status: 409,
      headers,
    });
  }

  if (deps.auditHmacSalt && deps.auditHmacSalt.length >= 16) {
    try {
      const ipHash = await hashAuditIdentifier(clientIp, deps.auditHmacSalt);
      await deps.recordAudit(
        sanitizeAuditEvent({
          userId: user.id,
          eventType: 'account_deletion_cancelled',
          ipHash,
          status: 'success',
          details: { http_status: 200 },
        })
      );
    } catch {
      // ignore
    }
  }

  return new Response(
    JSON.stringify({
      cancelled: true,
      account_status: 'active',
    }),
    { status: 200, headers }
  );
}

export interface ClaimedDeletionJob {
  requestId: string;
  userId: string;
  scheduledAt: string;
  expiresAt: string;
  purgeAttempts: number;
}

export interface PurgeWorkerDeps {
  corsOptions: CorsPolicyOptions;
  cronSecret: string | undefined;
  batchSize?: number;
  nowMs?: () => number;
  claimExpiredRequests(batchSize: number): Promise<ClaimedDeletionJob[]>;
  deleteRecoveryChallenges(userId: string): Promise<void>;
  deleteVaultMetadata(userId: string): Promise<void>;
  deleteProvisioningSalts(userId: string): Promise<void>;
  deleteAuthUser(userId: string): Promise<{ ok: boolean; notFound?: boolean; errorCode?: string }>;
  markCompleted(requestId: string): Promise<void>;
  scheduleRetry(input: {
    requestId: string;
    nextAttempts: number;
    nextRetryAtIso: string;
    terminalManualReview: boolean;
    errorCode: string;
  }): Promise<void>;
  recordAudit(event: ReturnType<typeof sanitizeAuditEvent>): Promise<void>;
}

export async function handleProcessDeletions(
  req: Request,
  deps: PurgeWorkerDeps
): Promise<Response> {
  const origin = req.headers.get('Origin');
  const cors = evaluateCorsRequest(origin, deps.corsOptions);
  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: 'FORBIDDEN' }), {
      status: 403,
      headers: { ...cors.headers, 'Content-Type': 'application/json' },
    });
  }
  const headers = { ...cors.headers, 'Content-Type': 'application/json' };
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }), {
      status: 405,
      headers,
    });
  }

  if (!deps.cronSecret || deps.cronSecret.length < 16) {
    return new Response(JSON.stringify({ error: 'WORKER_MISCONFIGURED' }), {
      status: 500,
      headers,
    });
  }

  // Strictly enforce cron secret header; ignore/reject Bearer JWTs without valid secret
  const submittedSecret = req.headers.get('X-Ghost-Cron-Secret');
  const isAuthorized = await constantTimeEqualSecrets(submittedSecret, deps.cronSecret);
  if (!isAuthorized) {
    return new Response(JSON.stringify({ error: 'FORBIDDEN' }), {
      status: 403,
      headers,
    });
  }

  const jobs = await deps.claimExpiredRequests(deps.batchSize ?? 25);
  let purged = 0;
  let retried = 0;
  let failedManualReview = 0;

  for (const job of jobs) {
    try {
      // Strict ordered destruction sequence: children -> auth.users (cascades user_accounts) -> request row
      await deps.deleteRecoveryChallenges(job.userId);
      await deps.deleteVaultMetadata(job.userId);
      await deps.deleteProvisioningSalts(job.userId);

      const authRes = await deps.deleteAuthUser(job.userId);
      if (!authRes.ok && !authRes.notFound) {
        throw new Error(authRes.errorCode || 'AUTH_DELETE_FAILED');
      }

      await deps.markCompleted(job.requestId);
      purged++;

      try {
        await deps.recordAudit(
          sanitizeAuditEvent({
            eventType: 'account_deletion_purged',
            status: 'success',
            details: { grace_hours: DELETION_GRACE_HOURS, http_status: 200 },
          })
        );
      } catch {
        // ignore
      }
    } catch (err) {
      const nextAttempts = job.purgeAttempts + 1;
      const terminal = nextAttempts >= MAX_PURGE_ATTEMPTS;
      const backoffMs = Math.min(2 ** nextAttempts * 5 * 60 * 1000, 24 * 60 * 60 * 1000);
      const now = deps.nowMs ? deps.nowMs() : Date.now();
      const nextRetryAtIso = new Date(now + backoffMs).toISOString();
      const errorCode =
        err instanceof Error && err.message.length <= 64
          ? err.message
          : 'PURGE_STEP_FAILED';

      await deps.scheduleRetry({
        requestId: job.requestId,
        nextAttempts,
        nextRetryAtIso,
        terminalManualReview: terminal,
        errorCode,
      });

      if (terminal) {
        failedManualReview++;
      } else {
        retried++;
      }

      try {
        await deps.recordAudit(
          sanitizeAuditEvent({
            eventType: terminal
              ? 'account_deletion_failed_manual_review'
              : 'account_deletion_retry_scheduled',
            status: 'failure',
            details: {
              error_code: errorCode,
              retry_attempt: nextAttempts,
              http_status: 500,
            },
          })
        );
      } catch {
        // ignore
      }
    }
  }

  return new Response(
    JSON.stringify({
      processed: jobs.length,
      purged,
      retried,
      failed_manual_review: failedManualReview,
    }),
    { status: 200, headers }
  );
}
