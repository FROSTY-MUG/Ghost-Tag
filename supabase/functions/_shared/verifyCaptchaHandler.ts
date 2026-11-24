/**
 * Ghost-Tag v2.1.0 - Standalone CAPTCHA Verification Endpoint Handler (verify-captcha)
 */

import { hashAuditIdentifier, sanitizeAuditEvent } from './audit.ts';
import { CorsPolicyOptions, evaluateCorsRequest } from './cors.ts';
import { TurnstileReplayStore, verifyTurnstileToken } from './turnstile.ts';

export interface VerifyCaptchaDeps {
  corsOptions: CorsPolicyOptions;
  turnstileSecretKey: string | undefined;
  auditHmacSalt: string | undefined;
  replayStore: TurnstileReplayStore;
  fetchFn?: typeof fetch;
  checkRateLimit(
    bucketKey: string,
    action: 'verify_captcha'
  ): Promise<{ allowed: boolean; retryAfterSeconds: number }>;
  recordAudit(event: ReturnType<typeof sanitizeAuditEvent>): Promise<void>;
}

export async function handleVerifyCaptcha(
  req: Request,
  deps: VerifyCaptchaDeps,
  clientIp = '0.0.0.0'
): Promise<Response> {
  const origin = req.headers.get('Origin');
  const cors = evaluateCorsRequest(origin, deps.corsOptions);
  if (!cors.allowed) {
    return new Response(JSON.stringify({ verified: false, error: 'CAPTCHA_FAILED' }), {
      status: 403,
      headers: { ...cors.headers, 'Content-Type': 'application/json' },
    });
  }
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: cors.headers });
  }
  const headers = { ...cors.headers, 'Content-Type': 'application/json' };
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ verified: false, error: 'METHOD_NOT_ALLOWED' }), {
      status: 405,
      headers,
    });
  }
  if (!deps.auditHmacSalt || deps.auditHmacSalt.length < 16) {
    return new Response(JSON.stringify({ verified: false, error: 'CAPTCHA_FAILED' }), {
      status: 500,
      headers,
    });
  }

  const ipHash = await hashAuditIdentifier(clientIp, deps.auditHmacSalt);
  const bucket = await hashAuditIdentifier(`captcha-ip:${clientIp}`, deps.auditHmacSalt);
  const rl = await deps.checkRateLimit(bucket, 'verify_captcha');
  if (!rl.allowed) {
    return new Response(
      JSON.stringify({
        verified: false,
        error: 'RATE_LIMITED',
        retry_after_seconds: rl.retryAfterSeconds,
      }),
      { status: 429, headers }
    );
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    body = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : {};
  } catch {
    return new Response(JSON.stringify({ verified: false, error: 'INVALID_REQUEST' }), {
      status: 400,
      headers,
    });
  }

  const expectedAction =
    typeof body.action === 'string' && /^[a-z0-9_]{3,48}$/.test(body.action)
      ? body.action
      : 'verify_captcha';

  const result = await verifyTurnstileToken({
    token: body.turnstile_token,
    secretKey: deps.turnstileSecretKey,
    expectedAction,
    remoteIp: clientIp,
    replayStore: deps.replayStore,
    fetchFn: deps.fetchFn,
  });

  if (!result.valid) {
    try {
      await deps.recordAudit(
        sanitizeAuditEvent({
          eventType:
            result.reason === 'token_replayed'
              ? 'captcha_replay_blocked'
              : 'captcha_verification_failed',
          ipHash,
          status: 'blocked',
          details: {
            error_code: 'TURNSTILE_REJECTED',
            reason: result.reason,
            action: expectedAction,
            http_status: 403,
          },
        })
      );
    } catch {
      // ignore audit failure
    }
    return new Response(JSON.stringify({ verified: false, error: 'CAPTCHA_FAILED' }), {
      status: 403,
      headers,
    });
  }

  try {
    await deps.recordAudit(
      sanitizeAuditEvent({
        eventType: 'captcha_verification_passed',
        ipHash,
        status: 'success',
        details: { action: expectedAction, http_status: 200 },
      })
    );
  } catch {
    // ignore audit failure
  }

  return new Response(JSON.stringify({ verified: true }), { status: 200, headers });
}
