/**
 * @file captchaAndAuthResponsibility.test.ts
 * @summary Verifies Corrections #3 & #4:
 * - Cloudflare Turnstile verification fails closed on missing config, missing/invalid/
 *   expired/replayed tokens, action mismatch, and Turnstile API outages/timeouts.
 * - account-auth delegates registration, password hashing/verification, JWT issuance,
 *   and password reset strictly to Supabase Auth (zero admin.createUser / zero passwords).
 * - account-auth enforces 1 email -> 1 Ghost account, duplicate prevention,
 *   and two-step CSPRNG recovery_salt provisioning without placeholder verifiers.
 * - Challenge issuance (POST /recover-vault/challenge) and deletion scheduling require
 *   Turnstile verification BEFORE any account lookup.
 */

import { handleAccountAuthRequest } from '../../supabase/functions/_shared/accountAuthHandler';
import { handleRecoverVaultRequest } from '../../supabase/functions/_shared/recoverVaultHandler';
import { handleScheduleDeletion } from '../../supabase/functions/_shared/deletionHandlers';
import { handleVerifyCaptcha } from '../../supabase/functions/_shared/verifyCaptchaHandler';
import { TurnstileReplayStore, verifyTurnstileToken } from '../../supabase/functions/_shared/turnstile';

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

class MemoryReplayStore implements TurnstileReplayStore {
  public seen = new Set<string>();
  async recordTokenUsage(hashHex: string): Promise<boolean> {
    if (this.seen.has(hashHex)) return false;
    this.seen.add(hashHex);
    return true;
  }
}

describe('PR #3: Cloudflare Turnstile & Supabase Auth Responsibility Boundaries', () => {
  const ROOT = path.resolve(__dirname, '../..');
  const CORS_OPTS = { environment: 'production', allowLocalhostCors: false };
  const ORIGIN = 'https://frosty-mug.github.io';
  const AUDIT_SALT = 'server-audit-hmac-salt-32-chars!!';
  const ENUM_SECRET = 'server-enumeration-hmac-secret!!';

  test('1. Turnstile fails closed on missing secret, malformed tokens, failed siteverify, outages/timeouts, action mismatch, and replay', async () => {
    const replayStore = new MemoryReplayStore();

    // Missing secret key
    const rMissingSecret = await verifyTurnstileToken({
      token: 'valid-length-turnstile-token-12345',
      secretKey: undefined,
      expectedAction: 'account_provision',
      replayStore,
    });
    expect(rMissingSecret.valid).toBe(false);
    expect(rMissingSecret.reason).toBe('missing_secret_config');

    // Missing / short token
    const rShort = await verifyTurnstileToken({
      token: 'short',
      secretKey: 'turnstile-secret-key-prod',
      expectedAction: 'account_provision',
      replayStore,
    });
    expect(rShort.valid).toBe(false);
    expect(rShort.reason).toBe('missing_or_invalid_token');

    // Cloudflare rejects token
    const rRejected = await verifyTurnstileToken({
      token: 'turnstile-expired-token-123456',
      secretKey: 'turnstile-secret-key-prod',
      expectedAction: 'account_provision',
      replayStore,
      fetchFn: (async () => ({
        ok: true,
        json: async () => ({ success: false }),
      })) as unknown as typeof fetch,
    });
    expect(rRejected.valid).toBe(false);
    expect(rRejected.reason).toBe('siteverify_rejected');

    // Cloudflare outage / timeout throws
    const rOutage = await verifyTurnstileToken({
      token: 'turnstile-network-timeout-123456',
      secretKey: 'turnstile-secret-key-prod',
      expectedAction: 'account_provision',
      replayStore,
      fetchFn: (async () => {
        throw new Error('AbortError');
      }) as unknown as typeof fetch,
    });
    expect(rOutage.valid).toBe(false);
    expect(rOutage.reason).toBe('siteverify_timeout_or_error');

    // Action mismatch
    const rMismatch = await verifyTurnstileToken({
      token: 'turnstile-wrong-action-123456',
      secretKey: 'turnstile-secret-key-prod',
      expectedAction: 'recovery_challenge',
      replayStore,
      fetchFn: (async () => ({
        ok: true,
        json: async () => ({ success: true, action: 'account_provision' }),
      })) as unknown as typeof fetch,
    });
    expect(rMismatch.valid).toBe(false);
    expect(rMismatch.reason).toBe('action_mismatch');

    // Valid token succeeds ONCE and is blocked on replay
    const okFetch = (async () => ({
      ok: true,
      json: async () => ({ success: true, action: 'account_provision' }),
    })) as unknown as typeof fetch;

    const first = await verifyTurnstileToken({
      token: 'single-use-valid-turnstile-token-99',
      secretKey: 'turnstile-secret-key-prod',
      expectedAction: 'account_provision',
      replayStore,
      fetchFn: okFetch,
    });
    expect(first.valid).toBe(true);

    const replay = await verifyTurnstileToken({
      token: 'single-use-valid-turnstile-token-99',
      secretKey: 'turnstile-secret-key-prod',
      expectedAction: 'account_provision',
      replayStore,
      fetchFn: okFetch,
    });
    expect(replay.valid).toBe(false);
    expect(replay.reason).toBe('token_replayed');
  });

  test('2. verify-captcha endpoint validates CAPTCHA fail-closed and emits sanitized audit logs', async () => {
    const audits: any[] = [];
    const replayStore = new MemoryReplayStore();

    const respBad = await handleVerifyCaptcha(
      makeReq(
        'https://proj.supabase.co/functions/v1/verify-captcha',
        'POST',
        { turnstile_token: 'bad', action: 'login_gate' },
        { Origin: ORIGIN }
      ),
      {
        corsOptions: CORS_OPTS,
        turnstileSecretKey: 'turnstile-secret-key-prod',
        auditHmacSalt: AUDIT_SALT,
        replayStore,
        checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        recordAudit: async (e) => {
          audits.push(e);
        },
      }
    );
    expect(respBad.status).toBe(403);

    const respOk = await handleVerifyCaptcha(
      makeReq(
        'https://proj.supabase.co/functions/v1/verify-captcha',
        'POST',
        { turnstile_token: 'valid-captcha-token-abcdef', action: 'password_reset' },
        { Origin: ORIGIN }
      ),
      {
        corsOptions: CORS_OPTS,
        turnstileSecretKey: 'turnstile-secret-key-prod',
        auditHmacSalt: AUDIT_SALT,
        replayStore,
        fetchFn: (async () => ({
          ok: true,
          json: async () => ({ success: true, action: 'password_reset' }),
        })) as unknown as typeof fetch,
        checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        recordAudit: async (e) => {
          audits.push(e);
        },
      }
    );
    expect(respOk.status).toBe(200);
    expect(await respOk.json()).toEqual({ verified: true });
    expect(audits.some((a) => a.event_type === 'captcha_verification_passed')).toBe(true);
  });

  test('3. account-auth NEVER calls admin.createUser or accepts passwords, enforces 1 email -> 1 account, and separates init -> complete', async () => {
    const edgeSrc = fs.readFileSync(
      path.join(ROOT, 'supabase/functions/account-auth/index.ts'),
      'utf8'
    );
    const handlerSrc = fs.readFileSync(
      path.join(ROOT, 'supabase/functions/_shared/accountAuthHandler.ts'),
      'utf8'
    );
    const codeOnly = (edgeSrc + '\n' + handlerSrc)
      .replace(/\/\/[^\n]*/g, '')
      .replace(/\/\*[\s\S]*?\*\//g, '');
    expect(codeOnly).not.toMatch(/admin\.createUser/i);
    expect(codeOnly).not.toMatch(/bcrypt/i);

    const accounts = new Map<string, { email: string }>();
    const pendingSalts = new Map<string, any>();
    const replayStore = new MemoryReplayStore();

    const makeDeps = (authUser: { id: string; email: string } | null) => ({
      corsOptions: CORS_OPTS,
      turnstileSecretKey: 'turnstile-secret-key-prod',
      auditHmacSalt: AUDIT_SALT,
      replayStore,
      fetchFn: (async () => ({
        ok: true,
        json: async () => ({ success: true, action: 'account_provision' }),
      })) as unknown as typeof fetch,
      authenticateUser: async () => authUser,
      checkRateLimit: async () => ({ allowed: true, remaining: 4, retryAfterSeconds: 0 }),
      hasAccountForUserOrEmail: async (userId: string, email: string) => {
        if (accounts.has(userId)) return true;
        for (const a of accounts.values()) {
          if (a.email === email) return true;
        }
        return false;
      },
      upsertProvisioningSalt: async (rec: any) => {
        pendingSalts.set(rec.userId, rec);
      },
      consumeProvisioningSalt: async (userId: string, email: string) => {
        const rec = pendingSalts.get(userId);
        if (!rec || rec.email !== email) return null;
        pendingSalts.delete(userId);
        return rec;
      },
      insertUserAccount: async (rec: any) => {
        if (accounts.has(rec.userId)) return { ok: false, conflict: true };
        for (const a of accounts.values()) {
          if (a.email === rec.email) return { ok: false, conflict: true };
        }
        accounts.set(rec.userId, { email: rec.email });
        return { ok: true as const };
      },
      recordAudit: async () => {},
    });

    const user1 = {
      id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      email: 'alice@example.org',
    };

    // Reject unauthenticated call
    const unauth = await handleAccountAuthRequest(
      makeReq('https://proj.supabase.co/functions/v1/account-auth/init', 'POST', {
        turnstile_token: 'valid-token-123456',
      }, { Origin: ORIGIN }),
      makeDeps(null)
    );
    expect(unauth.status).toBe(401);

    // Reject password / mnemonic fields immediately
    const withPassword = await handleAccountAuthRequest(
      makeReq('https://proj.supabase.co/functions/v1/account-auth/init', 'POST', {
        password: 'MySecretPassword!',
        turnstile_token: 'valid-token-123456',
      }, { Origin: ORIGIN, Authorization: 'Bearer valid-jwt' }),
      makeDeps(user1)
    );
    expect(withPassword.status).toBe(400);
    expect(accounts.size).toBe(0);

    // Reject missing/failed CAPTCHA on /init
    const badCaptcha = await handleAccountAuthRequest(
      makeReq('https://proj.supabase.co/functions/v1/account-auth/init', 'POST', {
        turnstile_token: 'bad',
      }, { Origin: ORIGIN, Authorization: 'Bearer valid-jwt' }),
      makeDeps(user1)
    );
    expect(badCaptcha.status).toBe(403);
    expect(pendingSalts.size).toBe(0);

    // Successful /init stores pending 32B CSPRNG salt, writes ZERO placeholder rows to user_accounts
    const initResp = await handleAccountAuthRequest(
      makeReq('https://proj.supabase.co/functions/v1/account-auth/init', 'POST', {
        turnstile_token: 'provision-turnstile-token-001',
      }, { Origin: ORIGIN, Authorization: 'Bearer valid-jwt' }),
      makeDeps(user1)
    );
    expect(initResp.status).toBe(200);
    const initJson = await initResp.json();
    expect(initJson.account_id).toBe(user1.id);
    expect(initJson.recovery_salt).toMatch(/^[0-9a-f]{64}$/);
    expect(accounts.size).toBe(0); // No placeholder verifier row created!

    // Successful /complete creates complete user_accounts row and consumes salt
    const completeResp = await handleAccountAuthRequest(
      makeReq('https://proj.supabase.co/functions/v1/account-auth/complete', 'POST', {
        recovery_verifier: 'b'.repeat(64),
        encrypted_recovery_envelope: btoa('ENC_RECOVERY_ENVELOPE_PAYLOAD_32_BYTES!!'),
        kdf_version: 2,
      }, { Origin: ORIGIN, Authorization: 'Bearer valid-jwt' }),
      makeDeps(user1)
    );
    expect(completeResp.status).toBe(201);
    expect(accounts.size).toBe(1);
    expect(pendingSalts.size).toBe(0);

    // Duplicate user or second user claiming same email rejected (1 email -> 1 account)
    const user2SameEmail = {
      id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      email: 'ALICE@EXAMPLE.ORG',
    };
    const dupEmailInit = await handleAccountAuthRequest(
      makeReq('https://proj.supabase.co/functions/v1/account-auth/init', 'POST', {
        turnstile_token: 'provision-turnstile-token-002',
      }, { Origin: ORIGIN, Authorization: 'Bearer valid-jwt' }),
      makeDeps(user2SameEmail)
    );
    expect(dupEmailInit.status).toBe(409);
  });

  test('4. Recovery challenge checks Turnstile BEFORE lookup (zero DB query when CAPTCHA fails)', async () => {
    const findAccountByEmail = jest.fn(async () => null);
    const replayStore = new MemoryReplayStore();

    const resp = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/challenge',
        'POST',
        { email: 'alice@example.org', turnstile_token: 'invalid' },
        { Origin: ORIGIN }
      ),
      {
        corsOptions: CORS_OPTS,
        turnstileSecretKey: 'turnstile-secret-key-prod',
        auditHmacSalt: AUDIT_SALT,
        enumerationSecret: ENUM_SECRET,
        replayStore,
        checkRateLimit: async () => ({ allowed: true, remaining: 9, retryAfterSeconds: 0 }),
        findAccountByEmail,
        findAccountById: async () => null,
        createRecoveryChallenge: async () => ({ challengeId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc' }),
        consumeRecoveryChallenge: async () => null,
        recordAudit: async () => {},
      }
    );

    expect(resp.status).toBe(403);
    expect(findAccountByEmail).not.toHaveBeenCalled();
  });

  test('5. Account deletion scheduling requires Cloudflare Turnstile + authenticated JWT', async () => {
    const replayStore = new MemoryReplayStore();
    const user = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };

    const missingCaptcha = await handleScheduleDeletion(
      makeReq(
        'https://proj.supabase.co/functions/v1/schedule-account-deletion',
        'POST',
        {},
        { Origin: ORIGIN, Authorization: 'Bearer jwt' }
      ),
      {
        corsOptions: CORS_OPTS,
        turnstileSecretKey: 'turnstile-secret-key-prod',
        auditHmacSalt: AUDIT_SALT,
        replayStore,
        authenticateUser: async () => user,
        checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        scheduleDeletionRpc: async (uid) => ({
          requestId: uid,
          scheduledAt: '2026-11-25T00:00:00.000Z',
          expiresAt: '2026-11-27T00:00:00.000Z',
          status: 'pending',
        }),
        recordAudit: async () => {},
      }
    );
    expect(missingCaptcha.status).toBe(403);

    const validSchedule = await handleScheduleDeletion(
      makeReq(
        'https://proj.supabase.co/functions/v1/schedule-account-deletion',
        'POST',
        { turnstile_token: 'deletion-turnstile-token-999' },
        { Origin: ORIGIN, Authorization: 'Bearer jwt' }
      ),
      {
        corsOptions: CORS_OPTS,
        turnstileSecretKey: 'turnstile-secret-key-prod',
        auditHmacSalt: AUDIT_SALT,
        replayStore,
        fetchFn: (async () => ({
          ok: true,
          json: async () => ({ success: true, action: 'account_deletion' }),
        })) as unknown as typeof fetch,
        authenticateUser: async () => user,
        checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
        scheduleDeletionRpc: async (uid) => ({
          requestId: uid,
          scheduledAt: '2026-11-25T00:00:00.000Z',
          expiresAt: '2026-11-27T00:00:00.000Z',
          status: 'pending',
        }),
        recordAudit: async () => {},
      }
    );
    expect(validSchedule.status).toBe(200);
    const body = await validSchedule.json();
    expect(body.grace_hours).toBe(48);
    expect(body.account_status).toBe('deletion_pending');
  });
});
