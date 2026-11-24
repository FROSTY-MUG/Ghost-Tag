/**
 * Ghost-Tag v2.1.0 - Account Provisioning Handler Logic (account-auth)
 *
 * Security Invariants (Correction #3 & #4):
 * - NEVER accepts user passwords, passphrases, or recovery phrases.
 * - NEVER duplicates Supabase Auth signup/login or calls auth.admin.createUser().
 * - Requires an already-authenticated Supabase Auth JWT verified via auth.getUser().
 * - Validates Cloudflare Turnstile fail-closed during /init.
 * - Enforces 1 email -> 1 Ghost-Tag account and duplicate-user rejection.
 * - Generates 32-byte server CSPRNG recovery_salt in account_provisioning_salts
 *   (/init) and inserts complete real verifier + envelope into user_accounts (/complete)
 *   without ever inserting placeholder verifier rows.
 */

import { AuditEventInput, hashAuditIdentifier, sanitizeAuditEvent } from './audit.ts';
import { CorsPolicyOptions, evaluateCorsRequest } from './cors.ts';
import {
  HEX64_REGEX,
  PROVISION_SALT_TTL_SECONDS,
  base64ToBytes,
  bytesToHex,
  normalizeEmail,
} from './recoveryCrypto.ts';
import { TurnstileReplayStore, verifyTurnstileToken } from './turnstile.ts';

export const FORBIDDEN_AUTH_BODY_KEYS = new Set([
  'password',
  'passphrase',
  'recovery_phrase',
  'mnemonic',
  'recovery_auth_secret',
  'recovery_kek',
  'raw_dek',
  'dek',
]);

export interface AuthenticatedUser {
  id: string;
  email: string;
}

export interface ProvisioningSaltRecord {
  userId: string;
  email: string;
  recoverySaltHex: string;
  expiresAtIso: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export interface AccountAuthDeps {
  corsOptions: CorsPolicyOptions;
  turnstileSecretKey: string | undefined;
  auditHmacSalt: string | undefined;
  replayStore: TurnstileReplayStore;
  fetchFn?: typeof fetch;
  randomBytes?: (len: number) => Uint8Array;
  authenticateUser(authHeader: string | null): Promise<AuthenticatedUser | null>;
  checkRateLimit(bucketKey: string, action: string): Promise<RateLimitResult>;
  hasAccountForUserOrEmail(userId: string, normalizedEmail: string): Promise<boolean>;
  upsertProvisioningSalt(record: ProvisioningSaltRecord): Promise<void>;
  consumeProvisioningSalt(userId: string, normalizedEmail: string): Promise<ProvisioningSaltRecord | null>;
  insertUserAccount(record: {
    userId: string;
    email: string;
    recoveryVerifierBytes: Uint8Array;
    recoverySaltBytes: Uint8Array;
    encryptedRecoveryEnvelopeBytes: Uint8Array;
    kdfVersion: number;
  }): Promise<{ ok: true } | { ok: false; conflict?: boolean }>;
  recordAudit(event: ReturnType<typeof sanitizeAuditEvent>): Promise<void>;
}

function defaultRandomBytes(len: number): Uint8Array {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

function hasForbiddenSecretFields(body: Record<string, unknown>): string | null {
  for (const key of Object.keys(body)) {
    if (FORBIDDEN_AUTH_BODY_KEYS.has(key.toLowerCase())) {
      return key;
    }
  }
  return null;
}

async function emitSafeAudit(
  deps: AccountAuthDeps,
  input: AuditEventInput
): Promise<void> {
  try {
    const sanitized = sanitizeAuditEvent(input);
    await deps.recordAudit(sanitized);
  } catch {
    // Audit serialization errors fail silent rather than crashing outer response,
    // while strictly never persisting unsanitized inputs.
  }
}

export async function handleAccountAuthRequest(
  req: Request,
  deps: AccountAuthDeps,
  clientIp = '0.0.0.0'
): Promise<Response> {
  const origin = req.headers.get('Origin');
  const cors = evaluateCorsRequest(origin, deps.corsOptions);

  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: 'ACCOUNT_PROVISION_FAILED' }), {
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
    return new Response(JSON.stringify({ error: 'ACCOUNT_PROVISION_FAILED' }), {
      status: 500,
      headers,
    });
  }

  const ipHash = await hashAuditIdentifier(clientIp, deps.auditHmacSalt);

  // Supabase Auth JWT verification MUST happen via Supabase Auth getUser()
  const authUser = await deps.authenticateUser(req.headers.get('Authorization'));
  if (!authUser) {
    await emitSafeAudit(deps, {
      eventType: 'account_provision_blocked',
      ipHash,
      status: 'blocked',
      details: { error_code: 'UNAUTHENTICATED', http_status: 401 },
    });
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers,
    });
  }

  const normalizedEmail = normalizeEmail(authUser.email);
  if (!normalizedEmail) {
    return new Response(JSON.stringify({ error: 'ACCOUNT_PROVISION_FAILED' }), {
      status: 400,
      headers,
    });
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('bad body');
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return new Response(JSON.stringify({ error: 'INVALID_REQUEST' }), {
      status: 400,
      headers,
    });
  }

  // Enforce Auth Boundary: reject password/passphrase/mnemonic fields immediately
  const forbiddenField = hasForbiddenSecretFields(body);
  if (forbiddenField) {
    await emitSafeAudit(deps, {
      userId: authUser.id,
      eventType: 'account_provision_blocked',
      ipHash,
      status: 'blocked',
      details: {
        error_code: 'FORBIDDEN_CREDENTIAL_FIELD',
        reason: forbiddenField,
        http_status: 400,
      },
    });
    return new Response(JSON.stringify({ error: 'UNSAFE_SECRET_FIELD_FORBIDDEN' }), {
      status: 400,
      headers,
    });
  }

  // Determine step from URL pathname suffix or explicit body.step
  const urlPath = new URL(req.url).pathname.toLowerCase();
  const explicitStep = typeof body.step === 'string' ? body.step.toLowerCase() : '';
  const step = urlPath.endsWith('/init')
    ? 'init'
    : urlPath.endsWith('/complete')
      ? 'complete'
      : explicitStep;

  if (step !== 'init' && step !== 'complete') {
    return new Response(JSON.stringify({ error: 'INVALID_PROVISION_STEP' }), {
      status: 400,
      headers,
    });
  }

  const bucketKey = await hashAuditIdentifier(`provision:${authUser.id}`, deps.auditHmacSalt);
  const rl = await deps.checkRateLimit(bucketKey, 'auth_provision');
  if (!rl.allowed) {
    await emitSafeAudit(deps, {
      userId: authUser.id,
      eventType: 'rate_limit_blocked',
      ipHash,
      status: 'blocked',
      details: { action: 'auth_provision', http_status: 429 },
    });
    return new Response(
      JSON.stringify({ error: 'RATE_LIMITED', retry_after_seconds: rl.retryAfterSeconds }),
      { status: 429, headers }
    );
  }

  if (step === 'init') {
    const captchaResult = await verifyTurnstileToken({
      token: body.turnstile_token,
      secretKey: deps.turnstileSecretKey,
      expectedAction: 'account_provision',
      remoteIp: clientIp,
      replayStore: deps.replayStore,
      fetchFn: deps.fetchFn,
    });

    if (!captchaResult.valid) {
      await emitSafeAudit(deps, {
        userId: authUser.id,
        eventType: 'captcha_verification_failed',
        ipHash,
        status: 'blocked',
        details: {
          error_code: 'TURNSTILE_REJECTED',
          reason: captchaResult.reason,
          action: 'account_provision',
          http_status: 403,
        },
      });
      return new Response(JSON.stringify({ error: 'CAPTCHA_VERIFICATION_FAILED' }), {
        status: 403,
        headers,
      });
    }

    await emitSafeAudit(deps, {
      userId: authUser.id,
      eventType: 'captcha_verification_passed',
      ipHash,
      status: 'success',
      details: { action: 'account_provision', http_status: 200 },
    });

    // Enforce 1 email -> 1 account & duplicate user check
    const alreadyExists = await deps.hasAccountForUserOrEmail(authUser.id, normalizedEmail);
    if (alreadyExists) {
      await emitSafeAudit(deps, {
        userId: authUser.id,
        eventType: 'account_provision_blocked',
        ipHash,
        status: 'blocked',
        details: { error_code: 'DUPLICATE_ACCOUNT', http_status: 409 },
      });
      return new Response(JSON.stringify({ error: 'ACCOUNT_ALREADY_EXISTS' }), {
        status: 409,
        headers,
      });
    }

    const rng = deps.randomBytes ?? defaultRandomBytes;
    const saltBytes = rng(32);
    if (saltBytes.length !== 32) {
      return new Response(JSON.stringify({ error: 'ACCOUNT_PROVISION_FAILED' }), {
        status: 500,
        headers,
      });
    }

    const saltHex = bytesToHex(saltBytes);
    const expiresAtIso = new Date(
      Date.now() + PROVISION_SALT_TTL_SECONDS * 1000
    ).toISOString();

    await deps.upsertProvisioningSalt({
      userId: authUser.id,
      email: normalizedEmail,
      recoverySaltHex: saltHex,
      expiresAtIso,
    });

    await emitSafeAudit(deps, {
      userId: authUser.id,
      eventType: 'account_provision_init',
      ipHash,
      status: 'success',
      details: { kdf_version: 2, http_status: 200 },
    });

    return new Response(
      JSON.stringify({
        account_id: authUser.id,
        recovery_salt: saltHex,
        kdf_version: 2,
      }),
      { status: 200, headers }
    );
  }

  // step === 'complete'
  const verifierHex = body.recovery_verifier;
  const envelopeB64 = body.encrypted_recovery_envelope;
  const kdfVersion = typeof body.kdf_version === 'number' ? body.kdf_version : 2;

  if (
    typeof verifierHex !== 'string' ||
    !HEX64_REGEX.test(verifierHex) ||
    typeof envelopeB64 !== 'string' ||
    envelopeB64.length < 44 ||
    !Number.isInteger(kdfVersion) ||
    kdfVersion < 1
  ) {
    return new Response(JSON.stringify({ error: 'INVALID_RECOVERY_PAYLOAD' }), {
      status: 400,
      headers,
    });
  }

  let envelopeBytes: Uint8Array;
  try {
    envelopeBytes = base64ToBytes(envelopeB64);
    if (envelopeBytes.length < 32 || envelopeBytes.length > 65536) {
      throw new Error('invalid length');
    }
  } catch {
    return new Response(JSON.stringify({ error: 'INVALID_RECOVERY_PAYLOAD' }), {
      status: 400,
      headers,
    });
  }

  const pendingSalt = await deps.consumeProvisioningSalt(authUser.id, normalizedEmail);
  if (!pendingSalt || new Date(pendingSalt.expiresAtIso).getTime() <= Date.now()) {
    await emitSafeAudit(deps, {
      userId: authUser.id,
      eventType: 'account_provision_blocked',
      ipHash,
      status: 'failure',
      details: { error_code: 'PROVISION_SALT_EXPIRED_OR_MISSING', http_status: 400 },
    });
    return new Response(JSON.stringify({ error: 'PROVISION_SESSION_EXPIRED' }), {
      status: 400,
      headers,
    });
  }

  const verifierBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    verifierBytes[i] = parseInt(verifierHex.slice(i * 2, i * 2 + 2), 16);
  }
  const saltBytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    saltBytes[i] = parseInt(pendingSalt.recoverySaltHex.slice(i * 2, i * 2 + 2), 16);
  }

  const insertResult = await deps.insertUserAccount({
    userId: authUser.id,
    email: normalizedEmail,
    recoveryVerifierBytes: verifierBytes,
    recoverySaltBytes: saltBytes,
    encryptedRecoveryEnvelopeBytes: envelopeBytes,
    kdfVersion,
  });

  if (!insertResult.ok) {
    await emitSafeAudit(deps, {
      userId: authUser.id,
      eventType: 'account_provision_blocked',
      ipHash,
      status: 'blocked',
      details: {
        error_code: insertResult.conflict ? 'DUPLICATE_ACCOUNT' : 'PROVISION_INSERT_FAILED',
        http_status: insertResult.conflict ? 409 : 500,
      },
    });
    return new Response(
      JSON.stringify({
        error: insertResult.conflict ? 'ACCOUNT_ALREADY_EXISTS' : 'ACCOUNT_PROVISION_FAILED',
      }),
      { status: insertResult.conflict ? 409 : 500, headers }
    );
  }

  await emitSafeAudit(deps, {
    userId: authUser.id,
    eventType: 'account_provision_complete',
    ipHash,
    status: 'success',
    details: { kdf_version: kdfVersion, http_status: 201 },
  });

  return new Response(
    JSON.stringify({
      success: true,
      account_id: authUser.id,
      kdf_version: kdfVersion,
    }),
    { status: 201, headers }
  );
}
