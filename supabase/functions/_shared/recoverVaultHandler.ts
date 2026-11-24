/**
 * Ghost-Tag v2.1.0 - Hardened Recover-Vault Request Handler
 *
 * Implements ALL 8 Compensating Controls Required by Correction #5:
 *   1. Server-side Cloudflare Turnstile validation on /challenge BEFORE account lookup
 *   2. Separate recovery_challenge rate limit (10/hr via check_rate_limit)
 *   3. Separate recovery_proof rate limit (5/hr via check_rate_limit)
 *   4. Indistinguishable anti-enumeration challenge synthesis for unknown/deleted accounts
 *   5. Strict input schema validation (email, RFC 4122 UUID, 64-hex proof; forbids secrets)
 *   6. Generic opaque error responses (never leaks account existence or DB errors)
 *   7. Atomic single-use DB challenge consumption (consume_recovery_challenge RPC + authoritative server_timestamp)
 *   8. Sanitized audit_events logging across all paths
 *
 * Returns ONLY { success: true, encrypted_recovery_envelope } upon proof verification —
 * NEVER returns recovery_verifier or recovery_salt on /verify.
 */

import { AuditEventInput, hashAuditIdentifier, sanitizeAuditEvent } from './audit.ts';
import { CorsPolicyOptions, evaluateCorsRequest } from './cors.ts';
import {
  HEX64_REGEX,
  RECOVERY_CHALLENGE_TTL_SECONDS,
  RFC4122_UUID_REGEX,
  bytesToBase64,
  bytesToHex,
  constantTimeEqualBytes,
  normalizeEmail,
  synthesizeAntiEnumerationChallenge,
  verifyRecoveryProof,
} from './recoveryCrypto.ts';
import { TurnstileReplayStore, verifyTurnstileToken } from './turnstile.ts';

export interface StoredRecoveryAccount {
  id: string;
  email: string;
  accountStatus: 'active' | 'deletion_pending' | 'purging' | 'deleted';
  recoveryVerifierBytes: Uint8Array;
  recoverySaltBytes: Uint8Array;
  encryptedRecoveryEnvelopeBytes: Uint8Array;
  kdfVersion: number;
}

export interface ConsumedChallengeRecord {
  accountId: string;
  nonceBytes: Uint8Array;
  serverTimestamp: number;
}

export interface RecoverVaultDeps {
  corsOptions: CorsPolicyOptions;
  turnstileSecretKey: string | undefined;
  auditHmacSalt: string | undefined;
  enumerationSecret: string | undefined;
  replayStore: TurnstileReplayStore;
  fetchFn?: typeof fetch;
  nowSeconds?: () => number;
  randomBytes?: (len: number) => Uint8Array;
  checkRateLimit(
    bucketKey: string,
    action: 'recovery_challenge' | 'recovery_proof'
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds: number }>;
  findAccountByEmail(normalizedEmail: string): Promise<StoredRecoveryAccount | null>;
  findAccountById(accountId: string): Promise<StoredRecoveryAccount | null>;
  createRecoveryChallenge(input: {
    accountId: string;
    nonceBytes: Uint8Array;
    serverTimestamp: number;
    expiresAtIso: string;
  }): Promise<{ challengeId: string } | null>;
  consumeRecoveryChallenge(challengeId: string): Promise<ConsumedChallengeRecord | null>;
  recordAudit(event: ReturnType<typeof sanitizeAuditEvent>): Promise<void>;
}

const FORBIDDEN_RECOVERY_KEYS = new Set([
  'password',
  'passphrase',
  'mnemonic',
  'recovery_phrase',
  'recovery_auth_secret',
]);

function defaultRandomBytes(len: number): Uint8Array {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

async function emitSafeAudit(
  deps: RecoverVaultDeps,
  input: AuditEventInput
): Promise<void> {
  try {
    await deps.recordAudit(sanitizeAuditEvent(input));
  } catch {
    // Fail silent on audit write error while preserving outer fail-closed behavior
  }
}

export async function handleRecoverVaultRequest(
  req: Request,
  deps: RecoverVaultDeps,
  clientIp = '0.0.0.0'
): Promise<Response> {
  const origin = req.headers.get('Origin');
  const cors = evaluateCorsRequest(origin, deps.corsOptions);

  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: 'RECOVERY_FAILED' }), {
      status: 403,
      headers: { ...cors.headers, 'Content-Type': 'application/json' },
    });
  }

  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: cors.headers });
  }

  const headers = { ...cors.headers, 'Content-Type': 'application/json' };
  const opaqueFail = (status: number) =>
    new Response(JSON.stringify({ error: 'RECOVERY_FAILED' }), { status, headers });

  if (req.method !== 'POST') {
    return opaqueFail(405);
  }

  if (
    !deps.auditHmacSalt ||
    deps.auditHmacSalt.length < 16 ||
    !deps.enumerationSecret ||
    deps.enumerationSecret.length < 16
  ) {
    return opaqueFail(500);
  }

  const ipHash = await hashAuditIdentifier(clientIp, deps.auditHmacSalt);

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid body');
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return opaqueFail(400);
  }

  for (const key of Object.keys(body)) {
    if (FORBIDDEN_RECOVERY_KEYS.has(key.toLowerCase())) {
      return opaqueFail(400);
    }
  }

  const pathname = new URL(req.url).pathname.toLowerCase();
  const explicitAction =
    typeof body.action === 'string' ? body.action.toLowerCase() : '';
  const route = pathname.endsWith('/challenge')
    ? 'challenge'
    : pathname.endsWith('/verify')
      ? 'verify'
      : explicitAction;

  if (route === 'challenge') {
    // 1. Validate email format and CAPTCHA BEFORE touching account DB rows
    const email = normalizeEmail(body.email);
    if (!email) {
      return opaqueFail(400);
    }

    const captcha = await verifyTurnstileToken({
      token: body.turnstile_token,
      secretKey: deps.turnstileSecretKey,
      expectedAction: 'recovery_challenge',
      remoteIp: clientIp,
      replayStore: deps.replayStore,
      fetchFn: deps.fetchFn,
    });

    if (!captcha.valid) {
      await emitSafeAudit(deps, {
        eventType: 'captcha_verification_failed',
        ipHash,
        status: 'blocked',
        details: {
          error_code: 'TURNSTILE_REJECTED',
          reason: captcha.reason,
          action: 'recovery_challenge',
          http_status: 403,
        },
      });
      return opaqueFail(403);
    }

    await emitSafeAudit(deps, {
      eventType: 'captcha_verification_passed',
      ipHash,
      status: 'success',
      details: { action: 'recovery_challenge', http_status: 200 },
    });

    // 2. Partitioned recovery_challenge rate limit (10/hr) using opaque email/IP buckets
    const emailBucket = await hashAuditIdentifier(`chal-email:${email}`, deps.auditHmacSalt);
    const ipBucket = await hashAuditIdentifier(`chal-ip:${clientIp}`, deps.auditHmacSalt);
    const [rlEmail, rlIp] = await Promise.all([
      deps.checkRateLimit(emailBucket, 'recovery_challenge'),
      deps.checkRateLimit(ipBucket, 'recovery_challenge'),
    ]);
    if (!rlEmail.allowed || !rlIp.allowed) {
      await emitSafeAudit(deps, {
        eventType: 'recovery_challenge_blocked',
        ipHash,
        status: 'blocked',
        details: { action: 'recovery_challenge', http_status: 429 },
      });
      return opaqueFail(429);
    }

    // 3. Authoritative server timestamp & uniform anti-enumeration work
    const serverTs = deps.nowSeconds
      ? deps.nowSeconds()
      : Math.floor(Date.now() / 1000);

    const [account, syntheticFallback] = await Promise.all([
      deps.findAccountByEmail(email),
      synthesizeAntiEnumerationChallenge(email, deps.enumerationSecret, serverTs),
    ]);

    const isEligibleAccount =
      account !== null &&
      (account.accountStatus === 'active' ||
        account.accountStatus === 'deletion_pending');

    if (!isEligibleAccount) {
      await emitSafeAudit(deps, {
        eventType: 'recovery_challenge_synthetic',
        ipHash,
        status: 'success',
        details: {
          challenge_outcome: 'synthetic',
          http_status: 200,
        },
      });
      return new Response(JSON.stringify(syntheticFallback), {
        status: 200,
        headers,
      });
    }

    const rng = deps.randomBytes ?? defaultRandomBytes;
    const nonceBytes = rng(32);
    const expiresAtIso = new Date(
      (serverTs + RECOVERY_CHALLENGE_TTL_SECONDS) * 1000
    ).toISOString();

    const stored = await deps.createRecoveryChallenge({
      accountId: account.id,
      nonceBytes,
      serverTimestamp: serverTs,
      expiresAtIso,
    });

    if (!stored) {
      return opaqueFail(500);
    }

    await emitSafeAudit(deps, {
      userId: account.id,
      eventType: 'recovery_challenge_issued',
      ipHash,
      status: 'success',
      details: {
        challenge_outcome: 'issued',
        kdf_version: account.kdfVersion,
        http_status: 200,
      },
    });

    return new Response(
      JSON.stringify({
        challenge_id: stored.challengeId,
        account_id: account.id,
        nonce: bytesToHex(nonceBytes),
        server_timestamp: serverTs,
        recovery_salt: bytesToHex(account.recoverySaltBytes),
        kdf_version: account.kdfVersion,
      }),
      { status: 200, headers }
    );
  }

  if (route === 'verify') {
    const challengeId = body.challenge_id;
    const submittedAccountId = body.account_id;
    const recoveryProof = body.recovery_proof;

    if (
      typeof challengeId !== 'string' ||
      !RFC4122_UUID_REGEX.test(challengeId) ||
      typeof recoveryProof !== 'string' ||
      !HEX64_REGEX.test(recoveryProof) ||
      (submittedAccountId !== undefined &&
        (typeof submittedAccountId !== 'string' ||
          !RFC4122_UUID_REGEX.test(submittedAccountId)))
    ) {
      return opaqueFail(400);
    }

    // Partitioned recovery_proof IP rate limit before touching challenge state
    const proofIpBucket = await hashAuditIdentifier(
      `proof-ip:${clientIp}`,
      deps.auditHmacSalt
    );
    const rlProofIp = await deps.checkRateLimit(proofIpBucket, 'recovery_proof');
    if (!rlProofIp.allowed) {
      await emitSafeAudit(deps, {
        eventType: 'recovery_proof_blocked',
        ipHash,
        status: 'blocked',
        details: { action: 'recovery_proof', http_status: 429 },
      });
      return opaqueFail(429);
    }

    // Atomic single-use consume (prevents replay & enforces expires_at > clock_timestamp())
    const challenge = await deps.consumeRecoveryChallenge(challengeId.toLowerCase());
    if (!challenge) {
      // Constant-time dummy work
      constantTimeEqualBytes(new Uint8Array(32), new Uint8Array(32));
      await emitSafeAudit(deps, {
        eventType: 'recovery_proof_failed',
        ipHash,
        status: 'failure',
        details: { reason: 'challenge_invalid_expired_or_replayed', http_status: 401 },
      });
      return opaqueFail(401);
    }

    // Per-account proof rate limit (5/hr)
    const acctBucket = await hashAuditIdentifier(
      `proof-acct:${challenge.accountId.toLowerCase()}`,
      deps.auditHmacSalt
    );
    const rlAcct = await deps.checkRateLimit(acctBucket, 'recovery_proof');
    if (!rlAcct.allowed) {
      await emitSafeAudit(deps, {
        userId: challenge.accountId,
        eventType: 'recovery_proof_blocked',
        ipHash,
        status: 'blocked',
        details: { action: 'recovery_proof', http_status: 429 },
      });
      return opaqueFail(429);
    }

    if (
      typeof submittedAccountId === 'string' &&
      submittedAccountId.toLowerCase() !== challenge.accountId.toLowerCase()
    ) {
      await emitSafeAudit(deps, {
        userId: challenge.accountId,
        eventType: 'recovery_proof_failed',
        ipHash,
        status: 'failure',
        details: { reason: 'account_binding_mismatch', http_status: 401 },
      });
      return opaqueFail(401);
    }

    const account = await deps.findAccountById(challenge.accountId);
    if (
      !account ||
      (account.accountStatus !== 'active' &&
        account.accountStatus !== 'deletion_pending')
    ) {
      await emitSafeAudit(deps, {
        eventType: 'recovery_proof_failed',
        ipHash,
        status: 'failure',
        details: { reason: 'account_unavailable', http_status: 401 },
      });
      return opaqueFail(401);
    }

    // Verify proof strictly using authoritative DB nonce, account_id, and DB server_timestamp
    const proofValid = await verifyRecoveryProof(
      account.recoveryVerifierBytes,
      challenge.nonceBytes,
      account.id,
      challenge.serverTimestamp,
      recoveryProof
    );

    if (!proofValid) {
      await emitSafeAudit(deps, {
        userId: account.id,
        eventType: 'recovery_proof_failed',
        ipHash,
        status: 'failure',
        details: { reason: 'invalid_proof_hmac', http_status: 401 },
      });
      return opaqueFail(401);
    }

    await emitSafeAudit(deps, {
      userId: account.id,
      eventType: 'recovery_proof_verified',
      ipHash,
      status: 'success',
      details: { kdf_version: account.kdfVersion, http_status: 200 },
    });

    // Return ONLY encrypted_recovery_envelope (NEVER recovery_verifier)
    return new Response(
      JSON.stringify({
        success: true,
        account_id: account.id,
        encrypted_recovery_envelope: bytesToBase64(account.encryptedRecoveryEnvelopeBytes),
        kdf_version: account.kdfVersion,
      }),
      { status: 200, headers }
    );
  }

  return opaqueFail(404);
}
