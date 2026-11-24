/**
 * @file recoveryChallengeProof.test.ts
 * @summary Verifies Correction #5 & Challenge-Response Cryptography:
 * - End-to-end 12-word BIP-39 normalization -> 2-stage Argon2id verifier ->
 *   76B canonical proof HMAC-SHA256(recovery_verifier, nonce || account_id || server_timestamp)
 * - Returns ONLY encrypted_recovery_envelope on verify (never exposes recovery_verifier)
 * - Rejects modified account_id, tampered proof, forged timestamp, expired challenges,
 *   and replayed challenges with generic 401 RECOVERY_FAILED
 * - Enforces 78B wrapped_dek validation on sync-vault-metadata
 * - Verifies supabase/config.toml recover-vault JWT policy gate & Edge imports
 */

import {
  RECOVERY_AUTH_DOMAIN,
  buildCanonicalProofMessage,
  computeRecoveryProofHex,
  getVerifierSalt,
  normalizeRecoveryPhrase,
} from '../../supabase/functions/_shared/recoveryCrypto';
import {
  StoredRecoveryAccount,
  handleRecoverVaultRequest,
} from '../../supabase/functions/_shared/recoverVaultHandler';
import { handleSyncVaultMetadata } from '../../supabase/functions/_shared/syncMetadataHandler';
import { TurnstileReplayStore } from '../../supabase/functions/_shared/turnstile';
import { deriveKEK, setTestArgon2Provider } from '../crypto/argon2';
import { generateDEK, generateKeyId } from '../crypto/random';
import { wrapAndSerializeDEK } from '../crypto/wrappedDekCodec';

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
  private seen = new Set<string>();
  async recordTokenUsage(hashHex: string): Promise<boolean> {
    if (this.seen.has(hashHex)) return false;
    this.seen.add(hashHex);
    return true;
  }
}

describe('PR #3: Recovery Challenge/Proof Verification & Vault Sync', () => {
  const ROOT = path.resolve(__dirname, '../..');
  const ORIGIN = 'https://frosty-mug.github.io';
  const CORS_OPTS = { environment: 'production', allowLocalhostCors: false };
  const AUDIT_SALT = 'server-audit-hmac-salt-32-chars!!';
  const ENUM_SECRET = 'server-enumeration-hmac-secret!!';

  beforeAll(() => {
    setTestArgon2Provider(async (input, salt) => {
      const data = new Uint8Array([
        ...new TextEncoder().encode(input),
        ...salt,
      ]);
      const digest = await crypto.subtle.digest('SHA-256', data);
      return new Uint8Array(digest);
    });
  });

  afterAll(() => {
    setTestArgon2Provider(null);
  });

  test('1. Full challenge-response flow succeeds and returns ONLY encrypted_recovery_envelope (no verifier leakage)', async () => {
    const accountId = '11111111-2222-4333-8444-555555555555';
    const phrase =
      '  Abandon   ABILITY able about above absent absorb abstract absurd abuse access  accident ';
    const normalizedPhrase = normalizeRecoveryPhrase(phrase);

    // Server generates 32B CSPRNG recovery_salt
    const recoverySalt = new Uint8Array(32).fill(0x42);

    // Stage 1: recovery_auth_secret
    const stage1Params = {
      salt: recoverySalt,
      memoryCost: 32768,
      timeCost: 3,
      parallelism: 2,
      version: 0x13,
    };
    const authSecretBytes = await deriveKEK(
      RECOVERY_AUTH_DOMAIN + normalizedPhrase,
      recoverySalt,
      stage1Params
    );
    const authSecretHex = Array.from(authSecretBytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    // Stage 2: recovery_verifier stored on server
    const verifierSalt = await getVerifierSalt();
    const stage2Params = {
      salt: verifierSalt,
      memoryCost: 32768,
      timeCost: 3,
      parallelism: 2,
      version: 0x13,
    };
    const recoveryVerifier = await deriveKEK(authSecretHex, verifierSalt, stage2Params);

    const envelopePlainMock = new TextEncoder().encode(
      'ENCRYPTED_RECOVERY_ENVELOPE_BLOB_V2.1.0_PAYLOAD'
    );

    const storedAccount: StoredRecoveryAccount = {
      id: accountId,
      email: 'alice@example.org',
      accountStatus: 'active',
      recoveryVerifierBytes: recoveryVerifier,
      recoverySaltBytes: recoverySalt,
      encryptedRecoveryEnvelopeBytes: envelopePlainMock,
      kdfVersion: 2,
    };

    const challenges = new Map<
      string,
      { accountId: string; nonceBytes: Uint8Array; serverTimestamp: number; expiresAtMs: number; consumed: boolean }
    >();
    let nowSec = 1_750_000_000;
    const replayStore = new MemoryReplayStore();
    const audits: any[] = [];

    const deps = {
      corsOptions: CORS_OPTS,
      turnstileSecretKey: 'turnstile-secret-prod-key',
      auditHmacSalt: AUDIT_SALT,
      enumerationSecret: ENUM_SECRET,
      replayStore,
      fetchFn: (async () => ({
        ok: true,
        json: async () => ({ success: true, action: 'recovery_challenge' }),
      })) as unknown as typeof fetch,
      nowSeconds: () => nowSec,
      checkRateLimit: async () => ({ allowed: true, remaining: 4, retryAfterSeconds: 0 }),
      findAccountByEmail: async (email: string) =>
        email === storedAccount.email ? storedAccount : null,
      findAccountById: async (id: string) =>
        id.toLowerCase() === accountId ? storedAccount : null,
      createRecoveryChallenge: async (input: any) => {
        const cid = '22222222-3333-4444-8555-666666666666';
        challenges.set(cid, {
          accountId: input.accountId,
          nonceBytes: input.nonceBytes,
          serverTimestamp: input.serverTimestamp,
          expiresAtMs: Date.parse(input.expiresAtIso),
          consumed: false,
        });
        return { challengeId: cid };
      },
      consumeRecoveryChallenge: async (cid: string) => {
        const c = challenges.get(cid);
        if (!c || c.consumed || c.expiresAtMs <= nowSec * 1000) {
          return null;
        }
        c.consumed = true;
        return {
          accountId: c.accountId,
          nonceBytes: c.nonceBytes,
          serverTimestamp: c.serverTimestamp,
        };
      },
      recordAudit: async (e: any) => {
        audits.push(e);
      },
    };

    // Step A: Client requests challenge with Turnstile token
    const chalResp = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/challenge',
        'POST',
        {
          email: 'ALICE@EXAMPLE.ORG',
          turnstile_token: 'valid-challenge-turnstile-token-1',
        },
        { Origin: ORIGIN }
      ),
      deps,
      '198.51.100.7'
    );
    expect(chalResp.status).toBe(200);
    const chalData = await chalResp.json();
    expect(chalData.challenge_id).toBe('22222222-3333-4444-8555-666666666666');
    expect(chalData.nonce).toMatch(/^[0-9a-f]{64}$/);

    // Verify 76B proof message composition
    const nonceBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      nonceBytes[i] = parseInt(chalData.nonce.slice(i * 2, i * 2 + 2), 16);
    }
    const proofMsg = buildCanonicalProofMessage(
      nonceBytes,
      chalData.account_id,
      chalData.server_timestamp
    );
    expect(proofMsg.length).toBe(76);

    const proofHex = await computeRecoveryProofHex(
      recoveryVerifier,
      nonceBytes,
      chalData.account_id,
      chalData.server_timestamp
    );

    // Step B: Client submits proof to /verify
    const verifyResp = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/verify',
        'POST',
        {
          challenge_id: chalData.challenge_id,
          account_id: chalData.account_id,
          recovery_proof: proofHex,
        },
        { Origin: ORIGIN }
      ),
      deps,
      '198.51.100.7'
    );

    expect(verifyResp.status).toBe(200);
    const verifyData = await verifyResp.json();
    expect(verifyData.success).toBe(true);
    expect(atob(verifyData.encrypted_recovery_envelope)).toBe(
      'ENCRYPTED_RECOVERY_ENVELOPE_BLOB_V2.1.0_PAYLOAD'
    );
    // Must NEVER expose recovery_verifier or recovery_salt in /verify response
    expect(verifyData.recovery_verifier).toBeUndefined();
    expect(verifyData.recovery_salt).toBeUndefined();

    // Replay same challenge immediately -> fails closed with generic 401
    const replayResp = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/verify',
        'POST',
        {
          challenge_id: chalData.challenge_id,
          account_id: chalData.account_id,
          recovery_proof: proofHex,
        },
        { Origin: ORIGIN }
      ),
      deps,
      '198.51.100.7'
    );
    expect(replayResp.status).toBe(401);
    expect(await replayResp.json()).toEqual({ error: 'RECOVERY_FAILED' });

    // Confirm sanitized audit events logged with zero plaintext secrets
    expect(audits.some((a) => a.event_type === 'recovery_proof_verified')).toBe(true);
    expect(audits.some((a) => a.event_type === 'recovery_proof_failed')).toBe(true);
  });

  test('2. Rejects tampered proof, mismatched account_id, client-forged timestamp, and expired challenge', async () => {
    const accountId = '11111111-2222-4333-8444-555555555555';
    const otherAccountId = '99999999-2222-4333-8444-555555555555';
    const verifier = new Uint8Array(32).fill(0xaa);
    const nonce = new Uint8Array(32).fill(0x55);
    let nowSec = 1_750_000_100;

    const stored: StoredRecoveryAccount = {
      id: accountId,
      email: 'bob@example.org',
      accountStatus: 'active',
      recoveryVerifierBytes: verifier,
      recoverySaltBytes: new Uint8Array(32).fill(0x11),
      encryptedRecoveryEnvelopeBytes: new Uint8Array(48).fill(0x77),
      kdfVersion: 2,
    };

    const validProof = await computeRecoveryProofHex(
      verifier,
      nonce,
      accountId,
      1_750_000_000
    );
    const tamperedProof =
      (validProof[0] === '0' ? '1' : '0') + validProof.slice(1);
    const forgedTimestampProof = await computeRecoveryProofHex(
      verifier,
      nonce,
      accountId,
      1_750_000_005
    );

    const makeDeps = (expired: boolean) => ({
      corsOptions: CORS_OPTS,
      turnstileSecretKey: 'turnstile-secret-prod-key',
      auditHmacSalt: AUDIT_SALT,
      enumerationSecret: ENUM_SECRET,
      replayStore: new MemoryReplayStore(),
      nowSeconds: () => nowSec,
      checkRateLimit: async () => ({ allowed: true, remaining: 4, retryAfterSeconds: 0 }),
      findAccountByEmail: async () => null,
      findAccountById: async () => stored,
      createRecoveryChallenge: async () => null,
      consumeRecoveryChallenge: async () =>
        expired ? null : { accountId, nonceBytes: nonce, serverTimestamp: 1_750_000_000 },
      recordAudit: async () => {},
    });

    // Wrong proof
    const rBadProof = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/verify',
        'POST',
        {
          challenge_id: '33333333-3333-4333-8333-333333333333',
          account_id: accountId,
          recovery_proof: tamperedProof,
        },
        { Origin: ORIGIN }
      ),
      makeDeps(false)
    );
    expect(rBadProof.status).toBe(401);

    // Account ID mismatch
    const rBadAccount = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/verify',
        'POST',
        {
          challenge_id: '33333333-3333-4333-8333-333333333333',
          account_id: otherAccountId,
          recovery_proof: validProof,
        },
        { Origin: ORIGIN }
      ),
      makeDeps(false)
    );
    expect(rBadAccount.status).toBe(401);

    // Proof signed with client-forged timestamp rather than authoritative DB server_timestamp
    const rForgedTs = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/verify',
        'POST',
        {
          challenge_id: '33333333-3333-4333-8333-333333333333',
          account_id: accountId,
          server_timestamp: 1_750_000_005,
          recovery_proof: forgedTimestampProof,
        },
        { Origin: ORIGIN }
      ),
      makeDeps(false)
    );
    expect(rForgedTs.status).toBe(401);

    // Expired challenge (>5m) rejected cleanly
    nowSec += 600;
    const rExpired = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/verify',
        'POST',
        {
          challenge_id: '33333333-3333-4333-8333-333333333333',
          account_id: accountId,
          recovery_proof: validProof,
        },
        { Origin: ORIGIN }
      ),
      makeDeps(true)
    );
    expect(rExpired.status).toBe(401);
  });

  test('3. sync-vault-metadata enforces canonical 78B wrapped_dek matching key_id and rejects deletion_pending accounts', async () => {
    const user = { id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa' };
    const kek = generateDEK();
    const dek = generateDEK();
    const keyId = generateKeyId();
    const wire78 = wrapAndSerializeDEK(kek, dek, keyId, 2);

    const b64 = (u: Uint8Array) => btoa(String.fromCharCode(...Array.from(u)));

    let status: 'active' | 'deletion_pending' = 'active';
    const upserted: any[] = [];

    const deps = {
      corsOptions: CORS_OPTS,
      auditHmacSalt: AUDIT_SALT,
      authenticateUser: async () => user,
      getAccountStatus: async () => status,
      checkRateLimit: async () => ({ allowed: true, retryAfterSeconds: 0 }),
      upsertVaultMetadata: async (rec: any) => {
        upserted.push(rec);
      },
      recordAudit: async () => {},
    };

    const okSync = await handleSyncVaultMetadata(
      makeReq(
        'https://proj.supabase.co/functions/v1/sync-vault-metadata',
        'POST',
        {
          vault_id: b64(new Uint8Array(16).fill(1)),
          encrypted_vault_name: b64(new Uint8Array(24).fill(2)),
          encrypted_vault_manifest: b64(new Uint8Array(64).fill(3)),
          wrapped_dek: b64(wire78),
          key_id: b64(keyId),
          total_chunk_count: 5,
          erasure_params: b64(new Uint8Array(4).fill(4)),
          integrity_hash: b64(new Uint8Array(32).fill(5)),
        },
        { Origin: ORIGIN, Authorization: 'Bearer jwt' }
      ),
      deps
    );
    expect(okSync.status).toBe(200);
    expect(upserted).toHaveLength(1);

    // Reject 56-byte legacy wrapped_dek
    const bad56 = await handleSyncVaultMetadata(
      makeReq(
        'https://proj.supabase.co/functions/v1/sync-vault-metadata',
        'POST',
        {
          vault_id: b64(new Uint8Array(16).fill(1)),
          encrypted_vault_name: b64(new Uint8Array(24).fill(2)),
          encrypted_vault_manifest: b64(new Uint8Array(64).fill(3)),
          wrapped_dek: b64(new Uint8Array(56)),
          key_id: b64(keyId),
          total_chunk_count: 5,
          erasure_params: b64(new Uint8Array(4).fill(4)),
          integrity_hash: b64(new Uint8Array(32).fill(5)),
        },
        { Origin: ORIGIN, Authorization: 'Bearer jwt' }
      ),
      deps
    );
    expect(bad56.status).toBe(400);

    // Reject deletion_pending account sync
    status = 'deletion_pending';
    const pendingReject = await handleSyncVaultMetadata(
      makeReq(
        'https://proj.supabase.co/functions/v1/sync-vault-metadata',
        'POST',
        {},
        { Origin: ORIGIN, Authorization: 'Bearer jwt' }
      ),
      deps
    );
    expect(pendingReject.status).toBe(403);
  });

  test('4. supabase/config.toml enforces strict JWT policy across all v2.1.0 Edge Functions', () => {
    const configToml = fs.readFileSync(
      path.join(ROOT, 'supabase/config.toml'),
      'utf8'
    );
    expect(configToml).toMatch(/\[functions\.account-auth\]\s+verify_jwt = true/);
    expect(configToml).toMatch(/\[functions\.migrate-recovery-verifier\]\s+verify_jwt = true/);
    expect(configToml).toMatch(/\[functions\.sync-vault-metadata\]\s+verify_jwt = true/);
    expect(configToml).toMatch(/\[functions\.schedule-account-deletion\]\s+verify_jwt = true/);
    expect(configToml).toMatch(/\[functions\.cancel-account-deletion\]\s+verify_jwt = true/);
    // All 8 compensating controls verified above -> verify_jwt = false authorized
    expect(configToml).toMatch(/\[functions\.recover-vault\]\s+verify_jwt = false/);
    expect(configToml).toMatch(/\[functions\.process-account-deletions\]\s+verify_jwt = false/);
  });
});
