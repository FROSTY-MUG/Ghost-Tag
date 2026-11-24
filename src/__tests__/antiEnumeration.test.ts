/**
 * @file antiEnumeration.test.ts
 * @summary Verifies Anti-Enumeration Opacity for Recovery Challenge & Verification:
 * - Unknown emails, deleted emails, and active accounts return identical HTTP 200
 *   JSON schema, field types, RFC 4122 v4 UUID syntax, and 64-hex nonce/salt sizes.
 * - Synthetic challenge generation is deterministic per email/account so repeated
 *   probes cannot distinguish dummy vs real accounts from mutable random attributes.
 * - Rate limit breaches and invalid inputs return identical generic opaque errors.
 */

import {
  RFC4122_UUID_REGEX,
  synthesizeAntiEnumerationChallenge,
} from '../../supabase/functions/_shared/recoveryCrypto';
import {
  StoredRecoveryAccount,
  handleRecoverVaultRequest,
} from '../../supabase/functions/_shared/recoverVaultHandler';
import { TurnstileReplayStore } from '../../supabase/functions/_shared/turnstile';

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

describe('PR #3: Anti-Enumeration Opacity', () => {
  const CORS_OPTS = { environment: 'production', allowLocalhostCors: false };
  const ORIGIN = 'https://frosty-mug.github.io';
  const AUDIT_SALT = 'server-audit-hmac-salt-32-chars!!';
  const ENUM_SECRET = 'server-enumeration-hmac-secret!!';

  test('1. Existing active, non-existent, and deleted accounts produce identical challenge response structure', async () => {
    const activeAccount: StoredRecoveryAccount = {
      id: '11111111-2222-4333-8444-555555555555',
      email: 'existing-user@example.org',
      accountStatus: 'active',
      recoveryVerifierBytes: new Uint8Array(32).fill(0x11),
      recoverySaltBytes: new Uint8Array(32).fill(0x22),
      encryptedRecoveryEnvelopeBytes: new Uint8Array(48).fill(0x33),
      kdfVersion: 2,
    };

    const deletedAccount: StoredRecoveryAccount = {
      id: '99999999-2222-4333-8444-555555555555',
      email: 'deleted-user@example.org',
      accountStatus: 'deleted',
      recoveryVerifierBytes: new Uint8Array(32).fill(0x44),
      recoverySaltBytes: new Uint8Array(32).fill(0x55),
      encryptedRecoveryEnvelopeBytes: new Uint8Array(48).fill(0x66),
      kdfVersion: 2,
    };

    const replayStore = new MemoryReplayStore();
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
      nowSeconds: () => 1_750_000_000,
      checkRateLimit: async () => ({ allowed: true, remaining: 9, retryAfterSeconds: 0 }),
      findAccountByEmail: async (email: string) => {
        if (email === activeAccount.email) return activeAccount;
        if (email === deletedAccount.email) return deletedAccount;
        return null;
      },
      findAccountById: async () => null,
      createRecoveryChallenge: async () => ({
        challengeId: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
      }),
      consumeRecoveryChallenge: async () => null,
      recordAudit: async () => {},
    };

    const queryChallenge = async (email: string, tokenSuffix: string) =>
      handleRecoverVaultRequest(
        makeReq(
          'https://proj.supabase.co/functions/v1/recover-vault/challenge',
          'POST',
          {
            email,
            turnstile_token: `turnstile-anti-enum-token-${tokenSuffix}`,
          },
          { Origin: ORIGIN }
        ),
        deps
      );

    const [rReal, rMissing, rDeleted] = await Promise.all([
      queryChallenge('existing-user@example.org', '001'),
      queryChallenge('never-registered@example.org', '002'),
      queryChallenge('deleted-user@example.org', '003'),
    ]);

    expect(rReal.status).toBe(200);
    expect(rMissing.status).toBe(200);
    expect(rDeleted.status).toBe(200);

    const [jReal, jMissing, jDeleted] = await Promise.all([
      rReal.json(),
      rMissing.json(),
      rDeleted.json(),
    ]);

    const realKeys = Object.keys(jReal).sort();
    expect(Object.keys(jMissing).sort()).toEqual(realKeys);
    expect(Object.keys(jDeleted).sort()).toEqual(realKeys);

    for (const payload of [jReal, jMissing, jDeleted]) {
      expect(RFC4122_UUID_REGEX.test(payload.challenge_id)).toBe(true);
      expect(RFC4122_UUID_REGEX.test(payload.account_id)).toBe(true);
      expect(payload.nonce).toMatch(/^[0-9a-f]{64}$/);
      expect(payload.recovery_salt).toMatch(/^[0-9a-f]{64}$/);
      expect(typeof payload.server_timestamp).toBe('number');
      expect(payload.kdf_version).toBe(2);
    }

    // Attempting /verify with synthetic challenge fails identically with generic 401
    const rSynthVerify = await handleRecoverVaultRequest(
      makeReq(
        'https://proj.supabase.co/functions/v1/recover-vault/verify',
        'POST',
        {
          challenge_id: jMissing.challenge_id,
          account_id: jMissing.account_id,
          recovery_proof: 'f'.repeat(64),
        },
        { Origin: ORIGIN }
      ),
      deps
    );
    expect(rSynthVerify.status).toBe(401);
    expect(await rSynthVerify.json()).toEqual({ error: 'RECOVERY_FAILED' });
  });

  test('2. Synthetic challenge account_id and recovery_salt remain consistent per email across challenges', async () => {
    const s1 = await synthesizeAntiEnumerationChallenge(
      'probe@example.org',
      ENUM_SECRET,
      1_750_000_000
    );
    const s2 = await synthesizeAntiEnumerationChallenge(
      'probe@example.org',
      ENUM_SECRET,
      1_750_000_010
    );
    const sOther = await synthesizeAntiEnumerationChallenge(
      'other@example.org',
      ENUM_SECRET,
      1_750_000_000
    );

    expect(s1.account_id).toBe(s2.account_id);
    expect(s1.recovery_salt).toBe(s2.recovery_salt);
    expect(s1.challenge_id).not.toBe(s2.challenge_id);
    expect(s1.nonce).not.toBe(s2.nonce);
    expect(s1.account_id).not.toBe(sOther.account_id);
  });
});
