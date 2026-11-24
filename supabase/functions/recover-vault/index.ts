// Ghost-Tag v2.1.0 - Zero-Session Challenge/Proof Vault Recovery Edge Function
// Protected by all 8 compensating controls (Turnstile challenge guard,
// partitioned recovery_challenge/recovery_proof rate limits, anti-enumeration synthesis,
// strict schema validation, generic errors, atomic replay guard, and audit logging).

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { handleRecoverVaultRequest } from '../_shared/recoverVaultHandler.ts';
import { pgByteaToBytes } from '../_shared/recoveryCrypto.ts';
import {
  bytesToPgBytea,
  createAdminSupabaseClient,
  createSupabaseAuditRecorder,
  createSupabaseRateLimiter,
  createSupabaseReplayStore,
  getClientIp,
  getCorsOptionsFromEnv,
  getEnvSecrets,
} from '../_shared/supabaseEdgeRuntime.ts';

serve(async (req: Request) => {
  const secrets = getEnvSecrets();
  const adminClient = createAdminSupabaseClient();

  return handleRecoverVaultRequest(
    req,
    {
      corsOptions: getCorsOptionsFromEnv(),
      turnstileSecretKey: secrets.turnstileSecretKey,
      auditHmacSalt: secrets.auditHmacSalt,
      enumerationSecret: secrets.enumerationSecret,
      replayStore: createSupabaseReplayStore(adminClient),
      checkRateLimit: createSupabaseRateLimiter(adminClient),
      async findAccountByEmail(normalizedEmail: string) {
        const { data, error } = await adminClient
          .from('user_accounts')
          .select(
            'id, email, account_status, recovery_verifier, recovery_salt, encrypted_recovery_envelope, recovery_kdf_version'
          )
          .eq('email', normalizedEmail)
          .maybeSingle();

        if (error || !data) return null;
        return {
          id: data.id,
          email: data.email,
          accountStatus: data.account_status,
          recoveryVerifierBytes: pgByteaToBytes(data.recovery_verifier),
          recoverySaltBytes: pgByteaToBytes(data.recovery_salt),
          encryptedRecoveryEnvelopeBytes: pgByteaToBytes(data.encrypted_recovery_envelope),
          kdfVersion: data.recovery_kdf_version,
        };
      },
      async findAccountById(accountId: string) {
        const { data, error } = await adminClient
          .from('user_accounts')
          .select(
            'id, email, account_status, recovery_verifier, recovery_salt, encrypted_recovery_envelope, recovery_kdf_version'
          )
          .eq('id', accountId)
          .maybeSingle();

        if (error || !data) return null;
        return {
          id: data.id,
          email: data.email,
          accountStatus: data.account_status,
          recoveryVerifierBytes: pgByteaToBytes(data.recovery_verifier),
          recoverySaltBytes: pgByteaToBytes(data.recovery_salt),
          encryptedRecoveryEnvelopeBytes: pgByteaToBytes(data.encrypted_recovery_envelope),
          kdfVersion: data.recovery_kdf_version,
        };
      },
      async createRecoveryChallenge(input) {
        const { data, error } = await adminClient
          .from('recovery_challenges')
          .insert({
            account_id: input.accountId,
            nonce: bytesToPgBytea(input.nonceBytes),
            server_timestamp: input.serverTimestamp,
            expires_at: input.expiresAtIso,
            consumed: false,
          })
          .select('id')
          .single();

        if (error || !data?.id) return null;
        return { challengeId: data.id };
      },
      async consumeRecoveryChallenge(challengeId: string) {
        const { data, error } = await adminClient.rpc('consume_recovery_challenge', {
          p_challenge_id: challengeId,
        });
        if (error || !Array.isArray(data) || data.length === 0) {
          return null;
        }
        const row = data[0];
        return {
          accountId: row.account_id,
          nonceBytes: pgByteaToBytes(row.nonce),
          serverTimestamp: Number(row.server_timestamp),
        };
      },
      recordAudit: createSupabaseAuditRecorder(adminClient),
    },
    getClientIp(req)
  );
});
