// Ghost-Tag v2.1.0 - Account Provisioning Edge Function (init / complete)
// Delegates identity/passwords/sessions strictly to Supabase Auth;
// never receives passwords and never calls auth.admin.createUser.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { handleAccountAuthRequest } from '../_shared/accountAuthHandler.ts';
import { bytesToHex, pgByteaToBytes } from '../_shared/recoveryCrypto.ts';
import {
  authenticateBearerUser,
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

  return handleAccountAuthRequest(
    req,
    {
      corsOptions: getCorsOptionsFromEnv(),
      turnstileSecretKey: secrets.turnstileSecretKey,
      auditHmacSalt: secrets.auditHmacSalt,
      replayStore: createSupabaseReplayStore(adminClient),
      authenticateUser: authenticateBearerUser,
      checkRateLimit: createSupabaseRateLimiter(adminClient),
      async hasAccountForUserOrEmail(userId: string, normalizedEmail: string) {
        const { data } = await adminClient
          .from('user_accounts')
          .select('id')
          .or(`id.eq.${userId},email.eq.${normalizedEmail}`)
          .limit(1);
        return Array.isArray(data) && data.length > 0;
      },
      async upsertProvisioningSalt(record) {
        const saltBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
          saltBytes[i] = parseInt(record.recoverySaltHex.slice(i * 2, i * 2 + 2), 16);
        }
        await adminClient.from('account_provisioning_salts').upsert({
          user_id: record.userId,
          email: record.email,
          recovery_salt: bytesToPgBytea(saltBytes),
          expires_at: record.expiresAtIso,
        });
      },
      async consumeProvisioningSalt(userId: string, normalizedEmail: string) {
        const { data, error } = await adminClient
          .from('account_provisioning_salts')
          .delete()
          .eq('user_id', userId)
          .eq('email', normalizedEmail)
          .gt('expires_at', new Date().toISOString())
          .select('user_id, email, recovery_salt, expires_at')
          .maybeSingle();

        if (error || !data) {
          return null;
        }
        return {
          userId: data.user_id,
          email: data.email,
          recoverySaltHex: bytesToHex(pgByteaToBytes(data.recovery_salt)),
          expiresAtIso: data.expires_at,
        };
      },
      async insertUserAccount(record) {
        const { error } = await adminClient.from('user_accounts').insert({
          id: record.userId,
          email: record.email,
          recovery_verifier: bytesToPgBytea(record.recoveryVerifierBytes),
          recovery_salt: bytesToPgBytea(record.recoverySaltBytes),
          encrypted_recovery_envelope: bytesToPgBytea(record.encryptedRecoveryEnvelopeBytes),
          recovery_kdf_version: record.kdfVersion,
          account_status: 'active',
        });
        if (!error) {
          return { ok: true };
        }
        return { ok: false, conflict: error.code === '23505' };
      },
      recordAudit: createSupabaseAuditRecorder(adminClient),
    },
    getClientIp(req)
  );
});
