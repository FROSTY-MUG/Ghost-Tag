// Ghost-Tag v2.1.0 - Authenticated Vault Metadata Sync Edge Function

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { handleSyncVaultMetadata } from '../_shared/syncMetadataHandler.ts';
import {
  authenticateBearerUser,
  bytesToPgBytea,
  createAdminSupabaseClient,
  createSupabaseAuditRecorder,
  createSupabaseRateLimiter,
  getClientIp,
  getCorsOptionsFromEnv,
  getEnvSecrets,
} from '../_shared/supabaseEdgeRuntime.ts';

serve(async (req: Request) => {
  const secrets = getEnvSecrets();
  const adminClient = createAdminSupabaseClient();

  return handleSyncVaultMetadata(
    req,
    {
      corsOptions: getCorsOptionsFromEnv(),
      auditHmacSalt: secrets.auditHmacSalt,
      authenticateUser: authenticateBearerUser,
      async getAccountStatus(userId: string) {
        const { data, error } = await adminClient
          .from('user_accounts')
          .select('account_status')
          .eq('id', userId)
          .maybeSingle();
        if (error || !data) return null;
        return data.account_status;
      },
      checkRateLimit: createSupabaseRateLimiter(adminClient),
      async upsertVaultMetadata(record) {
        const { error } = await adminClient.from('vault_metadata').upsert(
          {
            user_id: record.userId,
            vault_id: bytesToPgBytea(record.vaultIdBytes),
            encrypted_vault_name: bytesToPgBytea(record.encryptedVaultNameBytes),
            encrypted_vault_manifest: bytesToPgBytea(record.encryptedVaultManifestBytes),
            wrapped_dek: bytesToPgBytea(record.wrappedDekBytes),
            key_id: bytesToPgBytea(record.keyIdBytes),
            total_chunk_count: record.totalChunkCount,
            erasure_params: bytesToPgBytea(record.erasureParamsBytes),
            integrity_hash: bytesToPgBytea(record.integrityHashBytes),
            updated_at: new Date().toISOString(),
          },
          { onConflict: 'user_id,vault_id' }
        );
        if (error) {
          throw new Error('VAULT_METADATA_UPSERT_FAILED');
        }
      },
      recordAudit: createSupabaseAuditRecorder(adminClient),
    },
    getClientIp(req)
  );
});
