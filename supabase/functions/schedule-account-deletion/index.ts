// Ghost-Tag v2.1.0 - Account Deletion Scheduling Edge Function (48h Grace Period)

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { handleScheduleDeletion } from '../_shared/deletionHandlers.ts';
import {
  authenticateBearerUser,
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

  return handleScheduleDeletion(
    req,
    {
      corsOptions: getCorsOptionsFromEnv(),
      turnstileSecretKey: secrets.turnstileSecretKey,
      auditHmacSalt: secrets.auditHmacSalt,
      replayStore: createSupabaseReplayStore(adminClient),
      authenticateUser: authenticateBearerUser,
      checkRateLimit: createSupabaseRateLimiter(adminClient),
      async scheduleDeletionRpc(userId: string) {
        const { data, error } = await adminClient.rpc('schedule_account_deletion_rpc', {
          p_user_id: userId,
        });
        if (error || !Array.isArray(data) || data.length === 0) {
          throw new Error('DELETION_SCHEDULE_RPC_FAILED');
        }
        const row = data[0];
        return {
          requestId: row.request_id,
          scheduledAt: row.scheduled_at,
          expiresAt: row.expires_at,
          status: row.status,
        };
      },
      recordAudit: createSupabaseAuditRecorder(adminClient),
    },
    getClientIp(req)
  );
});
