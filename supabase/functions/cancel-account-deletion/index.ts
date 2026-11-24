// Ghost-Tag v2.1.0 - Cancel Account Deletion Grace-Period Edge Function

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { handleCancelDeletion } from '../_shared/deletionHandlers.ts';
import {
  authenticateBearerUser,
  createAdminSupabaseClient,
  createSupabaseAuditRecorder,
  getClientIp,
  getCorsOptionsFromEnv,
  getEnvSecrets,
} from '../_shared/supabaseEdgeRuntime.ts';

serve(async (req: Request) => {
  const secrets = getEnvSecrets();
  const adminClient = createAdminSupabaseClient();

  return handleCancelDeletion(
    req,
    {
      corsOptions: getCorsOptionsFromEnv(),
      auditHmacSalt: secrets.auditHmacSalt,
      authenticateUser: authenticateBearerUser,
      async cancelDeletionRpc(userId: string) {
        const { data, error } = await adminClient.rpc('cancel_account_deletion_rpc', {
          p_user_id: userId,
        });
        return !error && data === true;
      },
      recordAudit: createSupabaseAuditRecorder(adminClient),
    },
    getClientIp(req)
  );
});
