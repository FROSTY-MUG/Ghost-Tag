// Ghost-Tag v2.1.0 - Scheduled Account Purge Worker Edge Function
// Triggered every 15 minutes via pg_cron + pg_net with X-Ghost-Cron-Secret.

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { handleProcessDeletions } from '../_shared/deletionHandlers.ts';
import {
  createAdminSupabaseClient,
  createSupabaseAuditRecorder,
  getCorsOptionsFromEnv,
  getEnvSecrets,
} from '../_shared/supabaseEdgeRuntime.ts';

serve(async (req: Request) => {
  const secrets = getEnvSecrets();
  const adminClient = createAdminSupabaseClient();

  return handleProcessDeletions(req, {
    corsOptions: getCorsOptionsFromEnv(),
    cronSecret: secrets.deletionCronSecret,
    async claimExpiredRequests(batchSize: number) {
      const { data, error } = await adminClient.rpc('claim_expired_deletion_requests', {
        p_batch_size: batchSize,
      });
      if (error || !Array.isArray(data)) {
        return [];
      }
      return data.map((row: any) => ({
        requestId: row.request_id,
        userId: row.user_id,
        scheduledAt: row.scheduled_at,
        expiresAt: row.expires_at,
        purgeAttempts: Number(row.purge_attempts ?? 0),
      }));
    },
    async deleteRecoveryChallenges(userId: string) {
      const { error } = await adminClient
        .from('recovery_challenges')
        .delete()
        .eq('account_id', userId);
      if (error) throw new Error('CHALLENGE_PURGE_FAILED');
    },
    async deleteVaultMetadata(userId: string) {
      const { error } = await adminClient
        .from('vault_metadata')
        .delete()
        .eq('user_id', userId);
      if (error) throw new Error('METADATA_PURGE_FAILED');
    },
    async deleteProvisioningSalts(userId: string) {
      const { error } = await adminClient
        .from('account_provisioning_salts')
        .delete()
        .eq('user_id', userId);
      if (error) throw new Error('SALT_PURGE_FAILED');
    },
    async deleteAuthUser(userId: string) {
      const { error } = await adminClient.auth.admin.deleteUser(userId);
      if (!error) {
        return { ok: true };
      }
      const status = (error as { status?: number }).status;
      if (status === 404 || /not found/i.test(error.message || '')) {
        return { ok: true, notFound: true };
      }
      return { ok: false, errorCode: 'AUTH_DELETE_FAILED' };
    },
    async markCompleted(requestId: string) {
      const { error } = await adminClient
        .from('account_deletion_requests')
        .update({
          user_id: null,
          status: 'completed',
          completed_at: new Date().toISOString(),
          last_error_code: null,
        })
        .eq('id', requestId);
      if (error) throw new Error('REQUEST_COMPLETE_FAILED');
    },
    async scheduleRetry(input) {
      await adminClient
        .from('account_deletion_requests')
        .update({
          status: input.terminalManualReview ? 'failed_manual_review' : 'processing',
          purge_attempts: input.nextAttempts,
          next_retry_at: input.terminalManualReview ? null : input.nextRetryAtIso,
          last_error_code: input.errorCode,
        })
        .eq('id', input.requestId);
    },
    recordAudit: createSupabaseAuditRecorder(adminClient),
  });
});
