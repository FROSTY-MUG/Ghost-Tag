// Ghost-Tag v2.1.0 - Cloudflare Turnstile Verification Edge Function

import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';
import { handleVerifyCaptcha } from '../_shared/verifyCaptchaHandler.ts';
import {
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

  return handleVerifyCaptcha(
    req,
    {
      corsOptions: getCorsOptionsFromEnv(),
      turnstileSecretKey: secrets.turnstileSecretKey,
      auditHmacSalt: secrets.auditHmacSalt,
      replayStore: createSupabaseReplayStore(adminClient),
      checkRateLimit: createSupabaseRateLimiter(adminClient),
      recordAudit: createSupabaseAuditRecorder(adminClient),
    },
    getClientIp(req)
  );
});
