/**
 * Ghost-Tag v2.1.0 - Shared Deno / Supabase Edge Runtime Adapter
 *
 * Centralizes CORS env extraction, trusted proxy header extraction,
 * Supabase Auth JWT user lookup (no service-role signup), Turnstile replay
 * storage, check_rate_limit RPC calls, and sanitized audit logging.
 */

import { createClient, SupabaseClient } from 'https://esm.sh/@supabase/supabase-js@2.39.8';
import { sanitizeAuditEvent } from './audit.ts';
import { CorsPolicyOptions } from './cors.ts';
import { bytesToHex, pgByteaToBytes } from './recoveryCrypto.ts';
import { TurnstileReplayStore } from './turnstile.ts';

declare const Deno: {
  env: { get(name: string): string | undefined };
};

export function getCorsOptionsFromEnv(): CorsPolicyOptions {
  return {
    environment: Deno.env.get('GHOST_ENV') ?? 'production',
    allowLocalhostCors: Deno.env.get('ALLOW_LOCALHOST_CORS') === 'true',
    approvedProductionOrigins: Deno.env.get('APPROVED_CORS_ORIGINS') ?? '',
  };
}

export function getEnvSecrets() {
  return {
    supabaseUrl: Deno.env.get('SUPABASE_URL') ?? '',
    supabaseAnonKey: Deno.env.get('SUPABASE_ANON_KEY') ?? '',
    supabaseServiceKey: Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? '',
    turnstileSecretKey: Deno.env.get('CLOUDFLARE_TURNSTILE_SECRET_KEY'),
    auditHmacSalt: Deno.env.get('AUDIT_HMAC_SALT') ?? Deno.env.get('IP_HASH_SALT'),
    enumerationSecret: Deno.env.get('SERVER_ENUMERATION_SECRET'),
    deletionCronSecret: Deno.env.get('DELETION_WORKER_CRON_SECRET'),
  };
}

export function getClientIp(req: Request): string {
  const cfIp = req.headers.get('cf-connecting-ip');
  if (cfIp) return cfIp.trim();
  const realIp = req.headers.get('x-real-ip');
  if (realIp) return realIp.trim();
  const forwarded = req.headers.get('x-forwarded-for');
  if (forwarded) {
    const first = forwarded
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)[0];
    if (first) return first;
  }
  return '127.0.0.1';
}

export function createAdminSupabaseClient(): SupabaseClient {
  const { supabaseUrl, supabaseServiceKey } = getEnvSecrets();
  if (!supabaseUrl || !supabaseServiceKey) {
    throw new Error('SUPABASE_ENV_MISSING');
  }
  return createClient(supabaseUrl, supabaseServiceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

export async function authenticateBearerUser(
  authHeader: string | null
): Promise<{ id: string; email: string } | null> {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const { supabaseUrl, supabaseAnonKey } = getEnvSecrets();
  const token = authHeader.slice('Bearer '.length).trim();
  if (!supabaseUrl || !supabaseAnonKey || !token || token === supabaseAnonKey) {
    return null;
  }
  try {
    const authClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
      auth: { persistSession: false, autoRefreshToken: false },
    });
    const {
      data: { user },
      error,
    } = await authClient.auth.getUser();
    if (error || !user || !user.id || !user.email) {
      return null;
    }
    return { id: user.id, email: user.email };
  } catch {
    return null;
  }
}

export function createSupabaseReplayStore(
  adminClient: SupabaseClient
): TurnstileReplayStore {
  return {
    async recordTokenUsage(
      tokenHashHex: string,
      action: string,
      expiresAtIso: string
    ): Promise<boolean> {
      const { error } = await adminClient
        .from('turnstile_consumed_tokens')
        .insert({
          token_hash: tokenHashHex,
          action,
          expires_at: expiresAtIso,
        });
      return !error;
    },
  };
}

export function createSupabaseRateLimiter(adminClient: SupabaseClient) {
  return async function checkRateLimit(
    bucketKey: string,
    action: string
  ): Promise<{ allowed: boolean; remaining: number; retryAfterSeconds: number }> {
    const { data, error } = await adminClient.rpc('check_rate_limit', {
      p_bucket_key: bucketKey,
      p_action: action,
    });
    if (error || !Array.isArray(data) || data.length === 0) {
      // Fail closed cleanly
      return { allowed: false, remaining: 0, retryAfterSeconds: 3600 };
    }
    const row = data[0] as {
      allowed?: boolean;
      remaining?: number;
      retry_after_seconds?: number;
    };
    return {
      allowed: row.allowed === true,
      remaining: typeof row.remaining === 'number' ? row.remaining : 0,
      retryAfterSeconds:
        typeof row.retry_after_seconds === 'number' ? row.retry_after_seconds : 3600,
    };
  };
}

export function createSupabaseAuditRecorder(adminClient: SupabaseClient) {
  return async function recordAudit(
    event: ReturnType<typeof sanitizeAuditEvent>
  ): Promise<void> {
    await adminClient.from('audit_events').insert(event);
  };
}

export function bytesToPgBytea(bytes: Uint8Array): string {
  return `\\x${bytesToHex(bytes)}`;
}

export function decodePgBytea(value: string | Uint8Array): Uint8Array {
  return pgByteaToBytes(value);
}
