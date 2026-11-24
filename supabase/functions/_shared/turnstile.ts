/**
 * Ghost-Tag v2.1.0 - Shared Cloudflare Turnstile CAPTCHA Verifier
 *
 * Security Invariants:
 * - Fail closed if CLOUDFLARE_TURNSTILE_SECRET_KEY is unset or empty.
 * - Fail closed on missing/short/oversized/malformed tokens.
 * - Fail closed on timeout (5000ms AbortController) or Cloudflare API outage.
 * - Defense-in-depth SHA-256 token digest replay guard backed by PostgreSQL
 *   turnstile_consumed_tokens table.
 * - Zero Deno-only imports so Jest can execute this module directly.
 */

export const TURNSTILE_VERIFY_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify';
export const TURNSTILE_TIMEOUT_MS = 5000;
export const MAX_TURNSTILE_TOKEN_LENGTH = 4096;
export const MIN_TURNSTILE_TOKEN_LENGTH = 10;

export interface TurnstileReplayStore {
  /**
   * Attempts to record a single-use token SHA-256 hash.
   * Must return true ONLY on fresh insert; false if already consumed or on error.
   */
  recordTokenUsage(
    tokenHashHex: string,
    action: string,
    expiresAtIso: string
  ): Promise<boolean>;
}

export interface TurnstileVerificationOptions {
  token: unknown;
  secretKey: string | undefined;
  expectedAction: string;
  remoteIp?: string;
  replayStore?: TurnstileReplayStore;
  fetchFn?: typeof fetch;
  timeoutMs?: number;
}

export interface TurnstileVerificationResult {
  valid: boolean;
  reason:
    | 'ok'
    | 'missing_secret_config'
    | 'missing_or_invalid_token'
    | 'token_replayed'
    | 'siteverify_rejected'
    | 'action_mismatch'
    | 'siteverify_timeout_or_error';
  tokenHashHex?: string;
}

/**
 * Computes lowercase 64-hex SHA-256 digest of a Turnstile response token.
 */
export async function sha256Hex(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verifies a Cloudflare Turnstile token fail-closed with 5s timeout and replay prevention.
 */
export async function verifyTurnstileToken(
  opts: TurnstileVerificationOptions
): Promise<TurnstileVerificationResult> {
  if (!opts.secretKey || opts.secretKey.trim().length < 8) {
    return { valid: false, reason: 'missing_secret_config' };
  }

  if (typeof opts.token !== 'string') {
    return { valid: false, reason: 'missing_or_invalid_token' };
  }

  const trimmedToken = opts.token.trim();
  if (
    trimmedToken.length < MIN_TURNSTILE_TOKEN_LENGTH ||
    trimmedToken.length > MAX_TURNSTILE_TOKEN_LENGTH
  ) {
    return { valid: false, reason: 'missing_or_invalid_token' };
  }

  const tokenHashHex = await sha256Hex(trimmedToken);

  const fetchImpl = opts.fetchFn ?? fetch;
  const timeoutMs = opts.timeoutMs ?? TURNSTILE_TIMEOUT_MS;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let siteVerifyData: {
    success?: boolean;
    action?: string;
    challenge_ts?: string;
  } | null = null;

  try {
    const formData = new URLSearchParams();
    formData.set('secret', opts.secretKey.trim());
    formData.set('response', trimmedToken);
    if (opts.remoteIp) {
      formData.set('remoteip', opts.remoteIp);
    }

    const resp = await fetchImpl(TURNSTILE_VERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: formData.toString(),
      signal: controller.signal,
    });

    if (!resp.ok) {
      return {
        valid: false,
        reason: 'siteverify_timeout_or_error',
        tokenHashHex,
      };
    }

    siteVerifyData = (await resp.json()) as {
      success?: boolean;
      action?: string;
      challenge_ts?: string;
    };
  } catch {
    return {
      valid: false,
      reason: 'siteverify_timeout_or_error',
      tokenHashHex,
    };
  } finally {
    clearTimeout(timer);
  }

  if (!siteVerifyData || siteVerifyData.success !== true) {
    return { valid: false, reason: 'siteverify_rejected', tokenHashHex };
  }

  if (
    siteVerifyData.action &&
    opts.expectedAction &&
    siteVerifyData.action !== opts.expectedAction
  ) {
    return { valid: false, reason: 'action_mismatch', tokenHashHex };
  }

  // Enforce local single-use replay guard if store provided (fail closed on duplicate/error)
  if (opts.replayStore) {
    const expiresAtIso = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    try {
      const recorded = await opts.replayStore.recordTokenUsage(
        tokenHashHex,
        opts.expectedAction,
        expiresAtIso
      );
      if (!recorded) {
        return { valid: false, reason: 'token_replayed', tokenHashHex };
      }
    } catch {
      return { valid: false, reason: 'token_replayed', tokenHashHex };
    }
  }

  return { valid: true, reason: 'ok', tokenHashHex };
}
