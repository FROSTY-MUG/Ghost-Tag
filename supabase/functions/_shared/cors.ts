/**
 * Ghost-Tag v2.1.0 - Shared Strict CORS Allowlist Policy
 *
 * Security Invariants:
 * - Never emits Access-Control-Allow-Origin: *
 * - Never reflects arbitrary Origin headers
 * - Restricts production requests strictly to https://frosty-mug.github.io
 *   plus explicitly approved HTTPS domains via APPROVED_CORS_ORIGINS
 * - Permits http://localhost:<port> and http://127.0.0.1:<port> ONLY when
 *   explicitly running in development mode (GHOST_ENV=development or ALLOW_LOCALHOST_CORS=true)
 * - Always emits Vary: Origin
 */

export const PRODUCTION_ALLOWED_ORIGINS: readonly string[] = [
  'https://frosty-mug.github.io',
];

export interface CorsPolicyOptions {
  environment?: string;
  allowLocalhostCors?: boolean;
  approvedProductionOrigins?: string | readonly string[];
}

export interface CorsEvaluationResult {
  allowed: boolean;
  origin: string | null;
  headers: Record<string, string>;
}

/**
 * Validates and normalizes an approved HTTPS production origin.
 * Rejects wildcards (*), non-HTTPS origins, credentials, paths, or query strings.
 */
export function parseApprovedProductionOrigins(
  extra?: string | readonly string[]
): Set<string> {
  const allowed = new Set<string>(PRODUCTION_ALLOWED_ORIGINS);
  if (!extra) {
    return allowed;
  }

  const rawList = Array.isArray(extra)
    ? extra
    : String(extra).split(',');

  for (const item of rawList) {
    const trimmed = String(item).trim();
    if (!trimmed || trimmed === '*' || trimmed.includes('*')) {
      continue;
    }
    try {
      const parsed = new URL(trimmed);
      if (
        parsed.protocol === 'https:' &&
        !parsed.username &&
        !parsed.password &&
        (parsed.pathname === '' || parsed.pathname === '/') &&
        !parsed.search &&
        !parsed.hash &&
        parsed.origin === trimmed
      ) {
        allowed.add(parsed.origin);
      }
    } catch {
      // Ignore malformed origin entries (fail closed)
    }
  }

  return allowed;
}

/**
 * Validates a development-only loopback HTTP origin:
 * strictly http://localhost:<1-65535> or http://127.0.0.1:<1-65535>.
 * Never matches arbitrary hosts, subdomains, credentials, or paths.
 */
export function isValidLoopbackOrigin(origin: string): boolean {
  if (!origin || typeof origin !== 'string') {
    return false;
  }
  try {
    const parsed = new URL(origin);
    if (
      parsed.protocol !== 'http:' ||
      parsed.username ||
      parsed.password ||
      (parsed.pathname !== '' && parsed.pathname !== '/') ||
      parsed.search ||
      parsed.hash ||
      parsed.origin !== origin
    ) {
      return false;
    }
    if (parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
      return false;
    }
    if (!parsed.port) {
      return false;
    }
    const portNum = Number(parsed.port);
    return Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535;
  } catch {
    return false;
  }
}

/**
 * Checks whether an Origin header is permitted by the strict Ghost-Tag allowlist.
 * Note: Absence of an Origin header (non-browser native mobile/CLI client) is
 * handled separately by the caller; if Origin IS present, null/empty/* is denied.
 */
export function isAllowedCorsOrigin(
  origin: string | null | undefined,
  options: CorsPolicyOptions = {}
): boolean {
  if (!origin || typeof origin !== 'string') {
    return false;
  }
  const trimmed = origin.trim();
  if (!trimmed || trimmed === '*' || trimmed === 'null') {
    return false;
  }

  const productionSet = parseApprovedProductionOrigins(
    options.approvedProductionOrigins
  );
  if (productionSet.has(trimmed)) {
    return true;
  }

  const isDevMode =
    options.allowLocalhostCors === true ||
    options.environment === 'development';

  if (isDevMode && isValidLoopbackOrigin(trimmed)) {
    return true;
  }

  return false;
}

/**
 * Evaluates a request Origin header and constructs deterministic CORS response headers.
 * Never sets Access-Control-Allow-Origin to "*" or to unapproved origins.
 */
export function evaluateCorsRequest(
  origin: string | null | undefined,
  options: CorsPolicyOptions = {},
  allowedMethods = 'POST, OPTIONS',
  allowedHeaders = 'authorization, x-client-info, apikey, content-type, x-ghost-turnstile-token'
): CorsEvaluationResult {
  const baseHeaders: Record<string, string> = {
    'Access-Control-Allow-Methods': allowedMethods,
    'Access-Control-Allow-Headers': allowedHeaders,
    Vary: 'Origin',
  };

  // Non-browser native clients omit Origin
  if (origin === null || origin === undefined) {
    return {
      allowed: true,
      origin: null,
      headers: baseHeaders,
    };
  }

  const trimmed = String(origin).trim();
  if (!isAllowedCorsOrigin(trimmed, options)) {
    return {
      allowed: false,
      origin: null,
      headers: {
        Vary: 'Origin',
      },
    };
  }

  return {
    allowed: true,
    origin: trimmed,
    headers: {
      ...baseHeaders,
      'Access-Control-Allow-Origin': trimmed,
    },
  };
}
