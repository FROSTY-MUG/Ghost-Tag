/**
 * Ghost-Tag v2.1.0 - Whitelisted Privacy-Preserving Audit Event Sanitizer
 *
 * Security Invariants:
 * - Zero raw IP addresses, zero email addresses, zero recovery phrases,
 *   zero keys/DEKs/verifiers/envelopes, zero JWTs, zero NFC UIDs in audit logs.
 * - Strict whitelist of event_type values and top-level details keys.
 * - Recursive inspection of nested objects and arrays (no shallow bypasses).
 * - Does NOT falsely reject benign diagnostic codes/actions containing
 *   substrings like "token", "key", or "metadata" (e.g., TURNSTILE_TOKEN_EXPIRED).
 * - Zero Deno-only imports so Jest can execute this module directly.
 */

export type AuditStatus = 'success' | 'failure' | 'blocked';

export const ALLOWED_EVENT_TYPES: ReadonlySet<string> = new Set([
  'account_provision_init',
  'account_provision_complete',
  'account_provision_blocked',
  'captcha_verification_passed',
  'captcha_verification_failed',
  'captcha_replay_blocked',
  'recovery_challenge_issued',
  'recovery_challenge_synthetic',
  'recovery_challenge_blocked',
  'recovery_proof_verified',
  'recovery_proof_failed',
  'recovery_proof_blocked',
  'recovery_migration_verified',
  'recovery_migration_failed',
  'vault_metadata_synced',
  'vault_metadata_sync_rejected',
  'account_deletion_scheduled',
  'account_deletion_cancelled',
  'account_deletion_purged',
  'account_deletion_retry_scheduled',
  'account_deletion_failed_manual_review',
  'rate_limit_blocked',
]);

export const ALLOWED_DETAILS_KEYS: ReadonlySet<string> = new Set([
  'error_code',
  'reason',
  'action',
  'challenge_outcome',
  'grace_hours',
  'kdf_version',
  'attempt_bucket',
  'http_status',
  'retry_attempt',
]);

export const FORBIDDEN_NESTED_KEYS: ReadonlySet<string> = new Set([
  'recovery_phrase',
  'phrase',
  'mnemonic',
  'passphrase',
  'password',
  'recovery_verifier',
  'recovery_auth_secret',
  'recovery_salt',
  'recovery_kek',
  'kek',
  'dek',
  'wrapped_dek',
  'encrypted_recovery_envelope',
  'raw_ip',
  'client_ip',
  'ip',
  'ip_address',
  'tag_uid',
  'uid',
  'email',
  'jwt',
  'access_token',
  'refresh_token',
  'service_role_key',
  'authorization',
  'cookie',
  'secret_key',
]);

export const MAX_AUDIT_DETAILS_BYTES = 4096;

const HEX64_RE = /^[0-9a-f]{64}$/;
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const IPV4_RE = /(?:^|[^0-9])(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}(?:$|[^0-9])/;
const IPV6_RE = /(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F:]{1,}/;
const JWT_RE = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;
const PEM_RE = /-----BEGIN\s/;
const EMAIL_VALUE_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const LONG_HEX_SECRET_RE = /(?:^|[^0-9a-fA-F])[0-9a-fA-F]{64,}(?:$|[^0-9a-fA-F])/;
const MNEMONIC_RE = /^[a-z]+(?:\s+[a-z]+){11,}$/;

export interface AuditEventInput {
  userId?: string | null;
  eventType: string;
  deviceFingerprintHash?: string | null;
  ipHash?: string | null;
  status: AuditStatus;
  details?: Record<string, unknown>;
}

export interface SanitizedAuditEventRecord {
  user_id: string | null;
  event_type: string;
  device_fingerprint_hash: string | null;
  ip_hash: string | null;
  status: AuditStatus;
  details: Record<string, unknown>;
}

function isSensitiveStringValue(value: string): string | null {
  const trimmed = value.trim();
  if (IPV4_RE.test(trimmed)) return 'raw IPv4 value';
  if (IPV6_RE.test(trimmed)) return 'raw IPv6 value';
  if (JWT_RE.test(trimmed)) return 'JWT bearer value';
  if (PEM_RE.test(trimmed)) return 'PEM key material';
  if (EMAIL_VALUE_RE.test(trimmed)) return 'raw email value';
  if (LONG_HEX_SECRET_RE.test(trimmed)) return '64+ hex secret value';
  if (MNEMONIC_RE.test(trimmed.toLowerCase())) return 'mnemonic phrase value';
  return null;
}

function inspectAuditValue(val: unknown, depth = 0): void {
  if (val === null || val === undefined) {
    return;
  }
  if (depth > 6) {
    throw new Error('AUDIT_SANITIZER_REJECTED: nested structure exceeds depth limit');
  }
  if (typeof val === 'boolean' || typeof val === 'number') {
    if (typeof val === 'number' && !Number.isFinite(val)) {
      throw new Error('AUDIT_SANITIZER_REJECTED: non-finite number');
    }
    return;
  }
  if (typeof val === 'string') {
    if (val.length > 512) {
      throw new Error('AUDIT_SANITIZER_REJECTED: string value exceeds 512 chars');
    }
    const violation = isSensitiveStringValue(val);
    if (violation) {
      throw new Error(`AUDIT_SANITIZER_REJECTED: ${violation}`);
    }
    return;
  }
  if (Array.isArray(val)) {
    for (const elem of val) {
      inspectAuditValue(elem, depth + 1);
    }
    return;
  }
  if (typeof val === 'object') {
    for (const [k, child] of Object.entries(val as Record<string, unknown>)) {
      if (FORBIDDEN_NESTED_KEYS.has(k.toLowerCase())) {
        throw new Error(`AUDIT_SANITIZER_REJECTED: forbidden nested key "${k}"`);
      }
      inspectAuditValue(child, depth + 1);
    }
    return;
  }
  throw new Error('AUDIT_SANITIZER_REJECTED: unsupported details value type');
}

/**
 * Validates and constructs a PostgreSQL-ready sanitized audit record.
 * Throws explicitly on any policy violation (fail closed).
 */
export function sanitizeAuditEvent(
  input: AuditEventInput
): SanitizedAuditEventRecord {
  if (!ALLOWED_EVENT_TYPES.has(input.eventType)) {
    throw new Error(`AUDIT_SANITIZER_REJECTED: disallowed event_type "${input.eventType}"`);
  }

  if (
    input.status !== 'success' &&
    input.status !== 'failure' &&
    input.status !== 'blocked'
  ) {
    throw new Error('AUDIT_SANITIZER_REJECTED: invalid status');
  }

  let normalizedUserId: string | null = null;
  if (input.userId !== undefined && input.userId !== null) {
    if (!UUID_RE.test(input.userId)) {
      throw new Error('AUDIT_SANITIZER_REJECTED: invalid user_id UUID');
    }
    normalizedUserId = input.userId.toLowerCase();
  }

  let normalizedFp: string | null = null;
  if (
    input.deviceFingerprintHash !== undefined &&
    input.deviceFingerprintHash !== null
  ) {
    const fp = input.deviceFingerprintHash.trim().toLowerCase();
    if (!HEX64_RE.test(fp)) {
      throw new Error('AUDIT_SANITIZER_REJECTED: deviceFingerprintHash must be 64 lowercase hex');
    }
    normalizedFp = fp;
  }

  let normalizedIpHash: string | null = null;
  if (input.ipHash !== undefined && input.ipHash !== null) {
    const ih = input.ipHash.trim().toLowerCase();
    if (!HEX64_RE.test(ih)) {
      throw new Error('AUDIT_SANITIZER_REJECTED: ipHash must be 64 lowercase hex');
    }
    normalizedIpHash = ih;
  }

  const sanitizedDetails: Record<string, unknown> = {};
  const rawDetails = input.details ?? {};
  if (
    typeof rawDetails !== 'object' ||
    rawDetails === null ||
    Array.isArray(rawDetails)
  ) {
    throw new Error('AUDIT_SANITIZER_REJECTED: details must be a plain object');
  }

  for (const [key, value] of Object.entries(rawDetails)) {
    if (!ALLOWED_DETAILS_KEYS.has(key)) {
      throw new Error(`AUDIT_SANITIZER_REJECTED: disallowed details key "${key}"`);
    }
    if (value !== undefined) {
      inspectAuditValue(value, 1);
      sanitizedDetails[key] = value;
    }
  }

  const encodedBytes = new TextEncoder().encode(
    JSON.stringify(sanitizedDetails)
  ).byteLength;
  if (encodedBytes > MAX_AUDIT_DETAILS_BYTES) {
    throw new Error(
      `AUDIT_SANITIZER_REJECTED: details exceeds ${MAX_AUDIT_DETAILS_BYTES} bytes`
    );
  }

  return {
    user_id: normalizedUserId,
    event_type: input.eventType,
    device_fingerprint_hash: normalizedFp,
    ip_hash: normalizedIpHash,
    status: input.status,
    details: sanitizedDetails,
  };
}

/**
 * Derives a keyed 64-hex HMAC-SHA256 identifier hash (e.g., for ip_hash or device_fingerprint_hash).
 * Never emits reversible identifiers or unsalted hashes.
 */
export async function hashAuditIdentifier(
  rawIdentifier: string,
  hmacSalt: string
): Promise<string> {
  if (!hmacSalt || hmacSalt.length < 16) {
    throw new Error('AUDIT_HASH_FAILED: HMAC salt must be at least 16 characters');
  }
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(hmacSalt),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign(
    'HMAC',
    key,
    enc.encode(rawIdentifier.trim())
  );
  return Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
