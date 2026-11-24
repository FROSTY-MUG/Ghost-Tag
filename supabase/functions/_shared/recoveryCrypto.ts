/**
 * Ghost-Tag v2.1.0 - Zero-Knowledge Recovery Proof Cryptography & Anti-Enumeration Helpers
 *
 * Implements Corrected Recovery Architecture:
 *   Stage 1 (Client): recovery_auth_secret = Argon2id("ghost-recovery-auth-v2.1.0:" || normalized_phrase, recovery_salt)
 *   Stage 2 (Client): recovery_verifier    = Argon2id(hex(recovery_auth_secret), SHA256("ghost-verifier-salt-v2.1.0"))
 *   Challenge Proof : recovery_proof       = HMAC-SHA256(recovery_verifier, nonce(32B) || utf8(lower(account_id))(36B) || uint64_be(server_timestamp)(8B))
 *
 * Notice the server stores ONLY recovery_salt (32B CSPRNG), recovery_verifier (32B),
 * and encrypted_recovery_envelope (BYTEA) — never recovery_auth_secret or BIP-39 words.
 * Zero Deno-only imports so Jest executes this exact implementation directly.
 */

export const RECOVERY_AUTH_DOMAIN = 'ghost-recovery-auth-v2.1.0:';
export const VERIFIER_SALT_DOMAIN = 'ghost-verifier-salt-v2.1.0';
export const RECOVERY_CHALLENGE_TTL_SECONDS = 300;
export const PROVISION_SALT_TTL_SECONDS = 900;

export const RFC4122_UUID_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const HEX64_REGEX = /^[0-9a-fA-F]{64}$/;
export const EMAIL_REGEX = /^[^\s@]{1,64}@[^\s@]{1,255}$/;

export function normalizeEmail(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const cleaned = raw.trim().toLowerCase();
  if (cleaned.length < 3 || cleaned.length > 320 || !EMAIL_REGEX.test(cleaned)) {
    return null;
  }
  return cleaned;
}

/**
 * Normalizes a 12-word BIP-39 recovery phrase identically across platforms:
 * Unicode NFKD, trimmed, lowercased, single ASCII spaces.
 */
export function normalizeRecoveryPhrase(phrase: string): string {
  const normalized = phrase
    .normalize('NFKD')
    .trim()
    .toLowerCase()
    .replace(/\s+/g, ' ');
  const words = normalized.split(' ').filter(Boolean);
  if (words.length !== 12) {
    throw new Error('Recovery phrase must contain exactly 12 words');
  }
  return words.join(' ');
}

/**
 * Derives the fixed 32-byte VERIFIER_SALT = SHA-256("ghost-verifier-salt-v2.1.0").
 */
export async function getVerifierSalt(): Promise<Uint8Array> {
  const data = new TextEncoder().encode(VERIFIER_SALT_DOMAIN);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

export function hexToBytes(hex: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(hex) || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Decodes Postgres bytea outputs ('\\x...' or plain hex or Uint8Array) to Uint8Array.
 */
export function pgByteaToBytes(value: string | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof value === 'string') {
    if (value.startsWith('\\x') || value.startsWith('\\X')) {
      return hexToBytes(value.slice(2));
    }
    if (/^[0-9a-fA-F]+$/.test(value)) {
      return hexToBytes(value);
    }
    // Base64 fallback
    const bin = atob(value);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }
  throw new Error('Unsupported bytea representation');
}

export function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin);
}

/**
 * Builds the canonical 76-byte proof message:
 *   nonce (32B) || utf8(lowercase(account_id)) (36B) || uint64_be(server_timestamp) (8B)
 */
export function buildCanonicalProofMessage(
  nonce: Uint8Array,
  accountId: string,
  serverTimestamp: number
): Uint8Array {
  if (!(nonce instanceof Uint8Array) || nonce.length !== 32) {
    throw new Error('Challenge nonce must be exactly 32 bytes');
  }
  if (!RFC4122_UUID_REGEX.test(accountId)) {
    throw new Error('accountId must be a valid RFC 4122 UUID');
  }
  if (!Number.isInteger(serverTimestamp) || serverTimestamp < 0) {
    throw new Error('serverTimestamp must be a non-negative integer');
  }

  const accountBytes = new TextEncoder().encode(accountId.trim().toLowerCase());
  if (accountBytes.length !== 36) {
    throw new Error('Normalized accountId UUID must encode to exactly 36 UTF-8 bytes');
  }

  const msg = new Uint8Array(76);
  msg.set(nonce, 0);
  msg.set(accountBytes, 32);

  // Encode unsigned 64-bit big-endian integer safely without ES2020 BigInt dependency
  const view = new DataView(msg.buffer, 68, 8);
  const hi = Math.floor(serverTimestamp / 0x100000000);
  const lo = serverTimestamp >>> 0;
  view.setUint32(0, hi, false);
  view.setUint32(4, lo, false);
  return msg;
}

/**
 * Computes HMAC-SHA256(key, data) as a 32-byte Uint8Array.
 */
export async function hmacSha256(
  keyBytes: Uint8Array,
  messageBytes: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes.slice(),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, messageBytes.slice());
  return new Uint8Array(sig);
}

/**
 * Computes lowercase 64-hex challenge proof:
 *   HMAC-SHA256(recovery_verifier, nonce || utf8(lowercase(account_id)) || uint64_be(server_timestamp))
 */
export async function computeRecoveryProofHex(
  recoveryVerifierBytes: Uint8Array,
  nonce: Uint8Array,
  accountId: string,
  serverTimestamp: number
): Promise<string> {
  if (!(recoveryVerifierBytes instanceof Uint8Array) || recoveryVerifierBytes.length !== 32) {
    throw new Error('recovery_verifier must be exactly 32 bytes');
  }
  const msg = buildCanonicalProofMessage(nonce, accountId, serverTimestamp);
  const sig = await hmacSha256(recoveryVerifierBytes, msg);
  return bytesToHex(sig);
}

/**
 * Constant-time 32-byte array equality (runs full 32 iterations regardless of mismatch position).
 */
export function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Constant-time comparison of two secret strings by comparing their SHA-256 digests
 * so secret lengths are also protected against timing leakage.
 */
export async function constantTimeEqualSecrets(
  a: string | null | undefined,
  b: string | null | undefined
): Promise<boolean> {
  if (typeof a !== 'string' || typeof b !== 'string' || !a || !b) {
    return false;
  }
  const enc = new TextEncoder();
  const [da, db] = await Promise.all([
    crypto.subtle.digest('SHA-256', enc.encode(a)),
    crypto.subtle.digest('SHA-256', enc.encode(b)),
  ]);
  return constantTimeEqualBytes(new Uint8Array(da), new Uint8Array(db));
}

/**
 * Constant-time verification of submitted 64-hex challenge proof against stored 32B verifier.
 */
export async function verifyRecoveryProof(
  recoveryVerifierBytes: Uint8Array,
  nonce: Uint8Array,
  accountId: string,
  serverTimestamp: number,
  submittedProofHex: string
): Promise<boolean> {
  if (!HEX64_REGEX.test(submittedProofHex)) {
    return false;
  }
  const submittedBytes = hexToBytes(submittedProofHex);
  const msg = buildCanonicalProofMessage(nonce, accountId, serverTimestamp);
  const expectedBytes = await hmacSha256(recoveryVerifierBytes, msg);
  return constantTimeEqualBytes(expectedBytes, submittedBytes);
}

function bytesToRfc4122V4Uuid(bytes16: Uint8Array): string {
  const b = new Uint8Array(bytes16.slice(0, 16));
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 1
  const h = bytesToHex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export interface RecoveryChallengeResponsePayload {
  challenge_id: string;
  account_id: string;
  nonce: string;
  server_timestamp: number;
  recovery_salt: string;
  kdf_version: number;
}

/**
 * Generates an indistinguishable synthetic challenge response for unknown/deleted emails
 * using HMAC-SHA256(SERVER_ENUMERATION_SECRET, ...) so schema, UUID v4 formatting,
 * 64-hex nonce, 64-hex salt, timestamp, and status match real accounts identically.
 */
export async function synthesizeAntiEnumerationChallenge(
  normalizedEmail: string,
  enumerationSecret: string,
  serverTimestamp: number
): Promise<RecoveryChallengeResponsePayload> {
  if (!enumerationSecret || enumerationSecret.length < 16) {
    throw new Error('SERVER_ENUMERATION_SECRET missing or too short');
  }
  const secretBytes = new TextEncoder().encode(enumerationSecret);
  const enc = new TextEncoder();

  const [cidDigest, aidDigest, nonceDigest, saltDigest] = await Promise.all([
    hmacSha256(secretBytes, enc.encode(`challenge-id:${normalizedEmail}:${serverTimestamp}`)),
    hmacSha256(secretBytes, enc.encode(`account-id:${normalizedEmail}`)),
    hmacSha256(secretBytes, enc.encode(`nonce:${normalizedEmail}:${serverTimestamp}`)),
    hmacSha256(secretBytes, enc.encode(`recovery-salt:${normalizedEmail}`)),
  ]);

  return {
    challenge_id: bytesToRfc4122V4Uuid(cidDigest),
    account_id: bytesToRfc4122V4Uuid(aidDigest),
    nonce: bytesToHex(nonceDigest),
    server_timestamp: serverTimestamp,
    recovery_salt: bytesToHex(saltDigest),
    kdf_version: 2,
  };
}
