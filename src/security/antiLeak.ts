/**
 * @file antiLeak.ts
 * @summary Anti-Leak Protection, Diagnostic Log Sanitization, and Constant-Time Verification.
 *
 * Implements strict controls to prevent sensitive cryptographic material (passphrase hashes,
 * Argon2 outputs, KEKs, DEKs, and raw cipher keys) from leaking into console logs, crash
 * reports, error messages, or timing side-channels.
 */

import QuickCrypto from 'react-native-quick-crypto';
import { GhostTagError } from '../contracts/errors';

/**
 * Regular expression matching 64-character continuous hexadecimal strings
 * (representing 256-bit cryptographic keys, SHA-256 digests, or Argon2 hashes).
 */
const HEX_KEY_REGEX = /\b[0-9a-fA-F]{64}\b/g;

/**
 * Regular expression matching 32-character continuous hexadecimal strings
 * (representing 128-bit IVs, nonces, or salt buffers).
 */
const HEX_IV_REGEX = /\b[0-9a-fA-F]{32}\b/g;

/**
 * Regular expression matching potential Base64-encoded secret payloads (> 32 chars).
 */
const BASE64_SECRET_REGEX = /\b[A-Za-z0-9+/]{32,}={0,2}\b/g;

/**
 * Scans a string and redacts any detected cryptographic key patterns,
 * hash values, or high-entropy credentials.
 *
 * @param input Raw diagnostic string or log line.
 * @returns Sanitized string with cryptographic secrets replaced with redaction placeholders.
 */
export function redactSensitiveData(input: string): string {
  if (typeof input !== 'string' || input.length === 0) {
    return input;
  }

  return input
    .replace(HEX_KEY_REGEX, '[REDACTED_256BIT_SECRET]')
    .replace(HEX_IV_REGEX, '[REDACTED_128BIT_BUFFER]')
    .replace(BASE64_SECRET_REGEX, '[REDACTED_ENCODED_PAYLOAD]');
}

/**
 * Compares two byte arrays in constant time to prevent side-channel timing attacks.
 * Uses QuickCrypto.timingSafeEqual when available, with a constant-time fallback.
 *
 * @param a First byte buffer.
 * @param b Second byte buffer.
 * @returns True if arrays are of equal length and identical contents; false otherwise.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  try {
    const bufA = QuickCrypto.Buffer.from(a.buffer as ArrayBuffer, a.byteOffset, a.byteLength);
    const bufB = QuickCrypto.Buffer.from(b.buffer as ArrayBuffer, b.byteOffset, b.byteLength);
    return QuickCrypto.timingSafeEqual(bufA, bufB);
  } catch {
    // Constant-time bitwise accumulator fallback
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }
}

/**
 * Sanitizes an error instance or unknown exception, removing any potential secrets
 * or passphrase fragments from the error message or diagnostic detail.
 *
 * @param error Raw error caught in try/catch block.
 * @returns Sanitized error safe for user presentation or crash logging.
 */
export function sanitizeError(error: unknown): unknown {
  if (!error) {
    return error;
  }

  if (error instanceof GhostTagError) {
    const cleanUserMsg = redactSensitiveData(error.userMessage);
    const cleanTechDetail = error.technicalDetail
      ? redactSensitiveData(error.technicalDetail)
      : undefined;

    return new GhostTagError({
      code: error.code,
      userMessage: cleanUserMsg,
      technicalDetail: cleanTechDetail,
      category: error.category,
      severity: error.severity,
      cause: error.cause ? sanitizeError(error.cause) : undefined,
    });
  }

  if (error instanceof Error) {
    const sanitizedMsg = redactSensitiveData(error.message);
    const sanitizedError = new Error(sanitizedMsg);
    sanitizedError.name = error.name;
    if (error.stack) {
      sanitizedError.stack = redactSensitiveData(error.stack);
    }
    return sanitizedError;
  }

  if (typeof error === 'string') {
    return redactSensitiveData(error);
  }

  return error;
}

/**
 * Leak-proof logger interface that redacts sensitive key material
 * before emitting to console or diagnostic buffers.
 */
export class SanitizedLogger {
  private readonly context: string;

  constructor(context: string) {
    this.context = context;
  }

  public info(message: string, ...args: unknown[]): void {
    const cleanMsg = redactSensitiveData(message);
    const cleanArgs = args.map((arg) =>
      typeof arg === 'string' ? redactSensitiveData(arg) : arg
    );
    console.info(`[${this.context}] ${cleanMsg}`, ...cleanArgs);
  }

  public warn(message: string, ...args: unknown[]): void {
    const cleanMsg = redactSensitiveData(message);
    const cleanArgs = args.map((arg) =>
      typeof arg === 'string' ? redactSensitiveData(arg) : arg
    );
    console.warn(`[${this.context}] ${cleanMsg}`, ...cleanArgs);
  }

  public error(message: string, ...args: unknown[]): void {
    const cleanMsg = redactSensitiveData(message);
    const cleanArgs = args.map((arg) =>
      typeof arg === 'string' ? redactSensitiveData(arg) : arg
    );
    console.error(`[${this.context}] ${cleanMsg}`, ...cleanArgs);
  }
}
