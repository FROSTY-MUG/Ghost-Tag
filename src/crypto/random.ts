/**
 * @file random.ts
 * @summary Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) abstractions.
 *
 * Provides high-entropy randomness using native OS entropy pools via react-native-quick-crypto.
 * All functions return fresh, isolated Uint8Array buffers.
 */

import QuickCrypto from 'react-native-quick-crypto';
import {
  ENVELOPE_NONCE_SIZE,
  ENVELOPE_KEY_ID_SIZE,
} from '../contracts/envelope';
import {
  DEK_BYTE_LENGTH,
  PRIMARY_KDF_SALT_BYTE_LENGTH,
} from '../contracts/keyHierarchy';

/** Byte length of 256-bit recovery master secret. */
export const RECOVERY_SECRET_BYTE_LENGTH = 32 as const;

/**
 * Generates cryptographically secure random bytes of specified length.
 *
 * @param length Positive integer length in bytes.
 * @returns Fresh Uint8Array containing random bytes.
 * @throws {RangeError} If length is not a positive integer.
 */
export function generateSecureRandom(length: number): Uint8Array {
  if (length <= 0 || !Number.isInteger(length)) {
    throw new RangeError(
      `Secure random length must be a positive integer, received: ${length}`
    );
  }
  const buf = QuickCrypto.randomBytes(length);
  // Return an isolated Uint8Array copy rather than a shared Buffer pool slice
  const result = new Uint8Array(length);
  result.set(buf);
  return result;
}

/**
 * Generates a fresh 12-byte (96-bit) AES-256-GCM initialization vector (nonce).
 * MUST NEVER be repeated under the same key.
 *
 * @returns 12-byte random nonce.
 */
export function generateNonce(): Uint8Array {
  return generateSecureRandom(ENVELOPE_NONCE_SIZE);
}

/**
 * Generates a 16-byte (128-bit) unique Data Encryption Key (DEK) identifier.
 *
 * @returns 16-byte random key ID.
 */
export function generateKeyId(): Uint8Array {
  return generateSecureRandom(ENVELOPE_KEY_ID_SIZE);
}

/**
 * Generates a high-entropy 32-byte (256-bit) Data Encryption Key (DEK).
 *
 * @returns 32-byte random DEK.
 */
export function generateDEK(): Uint8Array {
  return generateSecureRandom(DEK_BYTE_LENGTH);
}

/**
 * Generates a 16-byte (128-bit) cryptographically secure salt for Argon2id KEK derivation.
 *
 * @returns 16-byte random salt.
 */
export function generateSalt(): Uint8Array {
  return generateSecureRandom(PRIMARY_KDF_SALT_BYTE_LENGTH);
}

/**
 * Generates a 32-byte (256-bit) recovery secret used for out-of-band vault recovery.
 *
 * @returns 32-byte random recovery secret.
 */
export function generateRecoverySecret(): Uint8Array {
  return generateSecureRandom(RECOVERY_SECRET_BYTE_LENGTH);
}

