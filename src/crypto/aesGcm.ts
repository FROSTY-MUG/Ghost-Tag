/**
 * @file aesGcm.ts
 * @summary Authenticated Encryption with Associated Data (AEAD) using AES-256-GCM.
 *
 * Implements authenticated encryption, decryption, and key-wrapping according to NIST SP 800-38D.
 * Guarantees confidentiality, authenticity, and binding of associated metadata.
 */

import QuickCrypto from 'react-native-quick-crypto';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import {
  ENVELOPE_NONCE_SIZE,
  ENVELOPE_GCM_TAG_SIZE,
} from '../contracts/envelope';
import {
  DEK_BYTE_LENGTH,
  KEK_BYTE_LENGTH,
} from '../contracts/keyHierarchy';
import { generateNonce } from './random';

/**
 * Result of AES-256-GCM authenticated encryption.
 */
export interface EncryptResult {
  /** Ciphertext bytes (length matches plaintext). */
  readonly ciphertext: Uint8Array;
  /** 12-byte initialization vector (never reused). */
  readonly nonce: Uint8Array;
  /** 16-byte authentication tag verifying ciphertext and AAD. */
  readonly tag: Uint8Array;
}

/**
 * Wrapped key payload containing ciphertext and authentication material.
 */
export interface WrappedKey {
  /** Encrypted key ciphertext bytes. */
  readonly ciphertext: Uint8Array;
  /** 12-byte initialization vector. */
  readonly nonce: Uint8Array;
  /** 16-byte authentication tag. */
  readonly tag: Uint8Array;
}

/**
 * Converts a Uint8Array to a QuickCrypto Buffer without memory copy where possible.
 */
function toBuffer(arr: Uint8Array): import('@craftzdog/react-native-buffer').Buffer {
  return QuickCrypto.Buffer.from(arr.buffer as ArrayBuffer, arr.byteOffset, arr.byteLength);
}

/**
 * Encrypts plaintext bytes using AES-256-GCM with Additional Authenticated Data (AAD).
 *
 * Security Properties:
 * - Always generates a fresh 12-byte random nonce per invocation.
 * - Nonce reuse with the same key is strictly prevented.
 * - AAD is authenticated by the GCM tag but not included in ciphertext.
 *
 * @param key 32-byte (256-bit) symmetric encryption key.
 * @param plaintext Arbitrary plaintext bytes to encrypt.
 * @param aad Additional Authenticated Data to bind into the authentication tag.
 * @returns Encrypted ciphertext, nonce, and auth tag.
 * @throws {GhostTagError} If key size is invalid.
 */
export function encrypt(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array
): EncryptResult {
  if (!key || key.length !== DEK_BYTE_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.ARGON2ID_FAILED,
      userMessage: `AES-256-GCM requires a ${DEK_BYTE_LENGTH}-byte key, received: ${key?.length ?? 0} bytes.`,
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
    });
  }

  const nonce = generateNonce();
  const keyBuf = toBuffer(key);
  const nonceBuf = toBuffer(nonce);
  const cipher = QuickCrypto.createCipheriv('aes-256-gcm', keyBuf, nonceBuf);

  if (aad && aad.length > 0) {
    cipher.setAAD(toBuffer(aad));
  }

  const plainBuf = toBuffer(plaintext);
  const part1 = cipher.update(plainBuf);
  const part2 = cipher.final();
  // Skip the concat when the final update produced no bytes (common for short inputs)
  const ctBuffer = part2.length > 0 ? QuickCrypto.Buffer.concat([part1, part2]) : part1;
  const tagBuffer = cipher.getAuthTag();

  const ciphertext = new Uint8Array(ctBuffer.length);
  ciphertext.set(ctBuffer);

  const tag = new Uint8Array(tagBuffer.length);
  tag.set(tagBuffer);

  return {
    ciphertext,
    nonce,
    tag,
  };
}

/**
 * Decrypts AES-256-GCM ciphertext and verifies the authentication tag against AAD.
 *
 * Security Properties:
 * - Constant-time authentication tag verification performed by OpenSSL/BoringSSL.
 * - If ciphertext, nonce, tag, or AAD has been modified, decryption will fail immediately.
 * - Throws a typed GhostTagError with GCM_AUTH_FAILED and severity CRITICAL.
 *
 * @param key 32-byte (256-bit) symmetric key.
 * @param ciphertext Encrypted ciphertext bytes.
 * @param nonce 12-byte initialization vector used during encryption.
 * @param tag 16-byte authentication tag.
 * @param aad Additional Authenticated Data bound during encryption.
 * @returns Decrypted plaintext bytes.
 * @throws {GhostTagError} If tag verification fails or parameters are invalid.
 */
export function decrypt(
  key: Uint8Array,
  ciphertext: Uint8Array,
  nonce: Uint8Array,
  tag: Uint8Array,
  aad: Uint8Array
): Uint8Array {
  if (!key || key.length !== DEK_BYTE_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.GCM_AUTH_FAILED,
      userMessage: `Decryption failed: key must be ${DEK_BYTE_LENGTH} bytes.`,
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.CRITICAL,
    });
  }

  if (!nonce || nonce.length !== ENVELOPE_NONCE_SIZE) {
    throw new GhostTagError({
      code: GhostTagErrorCode.GCM_AUTH_FAILED,
      userMessage: `Decryption failed: nonce must be ${ENVELOPE_NONCE_SIZE} bytes.`,
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.CRITICAL,
    });
  }

  if (!tag || tag.length !== ENVELOPE_GCM_TAG_SIZE) {
    throw new GhostTagError({
      code: GhostTagErrorCode.GCM_AUTH_FAILED,
      userMessage: `Decryption failed: auth tag must be ${ENVELOPE_GCM_TAG_SIZE} bytes.`,
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.CRITICAL,
    });
  }

  try {
    const keyBuf = toBuffer(key);
    const nonceBuf = toBuffer(nonce);
    const decipher = QuickCrypto.createDecipheriv('aes-256-gcm', keyBuf, nonceBuf);

    if (aad && aad.length > 0) {
      decipher.setAAD(toBuffer(aad));
    }
    decipher.setAuthTag(toBuffer(tag));

    const ctBuf = toBuffer(ciphertext);
    const part1 = decipher.update(ctBuf);
    const part2 = decipher.final();
    // Skip the concat when the final update produced no bytes (common for short inputs)
    const ptBuffer = part2.length > 0 ? QuickCrypto.Buffer.concat([part1, part2]) : part1;

    const plaintext = new Uint8Array(ptBuffer.length);
    plaintext.set(ptBuffer);
    return plaintext;
  } catch (err) {
    throw new GhostTagError({
      code: GhostTagErrorCode.GCM_AUTH_FAILED,
      userMessage:
        'Decryption failed: AES-256-GCM authentication tag verification failed. Ciphertext or AAD tampered with, or invalid key.',
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.CRITICAL,
      cause: err,
    });
  }
}

/**
 * Wraps a Data Encryption Key (DEK) under a Key Encryption Key (KEK) using AES-256-GCM.
 *
 * @param kek 32-byte Key Encryption Key derived from user master passphrase.
 * @param dek 32-byte Data Encryption Key to protect.
 * @param aad Domain separation and metadata authentication data.
 * @returns WrappedKey containing wrapped ciphertext, nonce, and auth tag.
 */
export function wrapKey(
  kek: Uint8Array,
  dek: Uint8Array,
  aad: Uint8Array
): WrappedKey {
  if (!kek || kek.length !== KEK_BYTE_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.ARGON2ID_FAILED,
      userMessage: `KEK must be ${KEK_BYTE_LENGTH} bytes.`,
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (!dek || dek.length !== DEK_BYTE_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.ARGON2ID_FAILED,
      userMessage: `DEK must be ${DEK_BYTE_LENGTH} bytes.`,
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
    });
  }

  const result = encrypt(kek, dek, aad);
  return {
    ciphertext: result.ciphertext,
    nonce: result.nonce,
    tag: result.tag,
  };
}

/**
 * Unwraps a wrapped Data Encryption Key (DEK) under a Key Encryption Key (KEK).
 *
 * @param kek 32-byte Key Encryption Key.
 * @param wrapped WrappedKey structure.
 * @param aad Domain separation and metadata authentication data.
 * @returns Decrypted 32-byte Data Encryption Key.
 * @throws {GhostTagError} If authentication fails or key material is invalid.
 */
export function unwrapKey(
  kek: Uint8Array,
  wrapped: WrappedKey,
  aad: Uint8Array
): Uint8Array {
  if (!wrapped || !wrapped.ciphertext || !wrapped.nonce || !wrapped.tag) {
    throw new GhostTagError({
      code: GhostTagErrorCode.GCM_AUTH_FAILED,
      userMessage: 'Key unwrap failed: malformed wrapped key payload.',
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.CRITICAL,
    });
  }

  const unwrapped = decrypt(
    kek,
    wrapped.ciphertext,
    wrapped.nonce,
    wrapped.tag,
    aad
  );

  if (unwrapped.length !== DEK_BYTE_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.GCM_AUTH_FAILED,
      userMessage: `Unwrapped key length mismatch: expected ${DEK_BYTE_LENGTH} bytes, got ${unwrapped.length}.`,
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.CRITICAL,
    });
  }

  return unwrapped;
}

