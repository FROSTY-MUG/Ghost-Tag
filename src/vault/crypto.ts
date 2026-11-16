/**
 * @file crypto.ts
 * @summary Vault Cryptographic Primitives & Key Management Bridge.
 *
 * Provides high-level cryptographic operations tailored for the Ghost-Tag vault:
 * - KEK derivation from master passphrases using Argon2id RFC 9106.
 * - Authenticated DEK wrapping/unwrapping using AES-256-GCM.
 * - Constant-time authentication tag and HMAC verifications.
 * - Explicit memory zeroization after cryptographic operations.
 */

import { deriveKEK } from '../crypto/argon2';
import { wrapDEK, unwrapDEK } from '../crypto/keyWrap';
import { zeroize } from '../security/secureWipe';
import { generateDEK, generateSalt } from '../crypto/random';
import { timingSafeEqual } from '../security/antiLeak';
import {
  DeviceTier,
  DEFAULT_KDF_PARAMETERS_BY_TIER,
  KdfParameters,
  WrappedDEK,
} from '../contracts/keyHierarchy';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

export class VaultCrypto {
  /**
   * Derives a 256-bit Key Encryption Key (KEK) from a user master passphrase and salt.
   * Transitory passphrase buffers are not retained.
   */
  public static async deriveKEK(
    passphrase: string,
    salt: Uint8Array,
    params?: KdfParameters
  ): Promise<Uint8Array> {
    if (!passphrase || passphrase.length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
        userMessage: 'Passphrase is required for KEK derivation.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    if (!salt || salt.length < 16) {
      throw new GhostTagError({
        code: GhostTagErrorCode.ARGON2ID_FAILED,
        userMessage: 'Invalid salt for KEK derivation. Minimum 16 bytes required.',
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }

    const effectiveParams: KdfParameters = params || {
      ...DEFAULT_KDF_PARAMETERS_BY_TIER[DeviceTier.STANDARD],
      salt,
    };

    return await deriveKEK(passphrase, salt, effectiveParams);
  }

  /**
   * Wraps a 256-bit Data Encryption Key (DEK) under a KEK using AES-256-GCM.
   */
  public static wrapDEK(
    kek: Uint8Array,
    dek: Uint8Array,
    keyId: Uint8Array,
    kdfVersion: number = 1
  ): WrappedDEK {
    if (kek.length !== 32) {
      throw new GhostTagError({
        code: GhostTagErrorCode.ARGON2ID_FAILED,
        userMessage: `KEK must be exactly 32 bytes (received ${kek.length}).`,
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }

    if (dek.length !== 32) {
      throw new GhostTagError({
        code: GhostTagErrorCode.ARGON2ID_FAILED,
        userMessage: `DEK must be exactly 32 bytes (received ${dek.length}).`,
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }

    return wrapDEK(kek, dek, keyId, kdfVersion);
  }

  /**
   * Unwraps a DEK from a WrappedDEK envelope under the provided KEK.
   * Throws PASSPHRASE_INVALID or GCM_AUTH_FAILED on authentication failure.
   */
  public static unwrapDEK(
    kek: Uint8Array,
    wrappedDek: WrappedDEK
  ): Uint8Array {
    if (kek.length !== 32) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_INVALID,
        userMessage: 'Invalid KEK size for DEK unwrapping.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    try {
      return unwrapDEK(kek, wrappedDek);
    } catch (err) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_INVALID,
        userMessage: 'Failed to unwrap DEK. Master passphrase or key material is incorrect.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
        cause: err instanceof Error ? err : undefined,
      });
    }
  }

  /**
   * Generates a cryptographically secure 256-bit random DEK.
   */
  public static generateDEK(): Uint8Array {
    return generateDEK();
  }

  /**
   * Generates a 16-byte random salt for KEK derivation.
   */
  public static generateSalt(): Uint8Array {
    return generateSalt();
  }

  /**
   * Securely zeroes out sensitive key material in place.
   */
  public static wipeBuffer(buffer: Uint8Array): void {
    zeroize(buffer);
  }

  /**
   * Constant-time comparison of two byte buffers to prevent timing side channels.
   */
  public static timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    return timingSafeEqual(a, b);
  }
}
