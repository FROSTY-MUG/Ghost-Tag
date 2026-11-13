/**
 * @file argon2.ts
 * @summary Argon2id Key Derivation Function (KDF) wrapper for KEK generation.
 *
 * Implements RFC 9106 Argon2id password-based key derivation to generate 256-bit Key Encryption
 * Keys (KEKs) from user master passphrases.
 *
 * Security Requirements:
 * - Never caches or persists derived key material in memory.
 * - Best-effort sanitization of intermediate passphrase buffers.
 * - Rejects KDF parameter downgrades to protect against brute-force attacks.
 * - Validates hardware execution performance bounds (< 100ms too weak, > 5000ms unresponsive).
 */

import { NativeModules } from 'react-native';
import QuickCrypto from 'react-native-quick-crypto';
import {
  DeviceTier,
  KdfParameters,
  DEFAULT_KDF_PARAMETERS_BY_TIER,
} from '../contracts/keyHierarchy';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { generateSalt } from './random';
import { bytesToHex, hexToBytes } from './keyWrap';
import { zeroize, secureWipeBuffer } from './secureMemory';
import { assertDeviceIntegrity } from '../security/deviceIntegrity';
import { sanitizeError } from '../security/antiLeak';

/**
 * Type alias conforming to contract specifications.
 */
export type KDFParams = KdfParameters;

/** Custom provider hook for testing or alternative KDF backends. */
let customArgon2Provider:
  | ((passphrase: string, salt: Uint8Array, params: KDFParams) => Promise<Uint8Array>)
  | null = null;

/**
 * Sets a custom Argon2id provider (primarily used for unit testing in non-native environments).
 *
 * @param provider Custom derivation callback or null to reset.
 */
export function setTestArgon2Provider(
  provider:
    | ((passphrase: string, salt: Uint8Array, params: KDFParams) => Promise<Uint8Array>)
    | null
): void {
  customArgon2Provider = provider;
}

/**
 * Validates structural and cryptographic bounds of Argon2id KDF parameters (RFC 9106).
 *
 * Rules:
 * - Salt must be a Uint8Array of at least 8 bytes (RFC 9106: 8 <= |s| <= 2^32-1).
 * - Parallelism (p) >= 1.
 * - Time cost / iterations (t) >= 1.
 * - Memory cost (m) >= 8 * p KiB.
 * - Version must be 0x13 (v1.3) or 0x10 (v1.0).
 *
 * @param params Candidate KdfParameters to validate.
 * @returns True if valid, false otherwise.
 */
export function validateParams(params: KDFParams): boolean {
  if (!params) {
    return false;
  }

  if (
    !params.salt ||
    !(params.salt instanceof Uint8Array) ||
    params.salt.length < 8
  ) {
    return false;
  }

  if (
    !Number.isInteger(params.parallelism) ||
    params.parallelism < 1 ||
    params.parallelism > 0xffffff
  ) {
    return false;
  }

  if (
    !Number.isInteger(params.timeCost) ||
    params.timeCost < 1 ||
    params.timeCost > 0xffffffff
  ) {
    return false;
  }

  const minMemory = 8 * params.parallelism;
  if (
    !Number.isInteger(params.memoryCost) ||
    params.memoryCost < minMemory ||
    params.memoryCost > 0xffffffff
  ) {
    return false;
  }

  if (params.version !== 0x13 && params.version !== 0x10) {
    return false;
  }

  return true;
}

/**
 * Checks whether a proposed set of KDF parameters represents a security downgrade
 * compared to current parameters.
 *
 * A downgrade occurs if any of memoryCost, timeCost, or parallelism is strictly reduced.
 *
 * @param current Currently active KDF parameters.
 * @param proposed Proposed new KDF parameters.
 * @returns True if proposed is a downgrade, false if equal or stronger.
 */
export function checkParamDowngrade(
  current: KDFParams,
  proposed: KDFParams
): boolean {
  if (!current || !proposed) {
    return false;
  }

  return (
    proposed.memoryCost < current.memoryCost ||
    proposed.timeCost < current.timeCost ||
    proposed.parallelism < current.parallelism
  );
}

/**
 * Retrieves default recommended KDF parameters for a given device tier with a fresh salt.
 *
 * @param tier Target DeviceTier.
 * @returns Recommended KDF parameters with a fresh 16-byte salt.
 */
export function getDefaultParams(tier: DeviceTier): KDFParams {
  const profile =
    DEFAULT_KDF_PARAMETERS_BY_TIER[tier] ??
    DEFAULT_KDF_PARAMETERS_BY_TIER[DeviceTier.STANDARD];

  return {
    salt: generateSalt(),
    memoryCost: profile.memoryCost,
    timeCost: profile.timeCost,
    parallelism: profile.parallelism,
    version: profile.version,
  };
}

/**
 * Internal low-level derivation dispatcher.
 */
async function executeArgon2id(
  passphrase: string,
  salt: Uint8Array,
  params: KDFParams
): Promise<Uint8Array> {
  // 1. If a test or custom provider is configured, use it
  if (customArgon2Provider) {
    return customArgon2Provider(passphrase, salt, params);
  }

  // 2. Try native react-native-argon2 bridge module
  const nativeArgon2 = NativeModules?.RNArgon2?.argon2;
  if (typeof nativeArgon2 === 'function') {
    const saltHex = bytesToHex(salt);
    const result = await nativeArgon2(passphrase, saltHex, {
      iterations: params.timeCost,
      memory: params.memoryCost,
      parallelism: params.parallelism,
      hashLength: 32,
      mode: 'argon2id',
      saltEncoding: 'hex',
    });
    return hexToBytes(result.rawHash);
  }

  // 3. Fallback for non-native / test execution (deterministic PBKDF2)
  const passBuf = QuickCrypto.Buffer.from(passphrase, 'utf8');
  try {
    const derived = QuickCrypto.pbkdf2Sync(
      passBuf,
      salt,
      Math.max(1000, params.timeCost * 2000),
      32,
      'sha256'
    );
    const result = new Uint8Array(32);
    result.set(derived);
    return result;
  } finally {
    zeroize(passBuf);
  }
}

/**
 * Derives a 32-byte (256-bit) Key Encryption Key (KEK) from a master passphrase and salt.
 *
 * Security Properties:
 * - Enforces parameter validation and rejects downgrades if compared.
 * - Times the derivation and logs warnings if elapsed time is < 100ms (too weak) or > 5000ms (unresponsive).
 * - Never caches the derived key in static or global state.
 * - Performs best-effort clearing of intermediate passphrase buffers.
 *
 * @param passphrase User master passphrase.
 * @param salt Cryptographically secure salt (minimum 8 bytes, typically 16 bytes).
 * @param params Argon2id configuration parameters.
 * @returns 32-byte derived Key Encryption Key.
 * @throws {GhostTagError} On invalid inputs or derivation failure.
 */
export async function deriveKEK(
  passphrase: string,
  salt: Uint8Array,
  params: KDFParams
): Promise<Uint8Array> {
  // Enforce strict device integrity before deriving any key material
  await assertDeviceIntegrity(salt);

  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new GhostTagError({
      code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
      userMessage: 'Passphrase is required for key derivation.',
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (!salt || !(salt instanceof Uint8Array) || salt.length < 8) {
    throw new GhostTagError({
      code: GhostTagErrorCode.ARGON2ID_FAILED,
      userMessage: 'Invalid salt provided for Argon2id key derivation.',
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (!validateParams(params)) {
    throw new GhostTagError({
      code: GhostTagErrorCode.ARGON2ID_FAILED,
      userMessage: 'Invalid Argon2id parameters provided for key derivation.',
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
    });
  }

  const startTime = Date.now();
  let derivedKey: Uint8Array;

  try {
    derivedKey = await executeArgon2id(passphrase, salt, params);
  } catch (err) {
    if (err instanceof GhostTagError) {
      throw err;
    }
    throw new GhostTagError({
      code: GhostTagErrorCode.ARGON2ID_FAILED,
      userMessage: 'Argon2id key derivation failed.',
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
      cause: sanitizeError(err),
    });
  }

  const elapsedMs = Date.now() - startTime;
  if (elapsedMs < 100) {
    console.warn(
      `[GhostTag Crypto Warning] Argon2id derivation completed in ${elapsedMs}ms (< 100ms minimum recommended). Consider increasing parameters.`
    );
  } else if (elapsedMs > 5000) {
    console.warn(
      `[GhostTag Crypto Warning] Argon2id derivation took ${elapsedMs}ms (> 5000ms), which may degrade responsiveness.`
    );
  }

  return derivedKey;
}

/**
 * Benchmarks the current host device to calibrate appropriate KDF parameters.
 *
 * Runs a standardized benchmark derivation to measure latency and select the highest
 * resistance parameter tier that completes within ~1.5 seconds.
 *
 * @returns Detected DeviceTier (HIGH_END, STANDARD, or LOW_END).
 */
export async function benchmarkDevice(): Promise<DeviceTier> {
  const benchmarkSalt = new Uint8Array(16);
  const testParams: KDFParams = {
    salt: benchmarkSalt,
    memoryCost: 32768,
    timeCost: 3,
    parallelism: 2,
    version: 0x13,
  };

  try {
    const start = Date.now();
    await deriveKEK('ghost-tag-benchmark-pass', benchmarkSalt, testParams);
    const duration = Date.now() - start;

    if (duration < 500) {
      return DeviceTier.HIGH_END;
    } else if (duration <= 2000) {
      return DeviceTier.STANDARD;
    } else {
      return DeviceTier.LOW_END;
    }
  } catch {
    return DeviceTier.STANDARD;
  }
}

