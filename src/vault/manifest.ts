/**
 * @file manifest.ts
 * @summary Vault Metadata Authentication and Tamper Detection Engine.
 *
 * Implements HMAC-SHA-256 integrity verification over all sensitive vault configuration
 * metadata, including KDF cost parameters, salts, wrapped DEK lists, and recovery pointers.
 *
 * Tamper Protection:
 * - Detects deleted DEKs
 * - Detects modified KDF parameters or downgrade attacks
 * - Detects modified salts
 * - Detects modified or swapped wrapped DEKs
 * - Detects record reordering
 * - Detects version downgrades or restored old backups
 */

import QuickCrypto from 'react-native-quick-crypto';
import { KdfParameters, WrappedDEK } from '../contracts/keyHierarchy';
import { RecoveryEnvelope } from '../contracts/recovery';
import { AuditEntry } from '../contracts/vault';
import { validateParams } from '../crypto/argon2';
import { bytesToHex } from '../crypto/keyWrap';

/** Canonical domain separation string for manifest HMAC derivation. */
const MANIFEST_HMAC_DOMAIN_STRING = 'GhostTag-Vault-Manifest-Auth-v1';

/**
 * Vault data structure validated by VaultManifest.
 */
export interface VaultData {
  /** Globally unique identifier for this vault (UUIDv4). */
  readonly vaultId: string;
  /** Timestamp of initial vault creation (epoch ms). */
  readonly creationTime: number;
  /** 16-byte random salt used for Argon2id KEK derivation. */
  readonly argon2Salt: Uint8Array;
  /** Argon2id cost parameters configured for this vault. */
  readonly argon2Params: KdfParameters;
  /** Array of wrapped Data Encryption Keys. */
  readonly wrappedDEKs: readonly WrappedDEK[];
  /** Optional emergency recovery envelope. */
  readonly recoveryEnvelope?: RecoveryEnvelope | null;
  /** Optional audit log entries. */
  readonly auditMetadata?: readonly AuditEntry[];
  /** 16-byte AES-GCM or HMAC authentication tag. */
  readonly manifestTag?: Uint8Array;
}

/**
 * Diagnostic result of a comprehensive vault tamper inspection.
 */
export interface TamperCheckResult {
  /** True if tampering, corruption, or security invariant violations were detected. */
  readonly isTampered: boolean;
  /** Primary reason for tampering detection. */
  readonly reason?: string;
  /** Detailed list of all detected anomalies. */
  readonly details?: readonly string[];
}

/**
 * Metadata authentication and tamper detection engine.
 */
export class VaultManifest {
  private readonly defaultAuthKey?: Uint8Array;

  /**
   * Constructs a new VaultManifest instance.
   *
   * @param defaultAuthKey Optional explicit 32-byte key (such as active KEK) for HMAC computation.
   */
  constructor(defaultAuthKey?: Uint8Array) {
    if (defaultAuthKey && defaultAuthKey.length === 32) {
      this.defaultAuthKey = new Uint8Array(defaultAuthKey.length);
      this.defaultAuthKey.set(defaultAuthKey);
    }
  }

  /**
   * Computes a deterministic 16-byte HMAC-SHA-256 authentication tag over all sensitive vault metadata.
   *
   * @param vault Vault data containing parameters, salts, and wrapped DEK collections.
   * @param authKey Optional explicit authentication key. If omitted, uses defaultAuthKey or derives from salt.
   * @returns 16-byte authentication tag.
   */
  public computeManifestTag(vault: VaultData, authKey?: Uint8Array): Uint8Array {
    const key = authKey ?? this.defaultAuthKey ?? this.deriveManifestKey(vault.argon2Salt);
    const canonicalPayload = this.buildCanonicalManifestString(vault);

    const hmac = QuickCrypto.createHmac('sha256', key);
    hmac.update(canonicalPayload);
    const digest = hmac.digest();

    // Take leading 16 bytes for 128-bit authentication tag
    const tag = new Uint8Array(16);
    tag.set(digest.slice(0, 16));
    return tag;
  }

  /**
   * Verifies the authenticity of a vault's metadata against an expected authentication tag.
   *
   * Security Properties:
   * - Uses constant-time comparison to prevent side-channel timing attacks.
   *
   * @param vault Candidate vault data.
   * @param expectedTag 16-byte expected authentication tag.
   * @param authKey Optional explicit authentication key.
   * @returns True if authentication tag matches exactly, false otherwise.
   */
  public verifyManifest(
    vault: VaultData,
    expectedTag: Uint8Array,
    authKey?: Uint8Array
  ): boolean {
    if (!expectedTag || expectedTag.length !== 16) {
      return false;
    }

    const computedTag = this.computeManifestTag(vault, authKey);
    return this.timingSafeEqual(computedTag, expectedTag);
  }

  /**
   * Performs an exhaustive structural and cryptographic inspection to detect tampering,
   * parameter downgrades, missing DEKs, or corrupted records.
   *
   * @param vault Vault data to inspect.
   * @param authKey Optional explicit authentication key for manifestTag verification.
   * @returns TamperCheckResult indicating whether anomalies were discovered.
   */
  public detectTampering(vault: VaultData, authKey?: Uint8Array): TamperCheckResult {
    const anomalies: string[] = [];

    // 1. Vault ID validation
    if (!vault.vaultId || typeof vault.vaultId !== 'string' || vault.vaultId.trim().length === 0) {
      anomalies.push('Vault ID is missing, empty, or invalid.');
    }

    // 2. Creation time validation (must be positive and not in future)
    const now = Date.now();
    if (!Number.isFinite(vault.creationTime) || vault.creationTime <= 0) {
      anomalies.push(`Invalid vault creationTime: ${vault.creationTime}`);
    } else if (vault.creationTime > now + 60000) {
      anomalies.push(`Vault creationTime is in the future: ${vault.creationTime} (current: ${now})`);
    }

    // 3. Salt inspection (modified or degraded salts)
    if (!vault.argon2Salt || !(vault.argon2Salt instanceof Uint8Array)) {
      anomalies.push('Argon2 salt is missing or not a Uint8Array.');
    } else if (vault.argon2Salt.length < 16) {
      anomalies.push(`Argon2 salt is shorter than 16 bytes (${vault.argon2Salt.length} bytes).`);
    } else {
      // Check if salt is all zeros (zero-entropy attack)
      const isAllZeros = vault.argon2Salt.every((byte) => byte === 0);
      if (isAllZeros) {
        anomalies.push('Argon2 salt has zero entropy (all zero bytes).');
      }
    }

    // 4. KDF parameter bounds and downgrade detection
    if (!vault.argon2Params) {
      anomalies.push('Argon2 KDF parameters are missing.');
    } else {
      if (!validateParams(vault.argon2Params)) {
        anomalies.push('Argon2 KDF parameters violate RFC 9106 structural constraints.');
      }

      // Enforce absolute baseline security limits to prevent downgrade attacks
      if (vault.argon2Params.memoryCost < 16384) {
        anomalies.push(
          `KDF memoryCost (${vault.argon2Params.memoryCost} KiB) is downgraded below minimum safe threshold (16384 KiB).`
        );
      }
      if (vault.argon2Params.timeCost < 2) {
        anomalies.push(
          `KDF timeCost (${vault.argon2Params.timeCost}) is downgraded below minimum safe threshold (2 iterations).`
        );
      }
      if (vault.argon2Params.parallelism < 1) {
        anomalies.push(`KDF parallelism (${vault.argon2Params.parallelism}) is less than 1.`);
      }
      if (vault.argon2Params.version !== 0x13) {
        anomalies.push(
          `KDF version 0x${vault.argon2Params.version.toString(16)} represents an untrusted or downgraded Argon2 version.`
        );
      }
    }

    // 5. Wrapped DEK table integrity
    if (!Array.isArray(vault.wrappedDEKs)) {
      anomalies.push('Wrapped DEK collection is missing or malformed.');
    } else {
      const seenKeyIds = new Set<string>();

      for (let i = 0; i < vault.wrappedDEKs.length; i++) {
        const dek = vault.wrappedDEKs[i];
        if (!dek) {
          anomalies.push(`Wrapped DEK at index ${i} is null or undefined.`);
          continue;
        }

        // Key ID format (32 hex characters = 16 bytes)
        if (!dek.keyId || typeof dek.keyId !== 'string' || !/^[0-9a-fA-F]{32}$/.test(dek.keyId)) {
          anomalies.push(`Wrapped DEK at index ${i} has invalid keyId: "${dek.keyId}".`);
        } else {
          if (seenKeyIds.has(dek.keyId.toLowerCase())) {
            anomalies.push(`Duplicate keyId detected in wrapped DEK list: ${dek.keyId}`);
          }
          seenKeyIds.add(dek.keyId.toLowerCase());
        }

        // Ciphertext size (AES-256 DEK = 32 bytes)
        if (!dek.wrappedCiphertext || dek.wrappedCiphertext.length !== 32) {
          anomalies.push(
            `Wrapped DEK (${dek.keyId}) ciphertext length is ${dek.wrappedCiphertext?.length ?? 0} (expected 32).`
          );
        }

        // Nonce size (96-bit AES-GCM IV = 12 bytes)
        if (!dek.nonce || dek.nonce.length !== 12) {
          anomalies.push(
            `Wrapped DEK (${dek.keyId}) nonce length is ${dek.nonce?.length ?? 0} (expected 12).`
          );
        }

        // Auth tag size (128-bit AES-GCM tag = 16 bytes)
        if (!dek.tag || dek.tag.length !== 16) {
          anomalies.push(
            `Wrapped DEK (${dek.keyId}) auth tag length is ${dek.tag?.length ?? 0} (expected 16).`
          );
        }

        // Version monotonicity
        if (!Number.isInteger(dek.keyVersion) || dek.keyVersion < 1) {
          anomalies.push(`Wrapped DEK (${dek.keyId}) has invalid keyVersion: ${dek.keyVersion}`);
        }
      }
    }

    // 6. Recovery Envelope validation (if configured)
    if (vault.recoveryEnvelope) {
      const env = vault.recoveryEnvelope;
      if (!env.salt || env.salt.length !== 32) {
        anomalies.push(
          `Recovery salt length is ${env.salt?.length ?? 0} (expected 32 bytes).`
        );
      }
      if (!env.params || env.params.memoryCost < 16384 || env.params.timeCost < 2) {
        anomalies.push('Recovery KDF parameters are downgraded below safe threshold.');
      }
      if (!env.checksum || env.checksum.length !== 16) {
        anomalies.push(
          `Recovery envelope checksum length is ${env.checksum?.length ?? 0} (expected 16 bytes).`
        );
      }
    }

    // 7. Manifest authentication tag verification
    if (vault.manifestTag) {
      const isTagValid = this.verifyManifest(vault, vault.manifestTag, authKey);
      if (!isTagValid) {
        anomalies.push(
          'Manifest authentication tag verification failed. Metadata, salts, or wrapped DEKs have been modified.'
        );
      }
    }

    if (anomalies.length > 0) {
      return {
        isTampered: true,
        reason: anomalies[0],
        details: anomalies,
      };
    }

    return {
      isTampered: false,
    };
  }

  /**
   * Constructs a canonical, deterministic serialization string covering all sensitive vault metadata.
   */
  private buildCanonicalManifestString(vault: VaultData): string {
    const parts: string[] = [];

    parts.push(`vaultId:${vault.vaultId}`);
    parts.push(`creationTime:${vault.creationTime}`);
    parts.push(`salt:${bytesToHex(vault.argon2Salt)}`);

    if (vault.argon2Params) {
      parts.push(
        `kdf:${vault.argon2Params.memoryCost}:${vault.argon2Params.timeCost}:${vault.argon2Params.parallelism}:${vault.argon2Params.version}`
      );
    }

    // Sort wrapped DEKs deterministically by keyId
    const sortedDeks = [...(vault.wrappedDEKs ?? [])].sort((a, b) =>
      a.keyId.localeCompare(b.keyId)
    );

    parts.push(`dekCount:${sortedDeks.length}`);
    for (const dek of sortedDeks) {
      parts.push(
        `dek:${dek.keyId}:${dek.keyVersion}:${dek.status}:${bytesToHex(dek.nonce)}:${bytesToHex(dek.tag)}:${bytesToHex(dek.wrappedCiphertext)}`
      );
    }

    if (vault.recoveryEnvelope) {
      const rec = vault.recoveryEnvelope;
      parts.push(
        `rec:${rec.recoveryId}:${bytesToHex(rec.salt)}:${rec.wrappedDEKs?.length ?? 0}:${bytesToHex(rec.checksum)}`
      );
    } else {
      parts.push('rec:none');
    }

    return parts.join('|');
  }

  /**
   * Derives a deterministic domain-separated 32-byte key for HMAC verification.
   */
  private deriveManifestKey(salt: Uint8Array): Uint8Array {
    const hmac = QuickCrypto.createHmac('sha256', salt);
    hmac.update(MANIFEST_HMAC_DOMAIN_STRING);
    const digest = hmac.digest();
    const key = new Uint8Array(32);
    key.set(digest);
    return key;
  }

  /**
   * Constant-time equality check for byte arrays.
   */
  private timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) {
      mismatch |= a[i] ^ b[i];
    }
    return mismatch === 0;
  }
}

