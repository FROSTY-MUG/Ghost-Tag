/**
 * @file dekManager.ts
 * @summary Data Encryption Key (DEK) Lifecycle and Envelope Key Management.
 *
 * Implements generation, storage, wrapping, rotation, and revocation of 256-bit
 * Data Encryption Keys (DEKs). DEKs are never stored in plaintext on disk and are
 * wrapped under the Key Encryption Key (KEK) using AES-256-GCM.
 */

import {
  KeyStatus,
  WrappedDEK,
  KEY_ID_BYTE_LENGTH,
  KEK_BYTE_LENGTH,
} from '../contracts/keyHierarchy';
import { Buffer } from 'buffer';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { generateDEK, generateKeyId } from '../crypto/random';
import { wrapDEK, unwrapDEK, bytesToHex, hexToBytes } from '../crypto/keyWrap';
import { zeroize } from '../crypto/secureMemory';
import { VaultDatabase } from './database';

/** Storage key prefix for individual wrapped DEKs. */
const DEK_KEY_PREFIX = 'dek_';

/** Storage key for the index of all managed key IDs. */
const DEK_INDEX_KEY = 'dek_index';

/** Serialized JSON schema for persisting WrappedDEK objects. */
interface SerializedWrappedDEK {
  readonly keyId: string;
  readonly wrappedCiphertext: string;
  readonly nonce: string;
  readonly tag: string;
  readonly creationTime: number;
  readonly keyVersion: number;
  readonly status: KeyStatus;
}

/**
 * Manages the persistent lifecycle of Data Encryption Keys (DEKs).
 */
export class DEKManager {
  private readonly database: VaultDatabase;

  /**
   * Constructs a new DEKManager.
   *
   * @param database Initialized VaultDatabase instance for persistent storage.
   */
  constructor(database: VaultDatabase) {
    this.database = database;
  }

  /**
   * Generates a new 256-bit Data Encryption Key, wraps it under the KEK, and persists it.
   *
   * Security Properties:
   * - Raw DEK is zeroized immediately after wrapping.
   * - Only the authenticated AES-256-GCM wrapped ciphertext is persisted.
   *
   * @param kek 32-byte active Key Encryption Key.
   * @returns Newly generated and persisted WrappedDEK container.
   * @throws {GhostTagError} If KEK is invalid or storage fails.
   */
  public async createDEK(kek: Uint8Array): Promise<WrappedDEK> {
    if (!kek || kek.length !== KEK_BYTE_LENGTH) {
      throw new GhostTagError({
        code: GhostTagErrorCode.ARGON2ID_FAILED,
        userMessage: `KEK must be ${KEK_BYTE_LENGTH} bytes for DEK wrapping.`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    const rawDek = generateDEK();
    const rawKeyId = generateKeyId();

    try {
      const wrapped = wrapDEK(kek, rawDek, rawKeyId, 1);
      await this.saveWrappedDEK(wrapped);
      await this.appendKeyIdToIndex(wrapped.keyId);
      return wrapped;
    } finally {
      // Direct security requirement: unwrapped DEK must be zeroized after use
      zeroize(rawDek);
    }
  }

  /**
   * Unwraps and retrieves the raw 256-bit DEK matching the specified keyId.
   *
   * Security Properties:
   * - Callers MUST zeroize the returned DEK buffer immediately after cryptographic use.
   * - Revoked keys cannot be unwrapped.
   *
   * @param keyId 16-byte DEK identifier.
   * @param kek 32-byte active Key Encryption Key.
   * @returns Raw 32-byte Data Encryption Key.
   * @throws {GhostTagError} If key is not found, revoked, or unwrapping fails.
   */
  public async getDEK(keyId: Uint8Array | string, kek: Uint8Array): Promise<Uint8Array> {
    const hexKeyId = this.normalizeKeyId(keyId);
    const wrapped = await this.loadWrappedDEK(hexKeyId);

    if (!wrapped) {
      throw new GhostTagError({
        code: GhostTagErrorCode.KEY_NOT_FOUND,
        userMessage: `No Data Encryption Key found for ID: ${hexKeyId}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    if (wrapped.status === KeyStatus.REVOKED) {
      throw new GhostTagError({
        code: GhostTagErrorCode.KEY_UNAVAILABLE,
        userMessage: `Data Encryption Key ${hexKeyId} has been revoked and cannot be used.`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }

    return unwrapDEK(kek, wrapped);
  }

  /**
   * Lists all 16-byte key IDs currently managed by the vault.
   *
   * @returns Array of 16-byte key ID byte arrays.
   */
  public async listKeyIds(): Promise<Uint8Array[]> {
    const index = await this.getKeyIndex();
    return index.map((hexId) => hexToBytes(hexId));
  }

  /**
   * Rotates a DEK by marking the existing key as ROTATED and creating a fresh ACTIVE DEK.
   *
   * @param oldKeyId 16-byte identifier of the key to rotate.
   * @param kek 32-byte active Key Encryption Key.
   * @returns Newly generated WrappedDEK container.
   * @throws {GhostTagError} If oldKeyId is not found or already revoked.
   */
  public async rotateDEK(oldKeyId: Uint8Array, kek: Uint8Array): Promise<WrappedDEK> {
    const hexOldId = this.normalizeKeyId(oldKeyId);
    const existing = await this.loadWrappedDEK(hexOldId);

    if (!existing) {
      throw new GhostTagError({
        code: GhostTagErrorCode.KEY_NOT_FOUND,
        userMessage: `Cannot rotate non-existent key ID: ${hexOldId}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    if (existing.status === KeyStatus.REVOKED) {
      throw new GhostTagError({
        code: GhostTagErrorCode.KEY_UNAVAILABLE,
        userMessage: `Cannot rotate revoked key ID: ${hexOldId}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    // Mark existing key as ROTATED (retained for tag decryption, forbidden for new writes)
    const updatedOld: WrappedDEK = {
      ...existing,
      status: KeyStatus.ROTATED,
    };
    await this.saveWrappedDEK(updatedOld);

    // Generate new active DEK
    return this.createDEK(kek);
  }

  /**
   * Permanently revokes a Data Encryption Key.
   *
   * @param keyId 16-byte identifier of the key to revoke.
   * @throws {GhostTagError} If key is not found.
   */
  public async revokeDEK(keyId: Uint8Array): Promise<void> {
    const hexId = this.normalizeKeyId(keyId);
    const existing = await this.loadWrappedDEK(hexId);

    if (!existing) {
      throw new GhostTagError({
        code: GhostTagErrorCode.KEY_NOT_FOUND,
        userMessage: `Cannot revoke non-existent key ID: ${hexId}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    const revoked: WrappedDEK = {
      ...existing,
      status: KeyStatus.REVOKED,
    };
    await this.saveWrappedDEK(revoked);
  }

  /**
   * Retrieves the operational lifecycle status of a DEK.
   *
   * @param keyId 16-byte identifier.
   * @returns KeyStatus (ACTIVE, ROTATED, or REVOKED).
   * @throws {GhostTagError} If key is not found.
   */
  public async getKeyStatus(keyId: Uint8Array): Promise<KeyStatus> {
    const hexId = this.normalizeKeyId(keyId);
    const wrapped = await this.loadWrappedDEK(hexId);

    if (!wrapped) {
      throw new GhostTagError({
        code: GhostTagErrorCode.KEY_NOT_FOUND,
        userMessage: `Key ID not found: ${hexId}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    return wrapped.status;
  }

  /**
   * Retrieves all WrappedDEK records currently in the vault.
   *
   * @returns Array of WrappedDEK structures.
   */
  public async getAllWrappedDEKs(): Promise<WrappedDEK[]> {
    const index = await this.getKeyIndex();
    const result: WrappedDEK[] = [];

    for (const hexId of index) {
      const dek = await this.loadWrappedDEK(hexId);
      if (dek) {
        result.push(dek);
      }
    }

    return result;
  }

  /**
   * Normalizes a 16-byte Uint8Array or 32-char hex string keyId to a lowercase hexadecimal string.
   */
  private normalizeKeyId(keyId: Uint8Array | string): string {
    if (typeof keyId === 'string') {
      if (keyId.length !== KEY_ID_BYTE_LENGTH * 2) {
        throw new GhostTagError({
          code: GhostTagErrorCode.KEY_NOT_FOUND,
          userMessage: `Invalid keyId format: expected ${KEY_ID_BYTE_LENGTH * 2} hex characters.`,
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.ERROR,
        });
      }
      return keyId.toLowerCase();
    }
    if (!keyId || !(keyId instanceof Uint8Array) || keyId.length !== KEY_ID_BYTE_LENGTH) {
      throw new GhostTagError({
        code: GhostTagErrorCode.KEY_NOT_FOUND,
        userMessage: `Invalid keyId format: expected ${KEY_ID_BYTE_LENGTH} bytes.`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }
    return bytesToHex(keyId);
  }

  /**
   * Persists a WrappedDEK object to the database.
   */
  private async saveWrappedDEK(wrapped: WrappedDEK): Promise<void> {
    const serialized: SerializedWrappedDEK = {
      keyId: wrapped.keyId,
      wrappedCiphertext: bytesToHex(wrapped.wrappedCiphertext),
      nonce: bytesToHex(wrapped.nonce),
      tag: bytesToHex(wrapped.tag),
      creationTime: wrapped.creationTime,
      keyVersion: wrapped.keyVersion,
      status: wrapped.status,
    };

    const json = JSON.stringify(serialized);
    const buf = Buffer.from(json, 'utf8');
    const bytes = new Uint8Array(buf.length);
    bytes.set(buf);
    await this.database.store(`${DEK_KEY_PREFIX}${wrapped.keyId}`, bytes);
  }

  /**
   * Loads and deserializes a WrappedDEK object from the database by hex keyId.
   */
  private async loadWrappedDEK(hexKeyId: string): Promise<WrappedDEK | null> {
    const rawBytes = await this.database.retrieve(`${DEK_KEY_PREFIX}${hexKeyId}`);
    if (!rawBytes) {
      return null;
    }

    try {
      const json = Buffer.from(rawBytes).toString('utf8');
      const parsed: SerializedWrappedDEK = JSON.parse(json);

      return {
        keyId: parsed.keyId,
        wrappedCiphertext: hexToBytes(parsed.wrappedCiphertext),
        nonce: hexToBytes(parsed.nonce),
        tag: hexToBytes(parsed.tag),
        creationTime: parsed.creationTime,
        keyVersion: parsed.keyVersion,
        status: parsed.status,
      };
    } catch {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: `Corrupted WrappedDEK record encountered for key ID: ${hexKeyId}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }
  }

  /**
   * Retrieves the index of all managed key IDs.
   */
  private async getKeyIndex(): Promise<string[]> {
    const rawBytes = await this.database.retrieve(DEK_INDEX_KEY);
    if (!rawBytes) {
      return [];
    }

    try {
      const json = Buffer.from(rawBytes).toString('utf8');
      return JSON.parse(json) as string[];
    } catch {
      return [];
    }
  }

  /**
   * Appends a new keyId to the persistent key index.
   */
  private async appendKeyIdToIndex(hexKeyId: string): Promise<void> {
    const index = await this.getKeyIndex();
    if (!index.includes(hexKeyId)) {
      index.push(hexKeyId);
      const json = JSON.stringify(index);
      const buf = Buffer.from(json, 'utf8');
      const bytes = new Uint8Array(buf.length);
      bytes.set(buf);
      await this.database.store(DEK_INDEX_KEY, bytes);
    }
  }
}
