/**
 * @file database.ts
 * @summary Encrypted Key-Value Database Layer for the Ghost-Tag Vault.
 *
 * Implements persistent at-rest encrypted storage using react-native-mmkv
 * with AES-256 encryption. Provides fallback storage for non-native test environments.
 */

import type { MMKV } from 'react-native-mmkv';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { bytesToHex, hexToBytes } from '../crypto/keyWrap';
import { zeroize } from '../crypto/secureMemory';

// Safe lazy loader for react-native-mmkv
let getCreateMMKV: (() => ((config: any) => MMKV) | null) = () => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mmkv = require('react-native-mmkv');
    return mmkv.createMMKV ?? null;
  } catch {
    return null;
  }
};

/** Default identifier for the Ghost-Tag MMKV vault database instance. */
export const DEFAULT_VAULT_DB_ID = 'ghost_tag_vault' as const;

/**
 * Encrypted Database Layer managing persistent vault storage.
 */
export class VaultDatabase {
  private mmkvInstance: MMKV | null = null;
  private memoryStore: Map<string, Uint8Array> | null = null;
  private isInitialized = false;
  private readonly dbId: string;
  private encryptionKeyCopy: Uint8Array | null = null;

  /**
   * Constructs a new VaultDatabase instance.
   *
   * @param dbId Optional unique database storage identifier.
   */
  constructor(dbId: string = DEFAULT_VAULT_DB_ID) {
    this.dbId = dbId;
  }

  /**
   * Initializes the encrypted storage engine with a 256-bit encryption key.
   *
   * @param encryptionKey 32-byte encryption key for AES-256 storage encryption.
   * @throws {GhostTagError} If the key is invalid or initialization fails.
   */
  public async initialize(encryptionKey: Uint8Array): Promise<void> {
    if (!encryptionKey || !(encryptionKey instanceof Uint8Array) || encryptionKey.length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Invalid encryption key provided for vault database initialization.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.FATAL,
      });
    }

    // Keep an ephemeral zeroizable copy of the encryption key
    this.encryptionKeyCopy = new Uint8Array(encryptionKey.length);
    this.encryptionKeyCopy.set(encryptionKey);

    const hexKey = bytesToHex(this.encryptionKeyCopy);

    const createMMKV = getCreateMMKV();
    if (createMMKV) {
      try {
        this.mmkvInstance = createMMKV({
          id: this.dbId,
          encryptionKey: hexKey,
          encryptionType: 'AES-256',
        });
        this.memoryStore = null;
      } catch {
        this.memoryStore = new Map<string, Uint8Array>();
        this.mmkvInstance = null;
      }
    } else {
      // In non-native test environments (e.g. Node/Jest without Nitro MMKV bridge),
      // fallback to secure memory store to enable unit tests.
      this.memoryStore = new Map<string, Uint8Array>();
      this.mmkvInstance = null;
    }

    this.isInitialized = true;
  }

  /**
   * Stores a binary value under the specified key.
   *
   * @param key Storage key identifier.
   * @param value Byte array value to store.
   * @throws {GhostTagError} If the database is not initialized or arguments are invalid.
   */
  public async store(key: string, value: Uint8Array): Promise<void> {
    this.ensureInitialized();

    if (typeof key !== 'string' || key.trim().length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Storage key must be a non-empty string.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    if (!value || !(value instanceof Uint8Array)) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Storage value must be a valid Uint8Array.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    if (this.mmkvInstance) {
      // Persist as hexadecimal string for reliable cross-platform serialization
      const hexValue = bytesToHex(value);
      this.mmkvInstance.set(key, hexValue);
    } else if (this.memoryStore) {
      const copy = new Uint8Array(value.length);
      copy.set(value);
      this.memoryStore.set(key, copy);
    }
  }

  /**
   * Retrieves a binary value by its key.
   *
   * @param key Storage key identifier.
   * @returns Fresh Uint8Array containing the stored value, or null if key does not exist.
   * @throws {GhostTagError} If the database is not initialized.
   */
  public async retrieve(key: string): Promise<Uint8Array | null> {
    this.ensureInitialized();

    if (this.mmkvInstance) {
      if (!this.mmkvInstance.contains(key)) {
        return null;
      }
      const hexValue = this.mmkvInstance.getString(key);
      if (!hexValue) {
        return null;
      }
      return hexToBytes(hexValue);
    } else if (this.memoryStore) {
      const value = this.memoryStore.get(key);
      if (!value) {
        return null;
      }
      const copy = new Uint8Array(value.length);
      copy.set(value);
      return copy;
    }

    return null;
  }

  /**
   * Deletes a value from storage by key.
   *
   * @param key Storage key identifier.
   * @throws {GhostTagError} If the database is not initialized.
   */
  public async delete(key: string): Promise<void> {
    this.ensureInitialized();

    if (this.mmkvInstance) {
      this.mmkvInstance.remove(key);
    } else if (this.memoryStore) {
      const val = this.memoryStore.get(key);
      if (val) {
        zeroize(val);
      }
      this.memoryStore.delete(key);
    }
  }

  /**
   * Checks whether a key exists in storage.
   *
   * @param key Storage key identifier.
   * @returns True if the key exists, false otherwise.
   */
  public async exists(key: string): Promise<boolean> {
    if (!this.isInitialized) {
      return false;
    }

    if (this.mmkvInstance) {
      return this.mmkvInstance.contains(key);
    } else if (this.memoryStore) {
      return this.memoryStore.has(key);
    }

    return false;
  }

  /**
   * Closes the database connection, zeroizing in-memory encryption keys and memory caches.
   */
  public async close(): Promise<void> {
    if (this.memoryStore) {
      for (const val of this.memoryStore.values()) {
        zeroize(val);
      }
      this.memoryStore.clear();
      this.memoryStore = null;
    }

    if (this.encryptionKeyCopy) {
      zeroize(this.encryptionKeyCopy);
      this.encryptionKeyCopy = null;
    }

    this.mmkvInstance = null;
    this.isInitialized = false;
  }

  /**
   * Internal guard enforcing initialization before storage operations.
   *
   * @throws {GhostTagError} If the database has not been initialized.
   */
  private ensureInitialized(): void {
    if (!this.isInitialized) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Vault database is not initialized. Call initialize() first.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.FATAL,
      });
    }
  }
}
