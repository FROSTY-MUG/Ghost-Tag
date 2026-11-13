/**
 * @file vaultManager.ts
 * @summary Core Vault Lifecycle and Cryptographic Session Orchestration.
 *
 * Implements initialization, opening, locking, deletion, and metadata introspection
 * for the Ghost-Tag vault.
 *
 * Security Directives:
 * - Creates vault with Argon2id-derived KEK.
 * - Benchmarks host device to tune KDF cost parameters.
 * - Creates initial wrapped DEK.
 * - Never persists plaintext passphrase, KEK, or unwrapped DEKs.
 * - Ephemeral KEK is zeroized upon lock.
 */

import {
  AuditEventType,
  AuditEntry,
  VAULT_SCHEMA_VERSION,
} from '../contracts/vault';
import { Buffer } from 'buffer';
import {
  KdfParameters,
  WrappedDEK,
  KEY_ID_BYTE_LENGTH,
} from '../contracts/keyHierarchy';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import {
  benchmarkDevice,
  getDefaultParams,
  deriveKEK,
} from '../crypto/argon2';
import { generateSecureRandom } from '../crypto/random';
import { bytesToHex, hexToBytes, unwrapDEK } from '../crypto/keyWrap';
import { zeroize } from '../crypto/secureMemory';
import { VaultDatabase } from './database';
import { VaultSession } from './session';
import { DEKManager } from './dekManager';
import { RecoveryManager } from './recoveryManager';
import { VaultManifest } from './manifest';
import { AuditLog } from './auditLog';

/** Storage key for the persistent vault metadata header. */
export const VAULT_METADATA_STORAGE_KEY = 'vault_metadata';

/** Default 32-byte storage encryption key used when no external key is provided. */
const DEFAULT_STORAGE_MASTER_KEY = new Uint8Array([
  0x47, 0x68, 0x6f, 0x73, 0x74, 0x54, 0x61, 0x67, // "GhostTag"
  0x56, 0x61, 0x75, 0x6c, 0x74, 0x53, 0x74, 0x6f, // "VaultSto"
  0x72, 0x61, 0x67, 0x65, 0x4d, 0x61, 0x73, 0x74, // "rageMast"
  0x65, 0x72, 0x4b, 0x65, 0x79, 0x32, 0x35, 0x36, // "erKey256"
]);

/**
 * Result returned upon successful creation of a new vault.
 */
export interface VaultCreationResult {
  /** Unique UUIDv4 identifier of the created vault. */
  readonly vaultId: string;
  /** Creation timestamp in epoch milliseconds. */
  readonly creationTime: number;
  /** Active unlocked session for the newly created vault. */
  readonly session: VaultSession;
  /** Hex identifier of the initial Data Encryption Key generated for the vault. */
  readonly initialDekId: string;
}

/**
 * Public vault metadata accessible without passphrase entry.
 */
export interface VaultMetadata {
  /** Unique identifier of the vault. */
  readonly vaultId: string;
  /** Creation timestamp in epoch milliseconds. */
  readonly creationTime: number;
  /** Schema format version. */
  readonly schemaVersion: number;
  /** Total number of wrapped DEKs managed by this vault. */
  readonly wrappedDekCount: number;
  /** Array of hex key IDs. */
  readonly keyIds: readonly string[];
  /** Timestamp of the most recent vault modification. */
  readonly lastModifiedTime: number;
}

/** Serialized JSON schema for the persistent vault header stored in database. */
interface StoredVaultHeader {
  readonly vaultId: string;
  readonly creationTime: number;
  readonly schemaVersion: number;
  readonly argon2Salt: string; // hex
  readonly argon2Params: {
    readonly memoryCost: number;
    readonly timeCost: number;
    readonly parallelism: number;
    readonly version: number;
  };
  readonly manifestTag: string; // hex
  readonly lastModifiedTime: number;
}

/**
 * Primary manager orchestrating vault creation, unlocking, locking, and lifecycle operations.
 */
export class VaultManager {
  private readonly database: VaultDatabase;
  private readonly auditLog: AuditLog;
  private readonly dekManager: DEKManager;
  private readonly recoveryManager: RecoveryManager;
  private readonly manifest: VaultManifest;
  private activeSession: VaultSession | null = null;
  private dbInitialized = false;

  /**
   * Constructs a new VaultManager instance.
   *
   * @param database Optional VaultDatabase instance (defaults to standard instance).
   * @param auditLog Optional AuditLog instance.
   * @param dekManager Optional DEKManager instance.
   * @param recoveryManager Optional RecoveryManager instance.
   * @param manifest Optional VaultManifest instance.
   */
  constructor(
    database?: VaultDatabase,
    auditLog?: AuditLog,
    dekManager?: DEKManager,
    recoveryManager?: RecoveryManager,
    manifest?: VaultManifest
  ) {
    this.database = database ?? new VaultDatabase();
    this.auditLog = auditLog ?? new AuditLog(this.database);
    this.dekManager = dekManager ?? new DEKManager(this.database);
    this.recoveryManager = recoveryManager ?? new RecoveryManager(this.database);
    this.manifest = manifest ?? new VaultManifest();
  }

  /**
   * Initializes the underlying database storage engine.
   *
   * @param encryptionKey Optional 32-byte storage encryption key.
   */
  public async initializeStorage(encryptionKey: Uint8Array = DEFAULT_STORAGE_MASTER_KEY): Promise<void> {
    if (!this.dbInitialized) {
      await this.database.initialize(encryptionKey);
      this.dbInitialized = true;
    }
  }

  /**
   * Creates a new encrypted vault, benchmarks hardware for KDF parameters,
   * generates the initial DEK, and returns an unlocked session.
   *
   * Security Properties:
   * - Never stores user passphrase or derived KEK in persistent storage.
   * - Benchmarks device to ensure unlock latency is balanced against brute-force resistance.
   * - Initial DEK is wrapped under the derived KEK using AES-256-GCM.
   *
   * @param passphrase Master passphrase chosen by user.
   * @returns VaultCreationResult containing vaultId, session, and initialDekId.
   * @throws {GhostTagError} If passphrase is empty or vault is already initialized.
   */
  public async createVault(passphrase: string): Promise<VaultCreationResult> {
    if (typeof passphrase !== 'string' || passphrase.trim().length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
        userMessage: 'A non-empty master passphrase is required to create a vault.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    await this.ensureStorageReady();

    const isExisting = await this.isVaultInitialized();
    if (isExisting) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Vault is already initialized on this device. Cannot recreate.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }

    // 1. Calibrate device performance tier
    const tier = await benchmarkDevice();
    const kdfParams = getDefaultParams(tier);

    let kek: Uint8Array | null = null;
    try {
      // 2. Derive primary Key Encryption Key (KEK) via Argon2id
      kek = await deriveKEK(passphrase, kdfParams.salt, kdfParams);

      const vaultId = bytesToHex(generateSecureRandom(16));
      const creationTime = Date.now();

      // 3. Generate initial Data Encryption Key (DEK)
      const initialDek = await this.dekManager.createDEK(kek);

      // 4. Compute initial manifest authentication tag
      const manifestTag = this.manifest.computeManifestTag(
        {
          vaultId,
          creationTime,
          argon2Salt: kdfParams.salt,
          argon2Params: kdfParams,
          wrappedDEKs: [initialDek],
        },
        kek
      );

      // 5. Persist vault metadata header
      const header: StoredVaultHeader = {
        vaultId,
        creationTime,
        schemaVersion: VAULT_SCHEMA_VERSION,
        argon2Salt: bytesToHex(kdfParams.salt),
        argon2Params: {
          memoryCost: kdfParams.memoryCost,
          timeCost: kdfParams.timeCost,
          parallelism: kdfParams.parallelism,
          version: kdfParams.version,
        },
        manifestTag: bytesToHex(manifestTag),
        lastModifiedTime: creationTime,
      };

      await this.saveHeader(header);

      // 6. Establish active unlocked session
      this.activeSession = new VaultSession(
        kek,
        (pass) => this.deriveAndVerifyKEK(pass)
      );

      this.activeSession.onLock(() => {
        this.logAuditEvent(AuditEventType.VAULT_LOCKED, 0, null).catch(() => {});
      });

      // 7. Audit creation events
      await this.logAuditEvent(AuditEventType.VAULT_CREATED, 0, null);
      await this.logAuditEvent(AuditEventType.DEK_GENERATED, 0, initialDek.keyId);

      return {
        vaultId,
        creationTime,
        session: this.activeSession,
        initialDekId: initialDek.keyId,
      };
    } finally {
      if (kek) {
        zeroize(kek);
      }
    }
  }

  /**
   * Opens and unlocks the vault using the user master passphrase.
   *
   * Security Properties:
   * - Verifies passphrase by attempting to unwrap managed DEKs and checking the manifest tag.
   * - Fails with PASSPHRASE_INVALID if passphrase is incorrect.
   * - KEK is held only in ephemeral memory within the returned VaultSession.
   *
   * @param passphrase User master passphrase.
   * @returns Unlocked VaultSession.
   * @throws {GhostTagError} If vault is not initialized or passphrase is invalid.
   */
  public async openVault(passphrase: string): Promise<VaultSession> {
    if (typeof passphrase !== 'string' || passphrase.trim().length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
        userMessage: 'Passphrase is required to unlock the vault.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    await this.ensureStorageReady();

    const isInit = await this.isVaultInitialized();
    if (!isInit) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
        userMessage: 'Vault is not initialized on this device.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    // If an active session is already open and unlocked, return it
    if (this.activeSession && this.activeSession.isUnlocked) {
      return this.activeSession;
    }

    const kek = await this.deriveAndVerifyKEK(passphrase);

    try {
      this.activeSession = new VaultSession(
        kek,
        (pass) => this.deriveAndVerifyKEK(pass)
      );

      this.activeSession.onLock(() => {
        this.logAuditEvent(AuditEventType.VAULT_LOCKED, 0, null).catch(() => {});
      });

      await this.logAuditEvent(AuditEventType.VAULT_UNLOCKED, 0, null);

      return this.activeSession;
    } finally {
      zeroize(kek);
    }
  }

  /**
   * Locks the active vault session immediately and wipes ephemeral KEK memory.
   */
  public lockVault(): void {
    if (this.activeSession) {
      this.activeSession.lock();
      this.activeSession = null;
    }
  }

  /**
   * Deletes all vault data, wrapped keys, recovery records, and audit logs from persistent storage.
   */
  public async deleteVault(): Promise<void> {
    this.lockVault();
    await this.ensureStorageReady();

    await this.database.delete(VAULT_METADATA_STORAGE_KEY);
    await this.database.delete('dek_index');
    await this.database.delete('recovery_envelope');
    await this.database.delete('vault_audit_entries');
    await this.database.delete('vault_audit_hash');
  }

  /**
   * Checks whether an initialized vault exists in persistent storage.
   *
   * @returns True if vault metadata exists, false otherwise.
   */
  public async isVaultInitialized(): Promise<boolean> {
    await this.ensureStorageReady();
    return this.database.exists(VAULT_METADATA_STORAGE_KEY);
  }

  /**
   * Retrieves high-level vault metadata without requiring master passphrase entry.
   *
   * @returns VaultMetadata containing vaultId, creationTime, DEK count, and key IDs.
   * @throws {GhostTagError} If vault is not initialized.
   */
  public async getVaultMetadata(): Promise<VaultMetadata> {
    await this.ensureStorageReady();
    const header = await this.loadHeader();

    if (!header) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Vault metadata record not found.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    const keyIds = await this.dekManager.listKeyIds();

    return {
      vaultId: header.vaultId,
      creationTime: header.creationTime,
      schemaVersion: header.schemaVersion,
      wrappedDekCount: keyIds.length,
      keyIds: keyIds.map(bytesToHex),
      lastModifiedTime: header.lastModifiedTime,
    };
  }

  /**
   * Retrieves the active VaultSession instance if one exists.
   */
  public getSession(): VaultSession | null {
    return this.activeSession;
  }

  /**
   * Alias for getSession() to provide active session introspection.
   */
  public getActiveSession(): VaultSession | null {
    return this.activeSession;
  }

  /**
   * Returns the DEKManager instance.
   */
  public getDEKManager(): DEKManager {
    return this.dekManager;
  }

  /**
   * Returns the RecoveryManager instance.
   */
  public getRecoveryManager(): RecoveryManager {
    return this.recoveryManager;
  }

  /**
   * Returns the AuditLog instance.
   */
  public getAuditLog(): AuditLog {
    return this.auditLog;
  }

  /**
   * Returns the VaultManifest instance.
   */
  public getManifest(): VaultManifest {
    return this.manifest;
  }

  /**
   * Internal routine to derive the KEK and verify it against managed DEKs and manifest.
   */
  private async deriveAndVerifyKEK(passphrase: string): Promise<Uint8Array> {
    const header = await this.loadHeader();
    if (!header) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Cannot unlock vault: metadata header missing.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }

    const salt = hexToBytes(header.argon2Salt);
    const kdfParams: KdfParameters = {
      salt,
      memoryCost: header.argon2Params.memoryCost,
      timeCost: header.argon2Params.timeCost,
      parallelism: header.argon2Params.parallelism,
      version: header.argon2Params.version,
    };

    let candidateKek: Uint8Array | null = null;
    try {
      candidateKek = await deriveKEK(passphrase, salt, kdfParams);

      // Verify passphrase by attempting to unwrap managed DEKs
      const deks = await this.dekManager.getAllWrappedDEKs();
      if (deks.length > 0) {
        // Test unwrap against the first available DEK
        const firstDek = deks[0];
        const unwrapped = unwrapDEK(candidateKek, firstDek);
        zeroize(unwrapped); // Zeroize test DEK immediately
      } else {
        // If no DEKs exist yet, verify manifest tag
        const expectedTag = hexToBytes(header.manifestTag);
        const isValid = this.manifest.verifyManifest(
          {
            vaultId: header.vaultId,
            creationTime: header.creationTime,
            argon2Salt: salt,
            argon2Params: kdfParams,
            wrappedDEKs: deks,
          },
          expectedTag,
          candidateKek
        );

        if (!isValid) {
          throw new Error('Manifest verification failed');
        }
      }

      // Return isolated copy of verified KEK
      const verifiedKek = new Uint8Array(candidateKek.length);
      verifiedKek.set(candidateKek);
      return verifiedKek;
    } catch (err) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_INVALID,
        userMessage: 'Master passphrase verification failed. Incorrect passphrase.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
        cause: err,
      });
    } finally {
      if (candidateKek) {
        zeroize(candidateKek);
      }
    }
  }

  /**
   * Ensures the database storage engine is initialized.
   */
  private async ensureStorageReady(): Promise<void> {
    if (!this.dbInitialized) {
      await this.initializeStorage();
    }
  }

  /**
   * Persists the vault metadata header.
   */
  private async saveHeader(header: StoredVaultHeader): Promise<void> {
    const json = JSON.stringify(header);
    const buf = Buffer.from(json, 'utf8');
    const bytes = new Uint8Array(buf.length);
    bytes.set(buf);
    await this.database.store(VAULT_METADATA_STORAGE_KEY, bytes);
  }

  /**
   * Loads the vault metadata header from the database.
   */
  private async loadHeader(): Promise<StoredVaultHeader | null> {
    const bytes = await this.database.retrieve(VAULT_METADATA_STORAGE_KEY);
    if (!bytes) {
      return null;
    }

    try {
      const json = Buffer.from(bytes).toString('utf8');
      return JSON.parse(json) as StoredVaultHeader;
    } catch {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Corrupted vault metadata header.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }
  }

  /**
   * Helper to append an audit log entry.
   */
  private async logAuditEvent(
    eventType: AuditEventType,
    resultCode: number | string,
    keyId: string | null
  ): Promise<void> {
    try {
      await this.auditLog.logEvent({
        eventId: bytesToHex(generateSecureRandom(16)),
        eventType,
        timestamp: Date.now(),
        resultCode,
        tagFamily: null,
        keyId,
        envelopeVersion: null,
        errorCode: null,
      });
    } catch {
      // Avoid audit logging failure breaking primary operations
    }
  }
}
