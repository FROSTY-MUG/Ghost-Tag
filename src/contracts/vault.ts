/**
 * @file vault.ts
 * @summary Ghost-Tag Vault Schema and Integrity Specifications.
 *
 * Defines the persistent data store schema for wrapped cryptographic keys,
 * KDF parameters, recovery pointers, and tamper-evident audit logs.
 *
 * ===========================================================================
 * CRITICAL SECURITY DIRECTIVE - FORBIDDEN FIELDS LIST
 * ===========================================================================
 * The following fields and data types are EXPLICITLY AND PERMANENTLY FORBIDDEN
 * from ever being stored, serialized, or retained in the Vault schema:
 *
 * 1. Plaintext Master Passphrase:
 *    NEVER store the user's master passphrase in plaintext, reversible format,
 *    or weak hash (MD5, SHA1, SHA256).
 *
 * 2. Plaintext Key Encryption Key (KEK):
 *    The 256-bit KEK derived via Argon2id MUST only exist in ephemeral volatile
 *    memory (RAM) during an active unlocked session and must be securely scrubbed/zeroed
 *    upon vault lock or process exit.
 *
 * 3. Plaintext Data Encryption Keys (DEKs):
 *    All 256-bit DEKs MUST NEVER be persisted in plaintext. They must be stored
 *    exclusively within `WrappedDEK` containers authenticated and encrypted via AES-256-GCM.
 *
 * 4. Plaintext Recovery Phrase / Mnemonic Words / Recovery Seed:
 *    The 24-word recovery phrase or raw 256-bit recovery seed MUST NEVER be saved to disk
 *    or cached in any persistent storage structure.
 *
 * 5. Plaintext Tag Payloads (Notes, Credentials, Configs, Asset IDs):
 *    Decrypted tag contents belong strictly to ephemeral presentation state and MUST NOT
 *    be cached or journaled into the persistent vault file.
 *
 * 6. De-anonymizing NFC Hardware UIDs Linked to Identifiable User Data:
 *    NFC tag hardware serial numbers (UIDs) must not be correlated with personal identities
 *    in plaintext long-term storage to prevent physical tracking.
 *
 * 7. Unsalted or Insecure Password Hashes:
 *    No intermediate verification digests without Argon2id salt and high work factors.
 * ===========================================================================
 */

import { GhostTagErrorCode } from './errors';
import { KdfParameters, WrappedDEK } from './keyHierarchy';
import { RecoveryEnvelope } from './recovery';
import { SupportedTagFamily } from './tags';

/**
 * Vault schema version number.
 * Serialized in Little-Endian byte order.
 */
export const VAULT_SCHEMA_VERSION = 0x0001 as const;

/**
 * Event types logged to the tamper-evident audit trail.
 */
export enum AuditEventType {
  /** Vault initialized and primary KEK derived. */
  VAULT_CREATED = 'VAULT_CREATED',
  /** Master passphrase verified; session unlocked. */
  VAULT_UNLOCKED = 'VAULT_UNLOCKED',
  /** Session terminated; volatile KEK wiped from memory. */
  VAULT_LOCKED = 'VAULT_LOCKED',
  /** User updated master passphrase; re-wrapped all active DEKs. */
  PASSPHRASE_CHANGED = 'PASSPHRASE_CHANGED',
  /** New DEK generated and wrapped for tag writing. */
  DEK_GENERATED = 'DEK_GENERATED',
  /** Existing DEK marked as rotated. */
  DEK_ROTATED = 'DEK_ROTATED',
  /** DEK marked as revoked. */
  DEK_REVOKED = 'DEK_REVOKED',
  /** NFC tag detected and envelope read from RF interface. */
  TAG_SCANNED = 'TAG_SCANNED',
  /** Envelope successfully decrypted and verified via GCM tag. */
  TAG_DECRYPTED = 'TAG_DECRYPTED',
  /** Encrypted envelope written and verified on NFC tag. */
  TAG_WRITTEN = 'TAG_WRITTEN',
  /** NFC tag sanitized and rewritten with empty/randomized NDEF. */
  TAG_WIPED = 'TAG_WIPED',
  /** Emergency recovery phrase generated and configured. */
  RECOVERY_CONFIGURED = 'RECOVERY_CONFIGURED',
  /** Recovery workflow initiated. */
  RECOVERY_INITIATED = 'RECOVERY_INITIATED',
  /** Recovery completed; DEKs restored via recovery KEK. */
  RECOVERY_COMPLETED = 'RECOVERY_COMPLETED',
  /** Recovery failed due to invalid phrase or corrupted envelope. */
  RECOVERY_FAILED = 'RECOVERY_FAILED',
  /** Audit log exported or viewed by authorized user. */
  AUDIT_EXPORTED = 'AUDIT_EXPORTED',
  /** Security or operational error recorded. */
  ERROR_RECORDED = 'ERROR_RECORDED',
}

/**
 * Individual entry in the vault's operational audit log.
 *
 * Security Properties:
 * - Tamper-Evident: Audit entries are chained using rolling SHA-256 hashes
 *   summarized in the `VaultManifest.auditHash`.
 * - Zero Secrets: Contains only metadata, timestamps, and error codes.
 *   Strictly forbidden from containing plaintext payload or key bytes.
 */
export interface AuditEntry {
  /**
   * Unique UUIDv4 identifier for the audit event.
   */
  readonly eventId: string;

  /**
   * Functional category of the audit event.
   */
  readonly eventType: AuditEventType;

  /**
   * Epoch timestamp in milliseconds when the event occurred.
   */
  readonly timestamp: number;

  /**
   * Operational return code (0 for SUCCESS, non-zero for error/warning).
   */
  readonly resultCode: number | string;

  /**
   * NFC tag family involved in the operation (or null if non-NFC event).
   */
  readonly tagFamily: SupportedTagFamily | string | null;

  /**
   * 16-byte hex key ID associated with this operation (or null if non-key event).
   */
  readonly keyId: string | null;

  /**
   * Envelope format version detected or generated (or null if not applicable).
   */
  readonly envelopeVersion: number | null;

  /**
   * Specific error code if the operation resulted in failure.
   */
  readonly errorCode: GhostTagErrorCode | null;
}

/**
 * Canonical vault metadata manifest authenticated by `manifestTag`.
 *
 * Security Properties:
 * - Authenticated via AES-256-GCM under the KEK.
 * - Guarantees the integrity of vault metadata, KDF configurations,
 *   and DEK key counts.
 */
export interface VaultManifest {
  /**
   * Unique identifier of the vault (UUIDv4).
   */
  readonly vaultId: string;

  /**
   * Vault creation timestamp (epoch ms).
   */
  readonly creationTime: number;

  /**
   * Schema version number (Little-Endian uint16).
   */
  readonly schemaVersion: number;

  /**
   * Total number of wrapped DEK containers in the vault.
   */
  readonly wrappedDekCount: number;

  /**
   * Array of key IDs currently managed by the vault.
   */
  readonly keyIds: readonly string[];

  /**
   * SHA-256 digest of the complete audit log chain.
   */
  readonly auditHash: Uint8Array;

  /**
   * Timestamp (epoch ms) of the most recent vault modification.
   */
  readonly lastModifiedTime: number;
}

/**
 * Complete Ghost-Tag Vault structure stored on persistent device storage.
 *
 * Security Properties:
 * - All secret key material is authenticated and encrypted (wrapped).
 * - Master passphrase KDF parameters are locked to prevent silent parameter downgrades.
 * - Manifest authentication tag validates entire vault configuration before operations proceed.
 */
export interface Vault {
  /**
   * Globally unique identifier for this vault (UUIDv4).
   */
  readonly vaultId: string;

  /**
   * Timestamp of initial vault creation (epoch milliseconds).
   */
  readonly creationTime: number;

  /**
   * 16-byte random salt used for Argon2id KEK derivation.
   */
  readonly argon2Salt: Uint8Array;

  /**
   * Argon2id cost parameters configured for this vault.
   */
  readonly argon2Params: KdfParameters;

  /**
   * Array of wrapped Data Encryption Keys.
   * Every key is encrypted via AES-256-GCM under the KEK.
   */
  readonly wrappedDEKs: readonly WrappedDEK[];

  /**
   * Recovery envelope enabling out-of-band vault restoration
   * via an independent high-entropy recovery phrase.
   */
  readonly recoveryEnvelope: RecoveryEnvelope;

  /**
   * Tamper-evident operational audit trail.
   */
  readonly auditMetadata: readonly AuditEntry[];

  /**
   * 16-byte AES-256-GCM authentication tag protecting the serialized VaultManifest.
   */
  readonly manifestTag: Uint8Array;
}
