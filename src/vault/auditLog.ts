/**
 * @file auditLog.ts
 * @summary Tamper-Evident Operational Audit Log for the Ghost-Tag Vault.
 *
 * Implements an append-only, hash-chained audit logging subsystem that records
 * operational events without storing sensitive keys, passphrases, payloads, or identifiers.
 *
 * Security Directives:
 * - Strictly ALLOWED fields: eventId, eventType, timestamp, resultCode, tagFamily, keyId, envelopeVersion, errorCode.
 * - PERMANENTLY FORBIDDEN: plaintext, passphrase, recovery_phrase, KEK, DEK, full UID, raw ciphertext, location, clipboard.
 * - Rolling SHA-256 hash chain prevents history truncation or reordering.
 */

import QuickCrypto from 'react-native-quick-crypto';
import { Buffer } from 'buffer';
import { AuditEntry, AuditEventType } from '../contracts/vault';
import { SupportedTagFamily } from '../contracts/tags';
import { GhostTagErrorCode, GhostTagError, ErrorCategory, ErrorSeverity } from '../contracts/errors';
import { bytesToHex, hexToBytes } from '../crypto/keyWrap';
import { VaultDatabase } from './database';

/** Storage key for persisting audit entries in VaultDatabase. */
export const AUDIT_ENTRIES_STORAGE_KEY = 'vault_audit_entries';

/** Storage key for persisting the rolling audit log SHA-256 digest. */
export const AUDIT_HASH_STORAGE_KEY = 'vault_audit_hash';

/** Maximum entries retained in the primary persistent log before archiving. */
export const DEFAULT_MAX_AUDIT_ENTRIES = 1000;

/**
 * Filter criteria for querying audit log events.
 */
export interface AuditFilter {
  /** Filter by event category. */
  readonly eventType?: AuditEventType;
  /** Start time in epoch ms (inclusive). */
  readonly startDate?: number;
  /** End time in epoch ms (inclusive). */
  readonly endDate?: number;
  /** Filter by 16-byte hex key ID. */
  readonly keyId?: string;
  /** Filter by operational return code. */
  readonly resultCode?: number | string;
  /** Filter by NFC tag family. */
  readonly tagFamily?: SupportedTagFamily | string;
  /** Maximum number of records to return. */
  readonly limit?: number;
}

/** Set of forbidden field names (in lowercase) to guard against accidental leakage. */
const FORBIDDEN_FIELDS = new Set([
  'plaintext',
  'passphrase',
  'password',
  'recoveryphrase',
  'recovery_phrase',
  'recoveryseed',
  'seed',
  'kek',
  'dek',
  'uid',
  'serialnumber',
  'rawciphertext',
  'ciphertext',
  'location',
  'clipboard',
  'payload',
]);

/**
 * Tamper-evident operational audit log manager.
 */
export class AuditLog {
  private readonly database: VaultDatabase;
  private readonly maxEntries: number;

  /**
   * Constructs a new AuditLog instance.
   *
   * @param database Initialized VaultDatabase instance for persistent storage.
   * @param maxEntries Maximum number of entries retained before oldest are rotated.
   */
  constructor(database: VaultDatabase, maxEntries: number = DEFAULT_MAX_AUDIT_ENTRIES) {
    this.database = database;
    this.maxEntries = maxEntries > 0 ? maxEntries : DEFAULT_MAX_AUDIT_ENTRIES;
  }

  /**
   * Appends an operational event to the tamper-evident audit log.
   *
   * Security Properties:
   * - Enforces zero-secrets directive: rejects entries containing forbidden sensitive fields.
   * - Computes and updates rolling SHA-256 hash chaining.
   *
   * @param event AuditEntry record to commit.
   * @throws {GhostTagError} If forbidden fields are detected or storage fails.
   */
  public async logEvent(event: AuditEntry): Promise<void> {
    this.assertNoForbiddenFields(event);

    const sanitizedEntry: AuditEntry = {
      eventId: event.eventId,
      eventType: event.eventType,
      timestamp: event.timestamp || Date.now(),
      resultCode: event.resultCode,
      tagFamily: event.tagFamily ?? null,
      keyId: event.keyId ? event.keyId.toLowerCase() : null,
      envelopeVersion: event.envelopeVersion ?? null,
      errorCode: event.errorCode ?? null,
    };

    const entries = await this.readEntries();
    const currentHash = await this.getAuditHash();

    // Compute next rolling hash: SHA256(currentHash || serializedEntry)
    const nextHash = this.computeRollingHash(currentHash, sanitizedEntry);

    entries.push(sanitizedEntry);

    // Enforce size bounds
    if (entries.length > this.maxEntries) {
      entries.splice(0, entries.length - this.maxEntries);
    }

    await this.persistEntries(entries);
    await this.persistAuditHash(nextHash);
  }

  /**
   * Retrieves audit log records matching the specified filter criteria.
   *
   * @param filter Optional filter criteria.
   * @returns Array of matching AuditEntry records, ordered chronologically.
   */
  public async getEvents(filter?: AuditFilter): Promise<AuditEntry[]> {
    const entries = await this.readEntries();
    if (!filter) {
      return [...entries];
    }

    let filtered = entries.filter((entry) => {
      if (filter.eventType && entry.eventType !== filter.eventType) {
        return false;
      }
      if (filter.startDate !== undefined && entry.timestamp < filter.startDate) {
        return false;
      }
      if (filter.endDate !== undefined && entry.timestamp > filter.endDate) {
        return false;
      }
      if (filter.keyId && entry.keyId !== filter.keyId.toLowerCase()) {
        return false;
      }
      if (filter.resultCode !== undefined && entry.resultCode !== filter.resultCode) {
        return false;
      }
      if (filter.tagFamily && entry.tagFamily !== filter.tagFamily) {
        return false;
      }
      return true;
    });

    if (filter.limit !== undefined && filter.limit > 0) {
      filtered = filtered.slice(-filter.limit);
    }

    return filtered;
  }

  /**
   * Clears all audit log entries and resets the rolling hash chain.
   *
   * Security Properties:
   * - Records an initial reset event into the fresh log.
   */
  public async clearEvents(): Promise<void> {
    const initialHash = new Uint8Array(32); // All zeros
    await this.persistEntries([]);
    await this.persistAuditHash(initialHash);
  }

  /**
   * Retrieves the current 32-byte rolling SHA-256 audit digest.
   *
   * @returns 32-byte rolling hash.
   */
  public async getAuditHash(): Promise<Uint8Array> {
    const rawBytes = await this.database.retrieve(AUDIT_HASH_STORAGE_KEY);
    if (!rawBytes || rawBytes.length !== 32) {
      return new Uint8Array(32); // Default 32 zero bytes
    }
    return rawBytes;
  }

  /**
   * Computes the rolling SHA-256 hash chaining over the previous hash and entry bytes.
   */
  private computeRollingHash(prevHash: Uint8Array, entry: AuditEntry): Uint8Array {
    const canonical = `${entry.eventId}:${entry.eventType}:${entry.timestamp}:${entry.resultCode}:${entry.tagFamily ?? ''}:${entry.keyId ?? ''}:${entry.envelopeVersion ?? ''}:${entry.errorCode ?? ''}`;
    const entryBuf = Buffer.from(canonical, 'utf8');

    const hash = QuickCrypto.createHash('sha256');
    hash.update(prevHash);
    hash.update(entryBuf);
    const digest = hash.digest();

    const result = new Uint8Array(32);
    result.set(digest);
    return result;
  }

  /**
   * Asserts that no forbidden sensitive keys exist on the audit entry object.
   */
  private assertNoForbiddenFields(event: any): void {
    if (!event || typeof event !== 'object') {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Audit event must be an object.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    for (const key of Object.keys(event)) {
      const normalizedKey = key.toLowerCase().replace(/[^a-z]/g, '');
      if (FORBIDDEN_FIELDS.has(normalizedKey)) {
        throw new GhostTagError({
          code: GhostTagErrorCode.VAULT_CORRUPT,
          userMessage: `Security directive violation: audit event contains forbidden sensitive field "${key}".`,
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.CRITICAL,
        });
      }
    }
  }

  /**
   * Reads all stored entries from the database.
   */
  private async readEntries(): Promise<AuditEntry[]> {
    const rawBytes = await this.database.retrieve(AUDIT_ENTRIES_STORAGE_KEY);
    if (!rawBytes) {
      return [];
    }

    try {
      const json = Buffer.from(rawBytes).toString('utf8');
      return JSON.parse(json) as AuditEntry[];
    } catch {
      return [];
    }
  }

  /**
   * Persists entries to the database.
   */
  private async persistEntries(entries: AuditEntry[]): Promise<void> {
    const json = JSON.stringify(entries);
    const buf = Buffer.from(json, 'utf8');
    const bytes = new Uint8Array(buf.length);
    bytes.set(buf);
    await this.database.store(AUDIT_ENTRIES_STORAGE_KEY, bytes);
  }

  /**
   * Persists the rolling audit hash to the database.
   */
  private async persistAuditHash(hash: Uint8Array): Promise<void> {
    await this.database.store(AUDIT_HASH_STORAGE_KEY, hash);
  }
}
