/**
 * @file bulkScanOperation.ts
 * @summary Ghost-Tag Random-Order Bulk Tag Scanning & Verification Engine.
 *
 * Implements non-sequential tag discovery, cryptographic envelope verification,
 * duplicate scan suppression, and temporary encrypted caching (72-hour TTL).
 *
 * Features:
 * - Order Independence: Scans tags in any random physical order.
 * - Anti-Tamper: Verifies 74-byte AAD binding and AES-256-GCM authentication tag.
 * - Cross-Vault Rejection: Rejects tags from mismatched vaults with `CHUNK_WRONG_VAULT`.
 * - Duplicate Rejection: Rejects already-scanned tags with `CHUNK_ALREADY_CACHED`.
 * - 72-Hour Cache: Persists chunks in encrypted cache with TTL countdown.
 */

import { TagReader } from '../nfc/tagReader';
import { extractBulkGhostTagPayload } from '../nfc/bulkNdefBuilder';
import {
  parseBulkEnvelope,
  constructBulkAAD,
  computeChunkHash,
} from '../crypto/bulkEnvelope';
import { decrypt } from '../crypto/aesGcm';
import { BulkVaultManifest } from '../contracts/bulkVault';
import { ChunkCacheManager } from '../vault/chunkCache';
import { JournalManager } from '../vault/journalManager';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

export interface ScanChunkResult {
  readonly globalChunkIndex: number;
  readonly fileId: Uint8Array;
  readonly fileChunkIndex: number;
  readonly totalFileChunks: number;
  readonly totalVaultChunks: number;
  readonly collectedCount: number;
  readonly remainingCount: number;
  readonly isVaultComplete: boolean;
  readonly expiresAt: number;
  readonly logMessage: string;
}

export class BulkScanOperation {
  private readonly tagReader: TagReader;
  private readonly chunkCache: ChunkCacheManager;
  private readonly journalManager: JournalManager;

  constructor(
    chunkCache: ChunkCacheManager,
    journalManager: JournalManager,
    tagReader = new TagReader()
  ) {
    this.chunkCache = chunkCache;
    this.journalManager = journalManager;
    this.tagReader = tagReader;
  }

  /**
   * Initializes or resumes a bulk scanning session.
   */
  public startScanSession(sessionId: string, manifest: BulkVaultManifest) {
    let journal = this.journalManager.getScanJournal(sessionId);
    if (!journal) {
      journal = this.journalManager.createScanJournal(
        sessionId,
        manifest.vaultId,
        manifest.totalVaultChunks
      );
    }
    return journal;
  }

  /**
   * Scans a single physical NFC tag presented by the user, verifies it cryptographically,
   * and caches the decrypted chunk payload.
   *
   * @param sessionId Active scan session identifier.
   * @param manifest Active bulk vault manifest.
   * @param dek Unwrapped 32-byte Data Encryption Key.
   * @returns Detailed ScanChunkResult with progress indicators.
   */
  public async scanTag(
    sessionId: string,
    manifest: BulkVaultManifest,
    dek: Uint8Array,
    tag?: import('../nfc/tagInfo').NfcTag
  ): Promise<ScanChunkResult> {
    const journal = this.journalManager.getScanJournal(sessionId);
    if (!journal) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: `Scan session ${sessionId} not found`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    // 1. Read NDEF message from NFC hardware
    const message = await this.tagReader.readNdefMessage(tag as import('../nfc/tagInfo').NfcTag);
    if (!message || message.length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.TAG_NOT_NDEF,
        userMessage: 'Tag does not contain an NDEF message',
        category: ErrorCategory.NFC,
        severity: ErrorSeverity.ERROR,
      });
    }
    const payload = extractBulkGhostTagPayload(message[0]);

    // 2. Parse bulk binary envelope
    const parsed = parseBulkEnvelope(payload);
    const header = parsed.header;

    // 3. Vault ID verification
    if (header.vaultId.length !== manifest.vaultId.length) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_WRONG_VAULT,
        userMessage: 'Scanned tag belongs to a different vault',
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }
    for (let i = 0; i < header.vaultId.length; i++) {
      if (header.vaultId[i] !== manifest.vaultId[i]) {
        throw new GhostTagError({
          code: GhostTagErrorCode.CHUNK_WRONG_VAULT,
          userMessage: 'Scanned tag belongs to a different vault',
          category: ErrorCategory.OPERATION,
          severity: ErrorSeverity.ERROR,
        });
      }
    }

    // 4. Duplicate scan check (cached check)
    if (this.chunkCache.getChunk(manifest.vaultId, header.globalChunkIndex) !== null) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_ALREADY_CACHED,
        userMessage: `Chunk #${header.globalChunkIndex} has already been scanned and verified.`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.WARNING,
      });
    }

    // 5. Verify chunk hash
    const computedHash = computeChunkHash(parsed.ciphertext);
    for (let i = 0; i < computedHash.length; i++) {
      if (computedHash[i] !== header.chunkHash[i]) {
        throw new GhostTagError({
          code: GhostTagErrorCode.CHUNK_HASH_MISMATCH,
          userMessage: `Chunk #${header.globalChunkIndex} failed SHA-256 verification`,
          category: ErrorCategory.CRYPTO,
          severity: ErrorSeverity.ERROR,
        });
      }
    }

    // 6. Decrypt chunk payload using AES-256-GCM and reconstructed 74-byte AAD
    const aad = constructBulkAAD(header);
    let chunkPayload: Uint8Array;
    try {
      chunkPayload = decrypt(dek, parsed.ciphertext, header.nonce, parsed.gcmTag, aad);
    } catch (err) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_CORRUPT,
        userMessage: `Chunk #${header.globalChunkIndex} failed AES-256-GCM authentication`,
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.CRITICAL,
        cause: err,
      });
    }

    // 7. Store in temporary encrypted cache with 72-hour TTL
    const tagUid = `tag-${header.globalChunkIndex}`; // Hardware UID abstraction
    const cachedRecord = this.chunkCache.cacheChunk(manifest.vaultId, {
      globalChunkIndex: header.globalChunkIndex,
      fileId: header.fileId,
      fileChunkIndex: header.fileChunkIndex,
      totalFileChunks: header.totalFileChunks,
      ciphertext: chunkPayload,
      chunkHash: header.chunkHash,
      tagUidHex: tagUid,
    });

    // 8. Update scan journal
    const updatedJournal = this.journalManager.recordChunkScanned(
      sessionId,
      header.globalChunkIndex,
      tagUid
    );

    const collectedCount = updatedJournal.collectedChunkIndices.length;
    const remainingCount = Math.max(0, header.totalVaultChunks - collectedCount);
    const isVaultComplete = collectedCount >= header.totalVaultChunks;

    return {
      globalChunkIndex: header.globalChunkIndex,
      fileId: header.fileId,
      fileChunkIndex: header.fileChunkIndex,
      totalFileChunks: header.totalFileChunks,
      totalVaultChunks: header.totalVaultChunks,
      collectedCount,
      remainingCount,
      isVaultComplete,
      expiresAt: cachedRecord.expiresAt,
      logMessage: `[READ] Chunk ${header.globalChunkIndex + 1}/${header.totalVaultChunks} verified. [CACHE] Cached with 72h TTL. (${remainingCount} remaining)`,
    };
  }
}
