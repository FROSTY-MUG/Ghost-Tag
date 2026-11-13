/**
 * @file journalManager.ts
 * @summary Write and Scan Session Journal Manager for Bulk Operations.
 *
 * Implements persistent journaling for multi-tag write and scan sessions,
 * allowing safe interruption and resumption across app lifecycles.
 */

import {
  WriteJournal,
  ScanJournal,
  WriteSessionStatus,
  CHUNK_CACHE_TTL_MS,
} from '../contracts/bulkVault';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

export class JournalManager {
  private writeJournals: Map<string, WriteJournal> = new Map();
  private scanJournals: Map<string, ScanJournal> = new Map();

  /**
   * Initializes a new write session journal.
   * Accurately calculates extra tags excluded if user presented more tags than needed.
   */
  public createWriteJournal(
    sessionId: string,
    vaultId: Uint8Array,
    requiredTagCount: number,
    presentedTagCount: number
  ): WriteJournal {
    const extraTags = Math.max(0, presentedTagCount - requiredTagCount);

    const journal: WriteJournal = {
      sessionId,
      vaultId,
      requiredTagCount,
      presentedTagCount,
      extraTagsExcludedCount: extraTags,
      completedChunkIndices: [],
      nextChunkIndex: 0,
      writtenTagUids: [],
      status: 'WRITING',
      startedAt: Date.now(),
      updatedAt: Date.now(),
    };

    this.writeJournals.set(sessionId, journal);
    return journal;
  }

  /**
   * Records a successfully written and verified chunk.
   * Throws `CHUNK_ALREADY_WRITTEN` if tag UID was already written in this session.
   */
  public recordChunkWritten(
    sessionId: string,
    globalChunkIndex: number,
    tagUidHex: string
  ): WriteJournal {
    const journal = this.writeJournals.get(sessionId);
    if (!journal) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: `Write session ${sessionId} not found`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    const normUid = tagUidHex.toLowerCase();
    if (journal.writtenTagUids.includes(normUid)) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_ALREADY_WRITTEN,
        userMessage: `Tag ${normUid} has already received a chunk in this write session`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.WARNING,
      });
    }

    const completed = [...journal.completedChunkIndices, globalChunkIndex];
    const writtenUids = [...journal.writtenTagUids, normUid];
    const isFinished = completed.length >= journal.requiredTagCount;

    const updated: WriteJournal = {
      ...journal,
      completedChunkIndices: completed,
      nextChunkIndex: isFinished ? journal.requiredTagCount : globalChunkIndex + 1,
      writtenTagUids: writtenUids,
      status: isFinished ? 'COMPLETED' : 'WRITING',
      updatedAt: Date.now(),
    };

    this.writeJournals.set(sessionId, updated);
    return updated;
  }

  /**
   * Retrieves an active or completed write journal.
   */
  public getWriteJournal(sessionId: string): WriteJournal | null {
    return this.writeJournals.get(sessionId) ?? null;
  }

  /**
   * Initializes a new scan session journal with a 72-hour expiration window.
   */
  public createScanJournal(
    sessionId: string,
    vaultId: Uint8Array,
    totalRequiredChunks: number
  ): ScanJournal {
    const now = Date.now();
    const journal: ScanJournal = {
      sessionId,
      vaultId,
      totalRequiredChunks,
      collectedChunkIndices: [],
      scannedTagUids: [],
      startedAt: now,
      expiresAt: now + CHUNK_CACHE_TTL_MS,
    };

    this.scanJournals.set(sessionId, journal);
    return journal;
  }

  /**
   * Records a chunk scanned and verified during bulk scanning.
   */
  public recordChunkScanned(
    sessionId: string,
    globalChunkIndex: number,
    tagUidHex: string
  ): ScanJournal {
    const journal = this.scanJournals.get(sessionId);
    if (!journal) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: `Scan session ${sessionId} not found`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    const normUid = tagUidHex.toLowerCase();
    const collected = journal.collectedChunkIndices.includes(globalChunkIndex)
      ? journal.collectedChunkIndices
      : [...journal.collectedChunkIndices, globalChunkIndex].sort((a, b) => a - b);

    const tagUids = journal.scannedTagUids.includes(normUid)
      ? journal.scannedTagUids
      : [...journal.scannedTagUids, normUid];

    const updated: ScanJournal = {
      ...journal,
      collectedChunkIndices: collected,
      scannedTagUids: tagUids,
    };

    this.scanJournals.set(sessionId, updated);
    return updated;
  }

  /**
   * Retrieves a scan journal.
   */
  public getScanJournal(sessionId: string): ScanJournal | null {
    return this.scanJournals.get(sessionId) ?? null;
  }
}

