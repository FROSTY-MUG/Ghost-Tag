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
  /** Lazily built per-session membership sets for O(1) duplicate checks. */
  private readonly writeUidIndexes = new Map<string, Set<string>>();
  private readonly scanUidIndexes = new Map<string, Set<string>>();
  private readonly scanChunkIndexes = new Map<string, Set<number>>();

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

    // New session journal: drop any stale membership indexes for this session
    this.writeUidIndexes.delete(sessionId);
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

    // O(1) duplicate check via lazily built per-session index set
    let writtenSet = this.writeUidIndexes.get(sessionId);
    if (!writtenSet) {
      writtenSet = new Set(journal.writtenTagUids);
      this.writeUidIndexes.set(sessionId, writtenSet);
    }
    if (writtenSet.has(normUid)) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_ALREADY_WRITTEN,
        userMessage: `Tag ${normUid} has already received a chunk in this write session`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.WARNING,
      });
    }
    writtenSet.add(normUid);

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
    this.writeUidIndexes.set(sessionId, writtenSet);
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

    // New session journal: drop any stale membership indexes for this session
    this.scanUidIndexes.delete(sessionId);
    this.scanChunkIndexes.delete(sessionId);
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

    // O(1) membership checks via lazily built per-session index sets
    let chunkSet = this.scanChunkIndexes.get(sessionId);
    if (!chunkSet) {
      chunkSet = new Set(journal.collectedChunkIndices);
      this.scanChunkIndexes.set(sessionId, chunkSet);
    }
    let tagUidSet = this.scanUidIndexes.get(sessionId);
    if (!tagUidSet) {
      tagUidSet = new Set(journal.scannedTagUids);
      this.scanUidIndexes.set(sessionId, tagUidSet);
    }

    const alreadyCollected = chunkSet.has(globalChunkIndex);
    if (!alreadyCollected) {
      chunkSet.add(globalChunkIndex);
    }
    const collected = alreadyCollected
      ? journal.collectedChunkIndices
      : [...journal.collectedChunkIndices, globalChunkIndex].sort((a, b) => a - b);

    const alreadyScanned = tagUidSet.has(normUid);
    if (!alreadyScanned) {
      tagUidSet.add(normUid);
    }
    const scannedTagUids = alreadyScanned
      ? journal.scannedTagUids
      : [...journal.scannedTagUids, normUid];

    const updated: ScanJournal = {
      ...journal,
      collectedChunkIndices: collected,
      scannedTagUids: scannedTagUids,
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

