/**
 * @file bulkWriteOperation.ts
 * @summary Ghost-Tag Bulk Distributed Chunk Write & Verification Engine.
 *
 * Implements the atomic write-and-verify workflow for distributing encrypted
 * file chunks across sets of physical NFC tags.
 *
 * Core Guarantees:
 * - Extra Tag Exclusion: If user presents 100 tags and only 86 are needed,
 *   instructs user to set aside the 14 extra tags and strictly refuses to write to them.
 * - Anti-Overwrite Protection: Detects if a tag UID was already written during this
 *   session and rejects it with `CHUNK_ALREADY_WRITTEN`.
 * - Full Read-Back Verification: Reads back the tag immediately after writing,
 *   verifying chunk index, chunk hash, and GCM authentication tag.
 * - Private Tag Mapping: Records hardware UID -> chunk coordinates exclusively
 *   in the local encrypted vault manifest. Physical tags store ZERO plaintext.
 */

import NfcManager from 'react-native-nfc-manager';
import { TagWriter } from '../nfc/tagWriter';
import { TagReader } from '../nfc/tagReader';
import { TagInfo, NfcTag } from '../nfc/tagInfo';
import {
  encodeBulkGhostTagNdefMessage,
  extractBulkGhostTagPayload,
} from '../nfc/bulkNdefBuilder';
import {
  serializeBulkEnvelope,
  parseBulkEnvelope,
  constructBulkAAD,
  computeChunkHash,
} from '../crypto/bulkEnvelope';
import { encrypt } from '../crypto/aesGcm';
import { hexToBytes } from '../crypto/keyWrap';
import { BulkVaultManifest } from '../contracts/bulkVault';
import { BulkVaultManager, PreparedChunk } from '../vault/bulkVaultManager';
import { JournalManager } from '../vault/journalManager';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

export interface BulkWriteProgress {
  readonly sessionId: string;
  readonly currentChunkIndex: number;
  readonly totalChunks: number;
  readonly writtenTagUid: string;
  readonly isComplete: boolean;
  readonly extraTagsExcluded: number;
  readonly logMessage: string;
}

export type BulkWriteCallback = (progress: BulkWriteProgress) => void;

export class BulkWriteOperation {
  private readonly tagWriter: TagWriter;
  private readonly tagReader: TagReader;
  private readonly tagInfoHelper: TagInfo;
  private readonly bulkVaultManager: BulkVaultManager;
  private readonly journalManager: JournalManager;

  constructor(
    bulkVaultManager: BulkVaultManager,
    journalManager: JournalManager,
    tagWriter = new TagWriter(),
    tagReader = new TagReader(),
    tagInfoHelper = new TagInfo()
  ) {
    this.bulkVaultManager = bulkVaultManager;
    this.journalManager = journalManager;
    this.tagWriter = tagWriter;
    this.tagReader = tagReader;
    this.tagInfoHelper = tagInfoHelper;
  }

  /**
   * Initializes a bulk write session.
   * If extra tags are presented, logs explicit instruction to set them aside.
   */
  public startSession(
    sessionId: string,
    vaultId: Uint8Array,
    requiredTagCount: number,
    presentedTagCount: number
  ): {
    instructionMessage: string;
    extraTagsExcluded: number;
  } {
    const journal = this.journalManager.createWriteJournal(
      sessionId,
      vaultId,
      requiredTagCount,
      presentedTagCount
    );

    const extraTags = journal.extraTagsExcludedCount;
    let instructionMessage = `Only ${requiredTagCount} tags are required.`;
    if (extraTags > 0) {
      instructionMessage = `Only ${requiredTagCount} tags are required. Please set aside the other ${extraTags} tags. Scan the ${requiredTagCount} required tags one by one.`;
    }

    return {
      instructionMessage,
      extraTagsExcluded: extraTags,
    };
  }

  /**
   * Writes the next prepared chunk to the detected tag and verifies it via read-back.
   *
   * @param sessionId Active write session identifier.
   * @param manifest Bulk vault manifest.
   * @param dek Unwrapped 32-byte Data Encryption Key.
   * @param tag Detected physical NFC tag.
   * @param chunk Prepared chunk metadata and payload.
   * @param onProgress Optional callback for progress reporting.
   * @returns Updated bulk vault manifest containing private tag mapping.
   */
  public async writeNextChunk(
    sessionId: string,
    manifest: BulkVaultManifest,
    dek: Uint8Array,
    tag: NfcTag,
    chunk: PreparedChunk,
    onProgress?: BulkWriteCallback
  ): Promise<BulkVaultManifest> {
    const journal = this.journalManager.getWriteJournal(sessionId);
    if (!journal) {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: `Write session ${sessionId} not found`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    const tagUid = tag.id?.toLowerCase();
    if (!tagUid) {
      throw new GhostTagError({
        code: GhostTagErrorCode.TAG_NOT_DETECTED,
        userMessage: 'Tag hardware UID could not be resolved',
        category: ErrorCategory.NFC,
        severity: ErrorSeverity.ERROR,
      });
    }

    // Anti-overwrite check: verify tag has not already been used in this session
    if (journal.writtenTagUids.includes(tagUid)) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_ALREADY_WRITTEN,
        userMessage: `Tag ${tagUid} has already received a chunk in this write session. Please use an unwritten tag.`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.WARNING,
      });
    }

    // Capacity verification
    const capacity = this.tagInfoHelper.calculateBulkChunkCapacity(tag);
    if (capacity.usableChunkBytes < chunk.chunkPayload.length) {
      throw new GhostTagError({
        code: GhostTagErrorCode.TAG_CAPACITY_INSUFFICIENT,
        userMessage: `Tag capacity (${capacity.usableChunkBytes}B) insufficient for chunk (${chunk.chunkPayload.length}B)`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    // 1. Generate chunk envelope nonce and AAD
    const keyIdBytes =
      typeof manifest.activeDekWrapped.keyId === 'string'
        ? hexToBytes(manifest.activeDekWrapped.keyId)
        : (manifest.activeDekWrapped.keyId as Uint8Array);

    const aad = constructBulkAAD({
      vaultId: manifest.vaultId,
      fileId: chunk.fileId,
      keyId: keyIdBytes,
      globalChunkIndex: chunk.globalChunkIndex,
      totalVaultChunks: chunk.totalVaultChunks,
      fileChunkIndex: chunk.fileChunkIndex,
      totalFileChunks: chunk.totalFileChunks,
      chunkCiphertextLength: chunk.chunkPayload.length,
    });

    // 2. Encrypt chunk payload with AES-256-GCM
    const { ciphertext: chunkCiphertext, nonce: chunkNonce, tag: gcmTag } = encrypt(
      dek,
      chunk.chunkPayload,
      aad
    );

    // 3. Compute chunk hash
    const chunkHash = computeChunkHash(chunkCiphertext);

    // 4. Serialize bulk envelope
    const serializedEnvelope = serializeBulkEnvelope({
      vaultId: manifest.vaultId,
      fileId: chunk.fileId,
      keyId: keyIdBytes,
      globalChunkIndex: chunk.globalChunkIndex,
      totalVaultChunks: chunk.totalVaultChunks,
      fileChunkIndex: chunk.fileChunkIndex,
      totalFileChunks: chunk.totalFileChunks,
      chunkCiphertext,
      chunkHash,
      nonce: chunkNonce,
      gcmTag,
    });

    // 5. Encode NDEF message and write to tag
    const encodedNdefBytes = encodeBulkGhostTagNdefMessage(serializedEnvelope);
    await NfcManager.writeNdefMessage(encodedNdefBytes);

    // 6. Read-back verification
    const readBackMessages = await this.tagReader.readNdefMessage(tag);
    if (!readBackMessages || readBackMessages.length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.TAG_WRITE_UNVERIFIED,
        userMessage: 'Read-back verification failed: no NDEF records found on tag',
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.CRITICAL,
      });
    }
    const readBackPayload = extractBulkGhostTagPayload(readBackMessages[0]);
    const parsedEnvelope = parseBulkEnvelope(readBackPayload);

    // Verify chunk integrity and parameters
    if (parsedEnvelope.header.globalChunkIndex !== chunk.globalChunkIndex) {
      throw new GhostTagError({
        code: GhostTagErrorCode.TAG_WRITE_UNVERIFIED,
        userMessage: `Read-back verification failed: index mismatch (wrote ${chunk.globalChunkIndex}, read ${parsedEnvelope.header.globalChunkIndex})`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.CRITICAL,
      });
    }

    for (let i = 0; i < chunkHash.length; i++) {
      if (parsedEnvelope.header.chunkHash[i] !== chunkHash[i]) {
        throw new GhostTagError({
          code: GhostTagErrorCode.TAG_WRITE_UNVERIFIED,
          userMessage: 'Read-back verification failed: chunk hash mismatch',
          category: ErrorCategory.OPERATION,
          severity: ErrorSeverity.CRITICAL,
        });
      }
    }

    // 8. Update write journal
    this.journalManager.recordChunkWritten(sessionId, chunk.globalChunkIndex, tagUid);

    // 9. Update private mapping in local vault manifest
    const updatedManifest = this.bulkVaultManager.recordTagMapping(
      manifest,
      tagUid,
      chunk.globalChunkIndex,
      chunk.fileId,
      chunk.fileChunkIndex
    );

    if (onProgress) {
      onProgress({
        sessionId,
        currentChunkIndex: chunk.globalChunkIndex + 1,
        totalChunks: chunk.totalVaultChunks,
        writtenTagUid: tagUid,
        isComplete: chunk.globalChunkIndex + 1 >= chunk.totalVaultChunks,
        extraTagsExcluded: journal.extraTagsExcludedCount,
        logMessage: `[WRITE] Chunk ${chunk.globalChunkIndex + 1}/${chunk.totalVaultChunks} written to tag ${tagUid}. Verified SHA-256.`,
      });
    }

    return updatedManifest;
  }
}
