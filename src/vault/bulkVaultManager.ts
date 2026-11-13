/**
 * @file bulkVaultManager.ts
 * @summary Bulk Multi-File Vault Manager & Manifest Coordinator.
 *
 * Coordinates creation of bulk vaults, file encryption, chunk distribution,
 * erasure coding configuration, and private local tag-to-chunk mapping.
 */

import { generateSecureRandom } from '../crypto/random';
import { encryptFile, splitCiphertext } from '../crypto/fileEncryption';
import { encodeErasureChunks } from '../crypto/erasureCoding';
import { computeChunkHash } from '../crypto/bulkEnvelope';
import {
  BulkVaultManifest,
  BulkFileRecord,
  TagMappingRecord,
  ErasureCodingConfig,
} from '../contracts/bulkVault';
import { WrappedDEK } from '../contracts/keyHierarchy';
import { RecoveryEnvelope } from '../contracts/recovery';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

export interface PreparedChunk {
  readonly globalChunkIndex: number;
  readonly fileId: Uint8Array;
  readonly fileChunkIndex: number;
  readonly totalFileChunks: number;
  readonly totalVaultChunks: number;
  readonly chunkPayload: Uint8Array;
  readonly chunkHash: Uint8Array;
  readonly isRecovery: boolean;
}

export class BulkVaultManager {
  /**
   * Initializes a new Bulk Vault manifest.
   */
  public createBulkVault(
    vaultName: string,
    activeDekWrapped: WrappedDEK,
    kdfSalt: Uint8Array,
    recoveryEnvelope: RecoveryEnvelope
  ): BulkVaultManifest {
    const vaultId = generateSecureRandom(16);
    const now = Date.now();

    return {
      vaultId,
      formatVersion: 2,
      vaultName,
      activeDekWrapped,
      kdfSalt,
      recoveryEnvelope,
      files: [],
      totalVaultChunks: 0,
      tagMappings: [],
      createdAt: now,
      updatedAt: now,
    };
  }

  /**
   * Adds an opaque binary file to the bulk vault, encrypting it with DEK,
   * splitting it into chunks for physical tags, and applying optional erasure coding.
   *
   * @param manifest Existing bulk vault manifest.
   * @param dek Unwrapped 32-byte Data Encryption Key.
   * @param fileName Original filename.
   * @param mimeType File MIME type.
   * @param fileBytes Raw binary file data.
   * @param usableTagCapacity Max bytes per tag payload (usable memory - 134B fixed overhead).
   * @param recoveryChunksM Optional recovery chunks for erasure coding (M >= 0).
   */
  public prepareFileAddition(
    manifest: BulkVaultManifest,
    dek: Uint8Array,
    fileName: string,
    mimeType: string,
    fileBytes: Uint8Array,
    usableTagCapacity: number,
    recoveryChunksM: number = 0
  ): {
    updatedManifest: BulkVaultManifest;
    fileRecord: BulkFileRecord;
    preparedChunks: PreparedChunk[];
  } {
    if (usableTagCapacity <= 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.TAG_CAPACITY_INSUFFICIENT,
        userMessage: `Usable tag capacity must be positive, got ${usableTagCapacity}`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    const fileId = generateSecureRandom(16);

    // 1. Encrypt entire file with AES-256-GCM
    const encryptedPkg = encryptFile(dek, fileBytes, fileId);

    // 2. Split complete ciphertext into raw data chunks
    const dataChunks = splitCiphertext(encryptedPkg.fullEncryptedBytes, usableTagCapacity);
    const k = dataChunks.length;

    // 3. Apply Reed-Solomon erasure coding if redundancy requested
    const encoded = encodeErasureChunks(dataChunks, recoveryChunksM);
    const allFileChunks = encoded.chunks;
    const totalFileChunks = allFileChunks.length;

    // 4. Compute chunk hashes
    const chunkHashes: Uint8Array[] = allFileChunks.map((chunk) => computeChunkHash(chunk));

    const erasureConfig: ErasureCodingConfig | undefined =
      recoveryChunksM > 0
        ? {
            dataChunksK: k,
            recoveryChunksM,
            totalChunks: totalFileChunks,
          }
        : undefined;

    const fileRecord: BulkFileRecord = {
      fileId,
      fileName,
      mimeType,
      originalSizeBytes: fileBytes.length,
      ciphertextSizeBytes: encryptedPkg.encryptedSizeBytes,
      chunkCount: totalFileChunks,
      chunkHashes,
      ciphertextSha256: encryptedPkg.ciphertextSha256,
      erasureCoding: erasureConfig,
      addedAt: Date.now(),
    };

    const startGlobalIndex = manifest.totalVaultChunks;
    const newTotalVaultChunks = startGlobalIndex + totalFileChunks;

    const preparedChunks: PreparedChunk[] = allFileChunks.map((chunk, idx) => ({
      globalChunkIndex: startGlobalIndex + idx,
      fileId,
      fileChunkIndex: idx,
      totalFileChunks,
      totalVaultChunks: newTotalVaultChunks,
      chunkPayload: chunk,
      chunkHash: chunkHashes[idx],
      isRecovery: idx >= k,
    }));

    const updatedManifest: BulkVaultManifest = {
      ...manifest,
      files: [...manifest.files, fileRecord],
      totalVaultChunks: newTotalVaultChunks,
      updatedAt: Date.now(),
    };

    return {
      updatedManifest,
      fileRecord,
      preparedChunks,
    };
  }

  /**
   * Updates the private local mapping table when a physical tag has been written.
   * Stored ONLY in local vault database; never written to physical NFC tag.
   */
  public recordTagMapping(
    manifest: BulkVaultManifest,
    tagUidHex: string,
    globalChunkIndex: number,
    fileId: Uint8Array,
    fileChunkIndex: number
  ): BulkVaultManifest {
    const normUid = tagUidHex.toLowerCase();
    const existing = manifest.tagMappings.find((m) => m.tagUidHex === normUid);
    if (existing) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_ALREADY_WRITTEN,
        userMessage: `Physical tag ${normUid} is already registered in mapping for chunk #${existing.globalChunkIndex}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    const mappingRecord: TagMappingRecord = {
      tagUidHex: normUid,
      globalChunkIndex,
      fileId,
      fileChunkIndex,
      writtenAt: Date.now(),
    };

    return {
      ...manifest,
      tagMappings: [...manifest.tagMappings, mappingRecord],
      updatedAt: Date.now(),
    };
  }
}
