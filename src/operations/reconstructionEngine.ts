/**
 * @file reconstructionEngine.ts
 * @summary File Reassembly and Decryption Pipeline for Bulk Vaults.
 *
 * Implements chunk reassembly, erasure decoding (Reed-Solomon / Cauchy-Vandermonde over GF(2^8)),
 * full-file SHA-256 ciphertext hash verification, and AES-256-GCM decryption.
 */

import { BulkFileRecord, BulkVaultManifest, CachedChunk } from '../contracts/bulkVault';
import { ChunkCacheManager } from '../vault/chunkCache';
import { decodeErasureChunks, AvailableChunk } from '../crypto/erasureCoding';
import { joinChunks, decryptFile } from '../crypto/fileEncryption';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

export interface ReconstructedFile {
  readonly fileId: Uint8Array;
  readonly fileName: string;
  readonly mimeType: string;
  readonly originalSizeBytes: number;
  readonly plaintext: Uint8Array;
  readonly verified: boolean;
}

export interface FileReconstructionStatus {
  readonly fileId: Uint8Array;
  readonly fileName: string;
  readonly totalChunks: number;
  readonly requiredChunks: number;
  readonly availableChunks: number;
  readonly canReconstruct: boolean;
}

export class ReconstructionEngine {
  private readonly chunkCache: ChunkCacheManager;

  constructor(chunkCache: ChunkCacheManager) {
    this.chunkCache = chunkCache;
  }

  /**
   * Assesses reconstruction readiness for all files in the bulk vault.
   */
  public getReconstructionStatus(manifest: BulkVaultManifest): FileReconstructionStatus[] {
    const cachedChunks = this.chunkCache.getCachedChunks(manifest.vaultId);

    return manifest.files.map((file) => {
      const fileCached = cachedChunks.filter((c) => this.matchesFileId(c.fileId, file.fileId));
      const required = file.erasureCoding ? file.erasureCoding.dataChunksK : file.chunkCount;
      const available = fileCached.length;

      return {
        fileId: file.fileId,
        fileName: file.fileName,
        totalChunks: file.chunkCount,
        requiredChunks: required,
        availableChunks: available,
        canReconstruct: available >= required,
      };
    });
  }

  /**
   * Reassembles and decrypts a specific file from cached chunks.
   *
   * @param manifest Bulk vault manifest.
   * @param fileRecord Target file record to reconstruct.
   * @param dek Unwrapped 32-byte Data Encryption Key.
   * @returns Decrypted file payload and metadata.
   */
  public reconstructFile(
    manifest: BulkVaultManifest,
    fileRecord: BulkFileRecord,
    dek: Uint8Array
  ): ReconstructedFile {
    const cachedChunks = this.chunkCache
      .getCachedChunks(manifest.vaultId)
      .filter((c) => this.matchesFileId(c.fileId, fileRecord.fileId));

    const k = fileRecord.erasureCoding ? fileRecord.erasureCoding.dataChunksK : fileRecord.chunkCount;
    const m = fileRecord.erasureCoding ? fileRecord.erasureCoding.recoveryChunksM : 0;

    if (cachedChunks.length < k) {
      throw new GhostTagError({
        code: GhostTagErrorCode.INSUFFICIENT_CHUNKS,
        userMessage: `Cannot reconstruct "${fileRecord.fileName}": have ${cachedChunks.length} chunks, need ${k}`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    let dataChunks: Uint8Array[];

    if (fileRecord.erasureCoding && m > 0) {
      // Format available chunks for erasure decoder
      const available: AvailableChunk[] = cachedChunks.map((c) => ({
        chunkIndex: c.fileChunkIndex,
        data: c.ciphertext,
      }));

      dataChunks = decodeErasureChunks(available, k, m);
    } else {
      // Systematic sorting
      const sorted = [...cachedChunks].sort((a, b) => a.fileChunkIndex - b.fileChunkIndex);
      dataChunks = sorted.map((c) => c.ciphertext);
    }

    // Join data chunks into full ciphertext package
    const fullCiphertextPackage = joinChunks(dataChunks);

    // Verify full ciphertext hash & decrypt
    const plaintext = decryptFile(
      dek,
      fullCiphertextPackage,
      fileRecord.fileId,
      fileRecord.ciphertextSha256
    );

    return {
      fileId: fileRecord.fileId,
      fileName: fileRecord.fileName,
      mimeType: fileRecord.mimeType,
      originalSizeBytes: plaintext.length,
      plaintext,
      verified: true,
    };
  }

  private matchesFileId(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}

