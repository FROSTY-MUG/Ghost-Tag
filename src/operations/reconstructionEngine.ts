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
import { computeFileCiphertextHash } from '../crypto/bulkEnvelope';
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

/** Per-file bulk vault integrity verification result. */
export interface BulkVaultFileVerification {
  /** 16-byte binary UUID of the file. */
  readonly fileId: Uint8Array;
  /** Human-readable filename (local manifest only). */
  readonly fileName: string;
  /** Total chunks for the file (data + recovery). */
  readonly chunkCount: number;
  /** Required chunks for reconstruction (K for erasure files, chunkCount otherwise). */
  readonly requiredChunks: number;
  /** Number of cached chunks found for this file. */
  readonly availableChunks: number;
  /** Indices of cached chunks with no matching data chunk. */
  readonly missingChunkIndices: number[];
  /** Indices of chunks whose cached hash differs from the manifest hash. */
  readonly chunkHashMismatches: number[];
  /** True when every chunk index 0..chunkCount-1 has a cached chunk. */
  readonly allChunksPresent: boolean;
  /** True when every cached chunk hash matches the manifest chunkHashes. */
  readonly allChunkHashesMatch: boolean;
  /** True when the full ciphertext hash can be recomputed (availableChunks >= requiredChunks). */
  readonly canVerifyCiphertextHash: boolean;
  /** Recomputed full-file ciphertext SHA-256 result (undefined when it could not be verified). */
  readonly ciphertextHashValid?: boolean;
  /**
   * True when the file is fully verified: all chunks present, all hashes match,
   * and the full ciphertext hash validates.
   */
  readonly isVerified: boolean;
}

/** Aggregate integrity verification report for a bulk vault. */
export interface BulkVaultVerificationReport {
  /** 16-byte binary UUID of the bulk vault. */
  readonly vaultId: Uint8Array;
  /** Per-file verification results, in manifest order. */
  readonly files: readonly BulkVaultFileVerification[];
  /** True when every file in the vault reports isVerified. */
  readonly isVaultVerified: boolean;
}

/**
 * Constant-time byte array equality (no early exit on length mismatch).
 */
function byteArraysEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
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
   * Security Properties:
   * - For erasure-coded files, passes the manifest's original (unpadded) data chunk
   *   lengths to the decoder so reconstruction reproduces the exact ciphertext bytes
   *   that were hashed at write time (verifying against ciphertextSha256).
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

    const chunkByIndex = this.indexChunksByFileChunkIndex(cachedChunks);
    const k = fileRecord.erasureCoding ? fileRecord.erasureCoding.dataChunksK : fileRecord.chunkCount;

    if (cachedChunks.length < k) {
      throw new GhostTagError({
        code: GhostTagErrorCode.INSUFFICIENT_CHUNKS,
        userMessage: `Cannot reconstruct "${fileRecord.fileName}": have ${cachedChunks.length} chunks, need ${k}`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.ERROR,
      });
    }

    const dataChunks = this.decodeDataChunks(fileRecord, chunkByIndex);

    // Join data chunks into full ciphertext package
    const fullCiphertextPackage = this.trimToCiphertextSize(fileRecord, joinChunks(dataChunks));

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

  /**
   * Verifies the integrity of a bulk vault against its cached chunks — without
   * requiring the vault DEK. For every file it checks:
   *
   * 1. That every chunk index in [0, chunkCount) has a cached chunk.
   * 2. That each cached chunk's SHA-256 hash matches the manifest's chunkHashes entry.
   * 3. When at least `requiredChunks` are available, reassembles the data chunks
   *    (erasure-decoded when the file is coded) and recomputes the full file
   *    ciphertext SHA-256 against the manifest's ciphertextSha256.
   *
   * @param manifest Bulk vault manifest.
   * @returns BulkVaultVerificationReport describing per-file and overall status.
   */
  public verifyBulkVault(manifest: BulkVaultManifest): BulkVaultVerificationReport {
    const cachedChunks = this.chunkCache.getCachedChunks(manifest.vaultId);
    const files: BulkVaultFileVerification[] = [];

    for (const file of manifest.files) {
      const fileChunks = cachedChunks.filter((c) => this.matchesFileId(c.fileId, file.fileId));
      const chunkByIndex = this.indexChunksByFileChunkIndex(fileChunks);

      const availableChunks = chunkByIndex.size;
      const requiredChunks = file.erasureCoding ? file.erasureCoding.dataChunksK : file.chunkCount;

      const missingChunkIndices: number[] = [];
      const chunkHashMismatches: number[] = [];
      for (let i = 0; i < file.chunkCount; i++) {
        const cached = chunkByIndex.get(i);
        if (!cached) {
          missingChunkIndices.push(i);
          continue;
        }
        const expectedHash = file.chunkHashes[i];
        if (expectedHash && !byteArraysEqual(cached.chunkHash, expectedHash)) {
          chunkHashMismatches.push(i);
        }
      }

      const allChunksPresent = missingChunkIndices.length === 0;
      const allChunkHashesMatch = chunkHashMismatches.length === 0;
      const canVerifyCiphertextHash = availableChunks >= requiredChunks;

      let ciphertextHashValid: boolean | undefined;
      if (canVerifyCiphertextHash) {
        try {
          const dataChunks = this.decodeDataChunks(file, chunkByIndex);
          const fullBytes = this.trimToCiphertextSize(file, joinChunks(dataChunks));
          ciphertextHashValid = byteArraysEqual(
            computeFileCiphertextHash(fullBytes),
            file.ciphertextSha256
          );
        } catch {
          ciphertextHashValid = false;
        }
      }

      files.push({
        fileId: file.fileId,
        fileName: file.fileName,
        chunkCount: file.chunkCount,
        requiredChunks,
        availableChunks,
        missingChunkIndices,
        chunkHashMismatches,
        allChunksPresent,
        allChunkHashesMatch,
        canVerifyCiphertextHash,
        ciphertextHashValid,
        isVerified:
          allChunksPresent && allChunkHashesMatch && ciphertextHashValid === true,
      });
    }

    return {
      vaultId: manifest.vaultId,
      files,
      isVaultVerified: files.every((f) => f.isVerified),
    };
  }

  /**
   * Indexes cached chunks by their file-chunk index, keeping the first record
   * when duplicates exist.
   */
  private indexChunksByFileChunkIndex(
    cachedChunks: readonly CachedChunk[]
  ): Map<number, CachedChunk> {
    const chunkByIndex = new Map<number, CachedChunk>();
    for (const c of cachedChunks) {
      if (!chunkByIndex.has(c.fileChunkIndex)) {
        chunkByIndex.set(c.fileChunkIndex, c);
      }
    }
    return chunkByIndex;
  }

  /**
   * Decodes the ordered data chunks for a file from the cached chunks.
   *
   * - Erasure-coded files: recovers the K systematic data chunks via
   *   `decodeErasureChunks`, passing the manifest's original (unpadded) chunk
   *   lengths so reconstruction is byte-exact with the original ciphertext.
   * - Systematic files: sorts cached chunks by file-chunk index and trims any
   *   stale padding against the manifest's original lengths.
   */
  private decodeDataChunks(
    fileRecord: BulkFileRecord,
    chunkByIndex: Map<number, CachedChunk>
  ): Uint8Array[] {
    const m = fileRecord.erasureCoding ? fileRecord.erasureCoding.recoveryChunksM : 0;

    if (m > 0) {
      const available: AvailableChunk[] = [];
      for (const c of chunkByIndex.values()) {
        available.push({ chunkIndex: c.fileChunkIndex, data: c.ciphertext });
      }
      return decodeErasureChunks(
        available,
        fileRecord.erasureCoding!.dataChunksK,
        m,
        fileRecord.chunkOriginalLengths
      );
    }

    // Systematic path: order cached chunks by file chunk index
    const sorted = Array.from(chunkByIndex.values()).sort(
      (a, b) => a.fileChunkIndex - b.fileChunkIndex
    );
    return sorted.map((c) =>
      this.trimToOriginalLength(c, fileRecord.chunkOriginalLengths?.[c.fileChunkIndex])
    );
  }

  /**
   * Trims a reconstructed buffer to the authoritative full-ciphertext size from
   * the file record when it exceeds it (no-op when the size matches).
   */
  private trimToCiphertextSize(
    fileRecord: BulkFileRecord,
    bytes: Uint8Array
  ): Uint8Array {
    const expectedLength = fileRecord.ciphertextSizeBytes || 0;
    return expectedLength > 0 && bytes.length > expectedLength
      ? bytes.subarray(0, expectedLength)
      : bytes;
  }

  /**
   * Trims a cached chunk to its original (unpadded) length when a length is known.
   */
  private trimToOriginalLength(
    chunk: CachedChunk,
    originalLength?: number
  ): Uint8Array {
    if (originalLength !== undefined && originalLength < chunk.ciphertext.length) {
      return chunk.ciphertext.subarray(0, originalLength);
    }
    return chunk.ciphertext;
  }

  private matchesFileId(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}
