/**
 * @file chunkCache.ts
 * @summary Temporary Encrypted Chunk Cache with 72-Hour TTL.
 *
 * Implements persistent caching of scanned NFC chunks to enable asynchronous,
 * multi-session tag scanning. Chunks are cached locally and automatically
 * expired after 72 hours.
 *
 * Security & Reliability:
 * - Duplicate Detection: Rejects duplicate scans of already-cached chunks with
 *   `CHUNK_ALREADY_CACHED`.
 * - Automatic Expiration: Purges cached chunks strictly after 72 hours (259,200,000 ms).
 * - Integrity Validation: Verifies chunk hash before caching.
 */

import { CachedChunk, CHUNK_CACHE_TTL_MS } from '../contracts/bulkVault';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { computeChunkHash } from '../crypto/bulkEnvelope';

export class ChunkCacheManager {
  private cache: Map<string, CachedChunk> = new Map();

  /**
   * Generates a unique cache key for a chunk: vaultIdHex:globalChunkIndex.
   */
  private makeKey(vaultId: Uint8Array, globalChunkIndex: number): string {
    const vaultHex = Array.from(vaultId)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return `${vaultHex}:${globalChunkIndex}`;
  }

  /**
   * Stores a scanned chunk in the cache with a 72-hour expiration timer.
   * Throws `CHUNK_ALREADY_CACHED` if this chunk index is already cached.
   * Throws `CHUNK_HASH_MISMATCH` if chunk hash does not match chunk ciphertext.
   */
  public cacheChunk(
    vaultId: Uint8Array,
    chunk: Omit<CachedChunk, 'scannedAt' | 'expiresAt'>
  ): CachedChunk {
    this.purgeExpiredChunks();

    // Verify chunk hash integrity
    const computedHash = computeChunkHash(chunk.ciphertext);
    if (computedHash.length !== chunk.chunkHash.length) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_HASH_MISMATCH,
        userMessage: 'Scanned chunk hash length mismatch',
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }
    for (let i = 0; i < computedHash.length; i++) {
      if (computedHash[i] !== chunk.chunkHash[i]) {
        throw new GhostTagError({
          code: GhostTagErrorCode.CHUNK_HASH_MISMATCH,
          userMessage: `Scanned chunk ${chunk.globalChunkIndex} failed SHA-256 hash verification`,
          category: ErrorCategory.CRYPTO,
          severity: ErrorSeverity.ERROR,
        });
      }
    }

    const key = this.makeKey(vaultId, chunk.globalChunkIndex);
    if (this.cache.has(key)) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_ALREADY_CACHED,
        userMessage: `Chunk #${chunk.globalChunkIndex} has already been scanned and cached`,
        category: ErrorCategory.OPERATION,
        severity: ErrorSeverity.WARNING,
      });
    }

    const now = Date.now();
    const cachedRecord: CachedChunk = {
      ...chunk,
      scannedAt: now,
      expiresAt: now + CHUNK_CACHE_TTL_MS,
    };

    this.cache.set(key, cachedRecord);
    return cachedRecord;
  }

  /**
   * Retrieves all unexpired cached chunks for a given vault.
   */
  public getCachedChunks(vaultId: Uint8Array): CachedChunk[] {
    this.purgeExpiredChunks();
    const vaultHex = Array.from(vaultId)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    const result: CachedChunk[] = [];

    for (const [key, chunk] of this.cache.entries()) {
      if (key.startsWith(vaultHex + ':')) {
        result.push(chunk);
      }
    }

    return result.sort((a, b) => a.globalChunkIndex - b.globalChunkIndex);
  }

  /**
   * Retrieves a specific cached chunk if present and unexpired.
   */
  public getChunk(vaultId: Uint8Array, globalChunkIndex: number): CachedChunk | null {
    this.purgeExpiredChunks();
    const key = this.makeKey(vaultId, globalChunkIndex);
    return this.cache.get(key) ?? null;
  }

  /**
   * Automatically purges all cached chunks that have exceeded the 72-hour TTL.
   * Returns the count of purged chunks.
   */
  public purgeExpiredChunks(): number {
    const now = Date.now();
    let purgedCount = 0;

    for (const [key, chunk] of this.cache.entries()) {
      if (now >= chunk.expiresAt) {
        this.cache.delete(key);
        purgedCount++;
      }
    }

    return purgedCount;
  }

  /**
   * Returns the time remaining in milliseconds before a cached chunk expires.
   */
  public getTimeRemainingMs(chunk: CachedChunk): number {
    const remaining = chunk.expiresAt - Date.now();
    return Math.max(0, remaining);
  }

  /**
   * Clears all cached chunks for a vault or completely.
   */
  public clearCache(vaultId?: Uint8Array): void {
    if (!vaultId) {
      this.cache.clear();
      return;
    }
    const vaultHex = Array.from(vaultId)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    for (const key of Array.from(this.cache.keys())) {
      if (key.startsWith(vaultHex + ':')) {
        this.cache.delete(key);
      }
    }
  }

  /**
   * Total number of currently cached chunks across all vaults.
   */
  public get size(): number {
    this.purgeExpiredChunks();
    return this.cache.size;
  }
}

