/**
 * @file chunkCache.ts
 * @summary Temporary Encrypted Chunk Cache with 72-Hour TTL.
 *
 * Implements in-memory caching of scanned NFC chunks. Chunks are cached locally
 * and automatically expire after 72 hours (CHUNK_CACHE_TTL_MS).
 *
 * Data Structure:
 * - Nested index: vaultIdHex -> (globalChunkIndex -> CachedChunk). Per-vault
 *   lookups and listings are O(1)/O(vault) instead of scanning every vault's
 *   chunks with string-prefix scans.
 *
 * Security & Reliability:
 * - Duplicate Detection: Rejects duplicate scans of already-cached chunks with
 *   `CHUNK_ALREADY_CACHED`.
 * - Automatic Expiration: Purges cached chunks strictly after 72 hours (259,200,000 ms).
 * - Integrity Validation: Verifies chunk hash (constant-time) before caching.
 *
 * Note: This cache is purely volatile session state; no persistent cache exists.
 */

import { CachedChunk, CHUNK_CACHE_TTL_MS } from '../contracts/bulkVault';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { computeChunkHash } from '../crypto/bulkEnvelope';

/** Character table for fast lowercase hex encoding of 16-byte vault IDs. */
const HEX_DIGITS = '0123456789abcdef';

/** Converts a byte array to a lowercase hex string using a character table. */
function toHexString(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    hex += HEX_DIGITS[b >> 4] + HEX_DIGITS[b & 0x0f];
  }
  return hex;
}

/**
 * Constant-time equality check of two same-length byte arrays.
 */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export class ChunkCacheManager {
  /** Nested volatile index: vaultIdHex -> (globalChunkIndex -> CachedChunk). */
  private readonly index: Map<string, Map<number, CachedChunk>> = new Map();

  /**
   * Stores a scanned chunk in the cache with a 72-hour expiration.
   * Throws `CHUNK_ALREADY_CACHED` if this chunk index is already cached.
   * Throws `CHUNK_HASH_MISMATCH` if chunk hash does not match chunk ciphertext.
   */
  public cacheChunk(
    vaultId: Uint8Array,
    chunk: Omit<CachedChunk, 'scannedAt' | 'expiresAt'>
  ): CachedChunk {
    this.purgeExpiredChunks();

    // Verify chunk hash integrity (constant-time comparison of 32-byte digests)
    const computedHash = computeChunkHash(chunk.ciphertext);
    if (computedHash.length !== chunk.chunkHash.length) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_HASH_MISMATCH,
        userMessage: 'Scanned chunk hash length mismatch',
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }
    if (!bytesEqual(computedHash, chunk.chunkHash)) {
      throw new GhostTagError({
        code: GhostTagErrorCode.CHUNK_HASH_MISMATCH,
        userMessage: `Scanned chunk ${chunk.globalChunkIndex} failed SHA-256 hash verification`,
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }

    const inner = this.getVaultIndex(vaultId);
    if (inner.has(chunk.globalChunkIndex)) {
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

    inner.set(chunk.globalChunkIndex, cachedRecord);
    return cachedRecord;
  }

  /**
   * Retrieves all unexpired cached chunks for a given vault, sorted by index.
   * O(number of cached chunks in this vault) — no scan across all vaults.
   */
  public getCachedChunks(vaultId: Uint8Array): CachedChunk[] {
    this.purgeExpiredChunks();
    const inner = this.index.get(toHexString(vaultId));
    if (!inner) {
      return [];
    }
    return Array.from(inner.values()).sort(
      (a, b) => a.globalChunkIndex - b.globalChunkIndex
    );
  }

  /**
   * Retrieves a specific cached chunk if present and unexpired. O(1) lookup.
   */
  public getChunk(vaultId: Uint8Array, globalChunkIndex: number): CachedChunk | null {
    this.purgeExpiredChunks();
    return this.index.get(toHexString(vaultId))?.get(globalChunkIndex) ?? null;
  }

  /**
   * Automatically purges all cached chunks that have exceeded the 72-hour TTL.
   * Also removes now-empty per-vault indexes. Returns the count of purged chunks.
   */
  public purgeExpiredChunks(): number {
    const now = Date.now();
    let purgedCount = 0;

    for (const [vaultHex, inner] of Array.from(this.index.entries())) {
      for (const [chunkIndex, chunk] of Array.from(inner.entries())) {
        if (now >= chunk.expiresAt) {
          inner.delete(chunkIndex);
          purgedCount++;
        }
      }
      if (inner.size === 0) {
        this.index.delete(vaultHex);
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
      this.index.clear();
      return;
    }
    this.index.delete(toHexString(vaultId));
  }

  /**
   * Total number of currently cached chunks across all vaults.
   */
  public get size(): number {
    this.purgeExpiredChunks();
    let total = 0;
    for (const inner of this.index.values()) {
      total += inner.size;
    }
    return total;
  }

  /**
   * Returns the per-vault index map, creating it if absent.
   */
  private getVaultIndex(vaultId: Uint8Array): Map<number, CachedChunk> {
    const vaultHex = toHexString(vaultId);
    let inner = this.index.get(vaultHex);
    if (!inner) {
      inner = new Map<number, CachedChunk>();
      this.index.set(vaultHex, inner);
    }
    return inner;
  }
}
