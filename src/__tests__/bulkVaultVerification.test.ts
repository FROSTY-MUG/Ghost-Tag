/**
 * @file bulkVaultVerification.test.ts
 * @summary Tests for Bulk Vault Integrity Verification & Reconstruction Enhancements.
 *
 * Covers:
 * - verifyBulkVault: per-file presence, hash, and full-ciphertext-hash verification
 *   without requiring the DEK.
 * - reconstructFile regression: erasure-coded files with a non-multiple chunk size
 *   reconstruct bit-for-bit using the manifest's original (unpadded) chunk lengths.
 * - ChunkCacheManager: nested per-vault index behaviors (duplicate rejection,
 *   O(1) lookups, per-vault clear, TTL purge).
 * - BulkVaultManager.recordTagMapping: O(1) duplicate detection via index.
 */

import { generateSecureRandom } from '../crypto/random';
import { computeChunkHash } from '../crypto/bulkEnvelope';
import { BulkVaultManager } from '../vault/bulkVaultManager';
import { ChunkCacheManager } from '../vault/chunkCache';
import { ReconstructionEngine } from '../operations/reconstructionEngine';
import { KeyStatus, WrappedDEK } from '../contracts/keyHierarchy';
import { RecoveryEnvelope } from '../contracts/recovery';
import { BulkVaultManifest, CachedChunk } from '../contracts/bulkVault';
import { GhostTagErrorCode } from '../contracts/errors';

const dek = generateSecureRandom(32);
const kdfSalt = generateSecureRandom(32);

const mockWrappedDek: WrappedDEK = {
  keyId: '0102030405060708090a0b0c0d0e0f10',
  wrappedCiphertext: generateSecureRandom(32),
  nonce: generateSecureRandom(12),
  tag: generateSecureRandom(16),
  creationTime: Date.now(),
  keyVersion: 1,
  status: KeyStatus.ACTIVE,
};

const mockRecoveryEnvelope: RecoveryEnvelope = {
  recoveryId: 'rec-test-1234',
  salt: generateSecureRandom(32),
  params: {
    memoryCost: 65536,
    timeCost: 5,
    parallelism: 4,
    version: 0x13,
    salt: generateSecureRandom(32),
  },
  wrappedDEKs: [],
  checksum: generateSecureRandom(16),
  createdAt: Date.now(),
};

const bulkVaultManager = new BulkVaultManager();
const chunkCache = new ChunkCacheManager();
const engine = new ReconstructionEngine(chunkCache);

/** Caches prepared chunks the same way BulkScanOperation does (decrypted payload + manifest hash). */
function cacheAllPreparedChunks(
  manifest: BulkVaultManifest,
  preparedChunks: {
    globalChunkIndex: number;
    fileId: Uint8Array;
    fileChunkIndex: number;
    totalFileChunks: number;
    chunkPayload: Uint8Array;
    chunkHash: Uint8Array;
  }[]
): void {
  for (const chunk of preparedChunks) {
    chunkCache.cacheChunk(manifest.vaultId, {
      globalChunkIndex: chunk.globalChunkIndex,
      fileId: chunk.fileId,
      fileChunkIndex: chunk.fileChunkIndex,
      totalFileChunks: chunk.totalFileChunks,
      ciphertext: chunk.chunkPayload,
      chunkHash: chunk.chunkHash,
      tagUidHex: `sim-tag-${chunk.globalChunkIndex}`,
    });
  }
}

describe('Bulk Vault Integrity Verification & Reconstruction Enhancements', () => {
  test('verifyBulkVault: M=0 vault reports all chunks present and hash verified', () => {
    const manifest = bulkVaultManager.createBulkVault(
      'Verify Vault M0',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );
    const fileBytes = new TextEncoder().encode(
      'Vault integrity verification payload — single file, no erasure.'
    );
    const { updatedManifest, fileRecord, preparedChunks } = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'notes.txt',
      'text/plain',
      fileBytes,
      50
    );
    expect(preparedChunks.length).toBeGreaterThan(1);
    cacheAllPreparedChunks(updatedManifest, preparedChunks);

    const report = engine.verifyBulkVault(updatedManifest);
    expect(report.isVaultVerified).toBe(true);
    expect(report.files.length).toBe(1);

    const f = report.files[0];
    expect(f.fileName).toBe('notes.txt');
    expect(f.chunkCount).toBe(preparedChunks.length);
    expect(f.availableChunks).toBe(preparedChunks.length);
    expect(f.missingChunkIndices).toEqual([]);
    expect(f.chunkHashMismatches).toEqual([]);
    expect(f.allChunksPresent).toBe(true);
    expect(f.allChunkHashesMatch).toBe(true);
    expect(f.canVerifyCiphertextHash).toBe(true);
    expect(f.ciphertextHashValid).toBe(true);
    expect(f.isVerified).toBe(true);

    // Reconstruction remains functional
    const reconstructed = engine.reconstructFile(updatedManifest, fileRecord, dek);
    expect(reconstructed.verified).toBe(true);
    expect(new TextDecoder().decode(reconstructed.plaintext)).toBe(
      'Vault integrity verification payload — single file, no erasure.'
    );
  });

  test('verifyBulkVault + reconstructFile: M=1 vault with non-multiple chunk size verifies and reconstructs bit-for-bit', () => {
    const manifest = bulkVaultManager.createBulkVault(
      'Verify Vault M1',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );
    // 987-byte payload with 100-byte chunks => final data chunk is shorter than the
    // max chunk length; erasure coding pads it, so reconstruction needs original lengths.
    const fileBytes = generateSecureRandom(987);
    const { updatedManifest, fileRecord, preparedChunks } = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'blob.bin',
      'application/octet-stream',
      fileBytes,
      100,
      1 // M = 1
    );

    expect(fileRecord.erasureCoding?.recoveryChunksM).toBe(1);
    const originalLengths = fileRecord.chunkOriginalLengths;
    expect(originalLengths).toBeDefined();
    expect(originalLengths!.length).toBe(fileRecord.erasureCoding!.dataChunksK);
    expect(originalLengths![originalLengths!.length - 1]).toBeLessThan(100);

    cacheAllPreparedChunks(updatedManifest, preparedChunks);

    const report = engine.verifyBulkVault(updatedManifest);
    expect(report.isVaultVerified).toBe(true);
    const f = report.files[0];
    expect(f.isVerified).toBe(true);
    expect(f.canVerifyCiphertextHash).toBe(true);
    expect(f.ciphertextHashValid).toBe(true);

    // Regression: reconstructFile must reproduce the original bytes exactly
    const reconstructed = engine.reconstructFile(updatedManifest, fileRecord, dek);
    expect(Array.from(reconstructed.plaintext)).toEqual(Array.from(fileBytes));

    // Legacy-manifest path: without stored original lengths, reconstruction still
    // trims padded chunks to the authoritative ciphertext size and verifies.
    const legacyRecord = { ...fileRecord };
    (legacyRecord as { chunkOriginalLengths?: readonly number[] }).chunkOriginalLengths = undefined;
    const legacyReconstructed = engine.reconstructFile(updatedManifest, legacyRecord, dek);
    expect(Array.from(legacyReconstructed.plaintext)).toEqual(Array.from(fileBytes));
  });

  test('verifyBulkVault: missing chunks are reported and the file is not verified', () => {
    const manifest = bulkVaultManager.createBulkVault(
      'Verify Vault Missing',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );
    const fileBytes = new TextEncoder().encode('Some integrity payload for missing chunk scenario.');
    const { updatedManifest, preparedChunks } = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'miss.txt',
      'text/plain',
      fileBytes,
      50
    );

    // Cache all chunks except file chunk index 0
    for (const chunk of preparedChunks) {
      if (chunk.fileChunkIndex === 0) continue;
      chunkCache.cacheChunk(updatedManifest.vaultId, {
        globalChunkIndex: chunk.globalChunkIndex,
        fileId: chunk.fileId,
        fileChunkIndex: chunk.fileChunkIndex,
        totalFileChunks: chunk.totalFileChunks,
        ciphertext: chunk.chunkPayload,
        chunkHash: chunk.chunkHash,
        tagUidHex: `sim-tag-${chunk.globalChunkIndex}`,
      });
    }

    const report = engine.verifyBulkVault(updatedManifest);
    expect(report.isVaultVerified).toBe(false);
    const f = report.files[0];
    expect(f.allChunksPresent).toBe(false);
    expect(f.missingChunkIndices).toEqual([0]);
    expect(f.availableChunks).toBe(preparedChunks.length - 1);
    expect(f.canVerifyCiphertextHash).toBe(false);
    expect(f.isVerified).toBe(false);
  });

  test('verifyBulkVault: tampered cached chunk hash is reported as a mismatch', () => {
    const manifest = bulkVaultManager.createBulkVault(
      'Verify Vault Tamper',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );
    const fileBytes = new TextEncoder().encode('Tamper detection scenario payload.');
    const { updatedManifest, preparedChunks } = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'tamp.txt',
      'text/plain',
      fileBytes,
      50
    );
    cacheAllPreparedChunks(updatedManifest, preparedChunks);

    const first = chunkCache.getChunk(updatedManifest.vaultId, 0);
    expect(first).not.toBeNull();
    // Simulate a tampered chunk hash stored on a scanned tag
    (first as { chunkHash: Uint8Array }).chunkHash = generateSecureRandom(32);

    const report = engine.verifyBulkVault(updatedManifest);
    const f = report.files[0];
    expect(f.allChunkHashesMatch).toBe(false);
    expect(f.chunkHashMismatches).toContain(0);
    expect(f.isVerified).toBe(false);
    // The full ciphertext hash is still independently verifiable (data itself is intact)
    expect(f.canVerifyCiphertextHash).toBe(true);
    expect(f.ciphertextHashValid).toBe(true);
  });
});

describe('ChunkCacheManager nested index', () => {
  const vaultA = generateSecureRandom(16);
  const vaultB = generateSecureRandom(16);

  function makeChunk(idx: number, payload: Uint8Array): Omit<CachedChunk, 'scannedAt' | 'expiresAt'> {
    return {
      globalChunkIndex: idx,
      fileId: generateSecureRandom(16),
      fileChunkIndex: idx,
      totalFileChunks: 2,
      ciphertext: payload,
      chunkHash: computeChunkHash(payload),
      tagUidHex: `tag-${idx}`,
    };
  }

  test('duplicate scans are rejected; O(1) getChunk; per-vault isolation and clearCache', () => {
    const cache = new ChunkCacheManager();
    const payload = generateSecureRandom(64);

    cache.cacheChunk(vaultA, makeChunk(0, payload));
    expect(() => cache.cacheChunk(vaultA, makeChunk(0, payload))).toThrow(
      expect.objectContaining({ code: GhostTagErrorCode.CHUNK_ALREADY_CACHED })
    );

    expect(cache.getChunk(vaultA, 0)).not.toBeNull();
    expect(cache.getChunk(vaultA, 99)).toBeNull();
    // Cross-vault isolation
    expect(cache.getChunk(vaultB, 0)).toBeNull();
    expect(cache.getCachedChunks(vaultA).length).toBe(1);
    expect(cache.getCachedChunks(vaultB).length).toBe(0);
    expect(cache.size).toBe(1);

    cache.clearCache(vaultA);
    expect(cache.getCachedChunks(vaultA).length).toBe(0);
  });

  test('purgeExpiredChunks removes expired entries and empty vaults', () => {
    const cache = new ChunkCacheManager();
    cache.cacheChunk(vaultA, makeChunk(0, generateSecureRandom(64)));

    const record = cache.getChunk(vaultA, 0);
    expect(record).not.toBeNull();
    (record as { expiresAt: number }).expiresAt = Date.now() - 1000;

    expect(cache.purgeExpiredChunks()).toBe(1);
    expect(cache.size).toBe(0);
  });
});

describe('BulkVaultManager.recordTagMapping O(1) index', () => {
  test('duplicate uid registration is rejected with the original chunk index', () => {
    const manager = new BulkVaultManager();
    const manifest = manager.createBulkVault(
      'Map Index Vault',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );
    const fileId = generateSecureRandom(16);

    const m1 = manager.recordTagMapping(manifest, '04A1B2C3D4E5F6', 7, fileId, 0);
    expect(m1.tagMappings.length).toBe(1);
    expect(m1.tagMappings[0].globalChunkIndex).toBe(7);
    expect(m1.tagMappings[0].tagUidHex).toBe('04a1b2c3d4e5f6');

    expect(() =>
      manager.recordTagMapping(m1, '04A1B2C3D4E5F6', 8, fileId, 1)
    ).toThrow(expect.objectContaining({ code: GhostTagErrorCode.CHUNK_ALREADY_WRITTEN }));

    const m2 = manager.recordTagMapping(m1, '04DDEEFF0011', 8, fileId, 1);
    expect(m2.tagMappings.length).toBe(2);
    expect(m2.tagMappings[1].globalChunkIndex).toBe(8);
  });
});
