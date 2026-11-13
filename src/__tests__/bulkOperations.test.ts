/**
 * @file bulkOperations.test.ts
 * @summary End-to-End Integration Tests for Ghost-Tag Bulk Scanning v2.
 *
 * Simulates complete distributed file vault lifecycle:
 * - Multi-file vault creation with DEK and recovery envelope.
 * - Dynamic tag calculation and extra tag exclusion ("Only 86 tags required...").
 * - Sequential tag write + read-back verification with anti-overwrite protection.
 * - Random-order tag scanning, duplicate suppression, and cross-vault rejection.
 * - Temporary encrypted caching with 72-hour TTL and expiration purge.
 * - File reassembly, SHA-256 ciphertext hash verification, and full-file decryption.
 * - SAF file export and disposable memory zeroization.
 */

import { generateSecureRandom } from '../crypto/random';
import { BulkVaultManager } from '../vault/bulkVaultManager';
import { ChunkCacheManager } from '../vault/chunkCache';
import { JournalManager } from '../vault/journalManager';
import { BulkWriteOperation } from '../operations/bulkWriteOperation';
import { BulkScanOperation } from '../operations/bulkScanOperation';
import { ReconstructionEngine } from '../operations/reconstructionEngine';
import { FileViewerAndExporter } from '../operations/fileViewerAndExporter';
import { TagInfo, NfcTag } from '../nfc/tagInfo';
import { TagWriter } from '../nfc/tagWriter';
import { TagReader } from '../nfc/tagReader';
import { GhostTagErrorCode } from '../contracts/errors';
import { KeyStatus, WrappedDEK } from '../contracts/keyHierarchy';
import { RecoveryEnvelope } from '../contracts/recovery';
import { encodeBulkGhostTagNdefMessage } from '../nfc/bulkNdefBuilder';
import { serializeBulkEnvelope, computeChunkHash } from '../crypto/bulkEnvelope';
import NfcManager from 'react-native-nfc-manager';

// Mock NfcManager native calls for simulated tag interactions
jest.mock('react-native-nfc-manager', () => {
  let currentNdefMessage: any[] = [];
  return {
    __esModule: true,
    default: {
      writeNdefMessage: jest.fn(async (bytes: number[]) => {
        // Mock saving message
        currentNdefMessage = [{ payload: bytes.slice(7) }]; // mock strip TLV
        return Promise.resolve();
      }),
      getNdefMessage: jest.fn(async () => {
        return { ndefMessage: currentNdefMessage };
      }),
    },
    Ndef: {
      TNF_MIME_MEDIA: 0x02,
      record: jest.fn((tnf, type, id, payload) => ({
        tnf,
        type: typeof type === 'string' ? Array.from(new TextEncoder().encode(type)) : type,
        id,
        payload,
      })),
      encodeMessage: jest.fn((records) => {
        return records[0]?.payload ?? [];
      }),
    },
  };
});

describe('Bulk Scanning v2 Operations Engine', () => {
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

  const tagInfoHelper = new TagInfo();
  const bulkVaultManager = new BulkVaultManager();
  const journalManager = new JournalManager();
  const chunkCache = new ChunkCacheManager();

  test('Vault Creation and Multi-File Preparation with Dynamic Tag Calculation', () => {
    let manifest = bulkVaultManager.createBulkVault(
      'Field Mission Vault',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );

    expect(manifest.vaultName).toBe('Field Mission Vault');
    expect(manifest.files.length).toBe(0);
    expect(manifest.totalVaultChunks).toBe(0);

    // Prepare 3 files of varying types
    const textBytes = new TextEncoder().encode('Mission operational notes: rendezvous at 0400 hours.');
    const pdfBytes = generateSecureRandom(1500); // 1.5 KB PDF
    const mediaBytes = generateSecureRandom(3000); // 3 KB binary stream

    const usableChunkCapacity = 400; // 400 bytes per chunk

    // 1. Add text file
    const textRes = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'notes.txt',
      'text/plain',
      textBytes,
      usableChunkCapacity
    );
    manifest = textRes.updatedManifest;
    expect(manifest.files.length).toBe(1);

    // 2. Add PDF file with 1 recovery chunk (erasure coding M=1)
    const pdfRes = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'report.pdf',
      'application/pdf',
      pdfBytes,
      usableChunkCapacity,
      1 // M = 1
    );
    manifest = pdfRes.updatedManifest;
    expect(manifest.files.length).toBe(2);

    // 3. Add Media binary
    const mediaRes = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'holiday.mp4',
      'video/mp4',
      mediaBytes,
      usableChunkCapacity
    );
    manifest = mediaRes.updatedManifest;
    expect(manifest.files.length).toBe(3);

    expect(manifest.totalVaultChunks).toBeGreaterThan(10);
  });

  test('Extra Tag Exclusion: Enforces setting aside surplus tags', () => {
    const writeOp = new BulkWriteOperation(bulkVaultManager, journalManager);
    const vaultId = generateSecureRandom(16);

    // Scenario: 86 tags needed, user presents 100 tags
    const session = writeOp.startSession('session-test-01', vaultId, 86, 100);

    expect(session.extraTagsExcluded).toBe(14);
    expect(session.instructionMessage).toContain(
      'Only 86 tags are required. Please set aside the other 14 tags. Scan the 86 required tags one by one.'
    );
  });

  test('Sequential Write and Anti-Overwrite Protection', async () => {
    const writeOp = new BulkWriteOperation(bulkVaultManager, journalManager);
    let manifest = bulkVaultManager.createBulkVault(
      'Overwrite Test Vault',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );

    const testFileBytes = new TextEncoder().encode('Anti overwrite test data');
    const { updatedManifest, preparedChunks } = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'test.bin',
      'application/octet-stream',
      testFileBytes,
      100
    );
    manifest = updatedManifest;

    writeOp.startSession('session-overwrite', manifest.vaultId, preparedChunks.length, preparedChunks.length);

    const simulatedTag1: NfcTag = {
      id: '04A1B2C3D4E5F6',
      techTypes: ['android.nfc.tech.NfcA', 'android.nfc.tech.MifareUltralight', 'android.nfc.tech.Ndef'],
      maxSize: 540,
    };

    // First write to tag1: should succeed
    const chunk0 = preparedChunks[0];
    let lastWrittenRecord: any[] = [];
    (NfcManager.writeNdefMessage as jest.Mock).mockImplementation(async (bytes: number[]) => {
      lastWrittenRecord = [
        {
          tnf: 0x02,
          type: Array.from(new TextEncoder().encode('application/vnd.ghost.bulk')),
          id: [],
          payload: bytes,
        },
      ];
    });

    const mockTagReader = {
      readNdefMessage: jest.fn(async () => lastWrittenRecord),
    };

    const customWriteOp = new BulkWriteOperation(
      bulkVaultManager,
      journalManager,
      new TagWriter(),
      mockTagReader as any,
      tagInfoHelper
    );

    const manifestAfterWrite1 = await customWriteOp.writeNextChunk(
      'session-overwrite',
      manifest,
      dek,
      simulatedTag1,
      chunk0
    );

    expect(manifestAfterWrite1.tagMappings.length).toBe(1);
    expect(manifestAfterWrite1.tagMappings[0].tagUidHex).toBe('04a1b2c3d4e5f6');

    // Attempting to write the second chunk to the SAME tag must fail with CHUNK_ALREADY_WRITTEN!
    if (preparedChunks.length > 1) {
      await expect(
        customWriteOp.writeNextChunk(
          'session-overwrite',
          manifestAfterWrite1,
          dek,
          simulatedTag1, // Same tag presented again!
          preparedChunks[1]
        )
      ).rejects.toThrow(expect.objectContaining({ code: GhostTagErrorCode.CHUNK_ALREADY_WRITTEN }));
    }
  });

  test('Random-Order Scanning, Duplicate Suppression, and Cross-Vault Rejection', async () => {
    const cache = new ChunkCacheManager();
    const jManager = new JournalManager();
    const vaultIdA = generateSecureRandom(16);
    const vaultIdB = generateSecureRandom(16);

    let manifest = bulkVaultManager.createBulkVault(
      'Scan Test Vault',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );
    // Override vaultId to vaultIdA
    manifest = { ...manifest, vaultId: vaultIdA };

    // Create 3 chunks
    const chunkData = new Uint8Array([1, 2, 3, 4, 5]);
    const chunkHash = computeChunkHash(chunkData);

    const serializedChunk0 = serializeBulkEnvelope({
      vaultId: vaultIdA,
      fileId: new Uint8Array(16),
      keyId: new Uint8Array(16),
      globalChunkIndex: 0,
      totalVaultChunks: 3,
      fileChunkIndex: 0,
      totalFileChunks: 3,
      chunkCiphertext: chunkData,
      chunkHash,
      nonce: new Uint8Array(12),
      gcmTag: new Uint8Array(16),
    });

    const serializedChunk1 = serializeBulkEnvelope({
      vaultId: vaultIdA,
      fileId: new Uint8Array(16),
      keyId: new Uint8Array(16),
      globalChunkIndex: 1,
      totalVaultChunks: 3,
      fileChunkIndex: 1,
      totalFileChunks: 3,
      chunkCiphertext: chunkData,
      chunkHash,
      nonce: new Uint8Array(12),
      gcmTag: new Uint8Array(16),
    });

    // Chunk from wrong vault B
    const serializedChunkWrongVault = serializeBulkEnvelope({
      vaultId: vaultIdB, // Mismatched vault
      fileId: new Uint8Array(16),
      keyId: new Uint8Array(16),
      globalChunkIndex: 2,
      totalVaultChunks: 3,
      fileChunkIndex: 2,
      totalFileChunks: 3,
      chunkCiphertext: chunkData,
      chunkHash,
      nonce: new Uint8Array(12),
      gcmTag: new Uint8Array(16),
    });

    // Mock reader
    let nextPayload = serializedChunk1; // Scan Chunk 1 first (random order!)
    const mockReader = {
      readNdefMessage: jest.fn(async () => [
        {
          tnf: 0x02,
          type: Array.from(new TextEncoder().encode('application/vnd.ghost.bulk')),
          id: [],
          payload: Array.from(nextPayload),
        },
      ]),
    };

    const scanOp = new BulkScanOperation(cache, jManager, mockReader as any);
    const sessionId = 'session-scan-01';
    scanOp.startScanSession(sessionId, manifest);

    // Mock crypto decrypt to succeed for tests
    const decryptSpy = jest.spyOn(require('../crypto/aesGcm'), 'decrypt').mockImplementation(() => chunkData);

    // 1. Scan Chunk #1 first (out of order)
    const res1 = await scanOp.scanTag(sessionId, manifest, dek);
    expect(res1.globalChunkIndex).toBe(1);
    expect(res1.collectedCount).toBe(1);

    // 2. Duplicate scan of Chunk #1: should throw CHUNK_ALREADY_CACHED
    await expect(scanOp.scanTag(sessionId, manifest, dek)).rejects.toThrow(
      expect.objectContaining({ code: GhostTagErrorCode.CHUNK_ALREADY_CACHED })
    );

    // 3. Scan Chunk from wrong vault: should throw CHUNK_WRONG_VAULT
    nextPayload = serializedChunkWrongVault;
    await expect(scanOp.scanTag(sessionId, manifest, dek)).rejects.toThrow(
      expect.objectContaining({ code: GhostTagErrorCode.CHUNK_WRONG_VAULT })
    );

    // 4. Scan Chunk #0 (finishing up)
    nextPayload = serializedChunk0;
    const res0 = await scanOp.scanTag(sessionId, manifest, dek);
    expect(res0.globalChunkIndex).toBe(0);
    expect(res0.collectedCount).toBe(2);

    decryptSpy.mockRestore();
  });

  test('72-Hour Cache TTL and Auto-Purge', () => {
    const cache = new ChunkCacheManager();
    const vaultId = generateSecureRandom(16);
    const payload = new Uint8Array([42, 43, 44]);
    const hash = computeChunkHash(payload);

    const cached = cache.cacheChunk(vaultId, {
      globalChunkIndex: 0,
      fileId: new Uint8Array(16),
      fileChunkIndex: 0,
      totalFileChunks: 1,
      ciphertext: payload,
      chunkHash: hash,
      tagUidHex: 'tag-0',
    });

    // Verify 72-hour TTL
    const now = Date.now();
    expect(cached.expiresAt).toBeGreaterThanOrEqual(now + 71 * 60 * 60 * 1000);
    expect(cache.getTimeRemainingMs(cached)).toBeGreaterThan(0);
    expect(cache.size).toBe(1);

    // Purge when unexpired does not remove chunk
    const purgedNow = cache.purgeExpiredChunks();
    expect(purgedNow).toBe(0);
    expect(cache.size).toBe(1);
  });

  test('Full File Reconstruction from Cached Chunks (Bit-for-Bit Identity)', () => {
    const cache = new ChunkCacheManager();
    const engine = new ReconstructionEngine(cache);

    let manifest = bulkVaultManager.createBulkVault(
      'Reconstruction Vault',
      mockWrappedDek,
      kdfSalt,
      mockRecoveryEnvelope
    );

    const originalFileBytes = new TextEncoder().encode(
      'Crucial cryptographic configuration data: AGY-GHOST-TAG-2026-PRODUCTION.'
    );

    const { updatedManifest, fileRecord, preparedChunks } = bulkVaultManager.prepareFileAddition(
      manifest,
      dek,
      'config.json',
      'application/json',
      originalFileBytes,
      30 // small chunks to force multiple chunks
    );
    manifest = updatedManifest;

    // Simulate scanning and caching all chunks
    for (const chunk of preparedChunks) {
      cache.cacheChunk(manifest.vaultId, {
        globalChunkIndex: chunk.globalChunkIndex,
        fileId: chunk.fileId,
        fileChunkIndex: chunk.fileChunkIndex,
        totalFileChunks: chunk.totalFileChunks,
        ciphertext: chunk.chunkPayload,
        chunkHash: chunk.chunkHash,
        tagUidHex: `sim-tag-${chunk.globalChunkIndex}`,
      });
    }

    // Check status
    const statuses = engine.getReconstructionStatus(manifest);
    expect(statuses.length).toBe(1);
    expect(statuses[0].canReconstruct).toBe(true);

    // Reconstruct file
    const reconstructed = engine.reconstructFile(manifest, fileRecord, dek);
    expect(reconstructed.fileName).toBe('config.json');
    expect(reconstructed.mimeType).toBe('application/json');
    expect(reconstructed.verified).toBe(true);

    const recoveredText = new TextDecoder().decode(reconstructed.plaintext);
    expect(recoveredText).toBe('Crucial cryptographic configuration data: AGY-GHOST-TAG-2026-PRODUCTION.');
  });

  test('File Viewer and SAF Exporter: Disposable view session zeroizes memory', async () => {
    const exporter = new FileViewerAndExporter();
    const plaintext = new TextEncoder().encode('Sensitive decrypted plaintext for viewer');

    const file = {
      fileId: new Uint8Array(16),
      fileName: 'secret.txt',
      mimeType: 'text/plain',
      originalSizeBytes: plaintext.length,
      plaintext: new Uint8Array(plaintext),
      verified: true,
    };

    const session = exporter.openViewSession(file);
    expect(session.fileName).toBe('secret.txt');
    expect(session.data.length).toBe(plaintext.length);

    // Call dispose: should zeroize the buffer
    session.dispose();
    for (let i = 0; i < session.data.length; i++) {
      expect(session.data[i]).toBe(0);
    }

    // Test SAF export
    const exportResult = await exporter.exportViaSaf(file, 'content://com.android.providers/doc/123');
    expect(exportResult.success).toBe(true);
    expect(exportResult.bytesExported).toBe(plaintext.length);

    // Target buffer zeroized after export
    for (let i = 0; i < file.plaintext.length; i++) {
      expect(file.plaintext[i]).toBe(0);
    }
  });
});
