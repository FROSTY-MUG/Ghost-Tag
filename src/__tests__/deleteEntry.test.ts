/**
 * @file deleteEntry.test.ts
 * @summary Unit tests for Ghost-Tag v2.0.5 Android Entry Deletion & Safe Rewrite Engine.
 */

import {
  planEntryDeletion,
  validateRequiredRewriteTags,
  finalizeEntryDeletion,
  DELETE_ENTRY_WARNING_HEADER,
  DELETE_ENTRY_WARNING_BODY,
  CANNOT_DELETE_ENTRY_MESSAGE,
} from '../operations/deleteEntryOperation';
import { BulkVaultManifest } from '../contracts/bulkVault';
import { KeyStatus } from '../contracts/keyHierarchy';

describe('Ghost-Tag Android Entry Deletion & Safe Rewrite', () => {
  const fileId1 = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const fileId2 = new Uint8Array([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);

  const mockManifest: BulkVaultManifest = {
    vaultId: new Uint8Array(16),
    formatVersion: 2,
    vaultName: 'Test Field Vault',
    createdAt: 1000,
    updatedAt: 1000,
    kdfSalt: new Uint8Array(32),
    activeDekWrapped: {
      keyId: 'test-key-id',
      wrappedCiphertext: new Uint8Array(32),
      nonce: new Uint8Array(12),
      tag: new Uint8Array(16),
      keyVersion: 1,
      status: KeyStatus.ACTIVE,
      creationTime: 1000,
    },
    recoveryEnvelope: {
      recoveryId: 'test-recovery-id',
      salt: new Uint8Array(32),
      params: {
        salt: new Uint8Array(32),
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
        version: 0x13,
      },
      wrappedDEKs: [],
      checksum: new Uint8Array(16),
      createdAt: 1000,
    },
    totalVaultChunks: 4,
    files: [
      {
        fileId: fileId1,
        fileName: 'photo.jpg',
        mimeType: 'image/jpeg',
        originalSizeBytes: 1024,
        ciphertextSizeBytes: 1040,
        chunkCount: 2,
        chunkHashes: [new Uint8Array(32), new Uint8Array(32)],
        ciphertextSha256: new Uint8Array(32),
        addedAt: 1000,
      },
      {
        fileId: fileId2,
        fileName: 'notes.txt',
        mimeType: 'text/plain',
        originalSizeBytes: 500,
        ciphertextSizeBytes: 516,
        chunkCount: 2,
        chunkHashes: [new Uint8Array(32), new Uint8Array(32)],
        ciphertextSha256: new Uint8Array(32),
        addedAt: 1000,
      },
    ],
    tagMappings: [
      {
        tagUidHex: '04aabbccddeeff',
        globalChunkIndex: 0,
        fileId: fileId1,
        fileChunkIndex: 0,
        writtenAt: 1000,
      },
      {
        tagUidHex: '04112233445566',
        globalChunkIndex: 1,
        fileId: fileId1,
        fileChunkIndex: 1,
        writtenAt: 1000,
      },
      {
        tagUidHex: '04998877665544',
        globalChunkIndex: 2,
        fileId: fileId2,
        fileChunkIndex: 0,
        writtenAt: 1000,
      },
    ],
  };

  test('warning text strictly matches specification Section 13', () => {
    expect(DELETE_ENTRY_WARNING_HEADER).toBe('DELETE ENTRY');
    expect(DELETE_ENTRY_WARNING_BODY).toContain(
      'Deleting this entry requires rewriting encrypted Ghost data on the affected NFC tags.'
    );
    expect(DELETE_ENTRY_WARNING_BODY).toContain(
      'This operation may fail if a tag is damaged, removed too early, or becomes unreadable.'
    );
    expect(DELETE_ENTRY_WARNING_BODY).toContain(
      'Existing entries may become temporarily unavailable until the rewrite completes.'
    );
    expect(CANNOT_DELETE_ENTRY_MESSAGE).toContain(
      'The NFC tag containing required encrypted data is missing or unreadable.'
    );
  });

  test('plans entry deletion and maps affected tags correctly', () => {
    const plan = planEntryDeletion(mockManifest, 'photo.jpg');
    expect(plan.targetEntryName).toBe('photo.jpg');
    expect(plan.affectedTagUids).toEqual(['04aabbccddeeff', '04112233445566']);
    expect(plan.remainingFiles.length).toBe(1);
    expect(plan.remainingFiles[0].fileName).toBe('notes.txt');
    expect(plan.totalRemainingChunks).toBe(2);
  });

  test('throws if entry is not in manifest', () => {
    expect(() => planEntryDeletion(mockManifest, 'nonexistent.pdf')).toThrow(
      /Target entry "nonexistent.pdf" not found/
    );
  });

  test('validates required tags presence before rewrite', () => {
    const plan = planEntryDeletion(mockManifest, 'photo.jpg');
    
    // Success when all tags are present
    const valid = validateRequiredRewriteTags(plan, ['04aabbccddeeff', '04112233445566']);
    expect(valid.ready).toBe(true);

    // Fails when a required tag is missing
    expect(() =>
      validateRequiredRewriteTags(plan, ['04aabbccddeeff'])
    ).toThrow(/CANNOT DELETE ENTRY/);
  });

  test('finalizes deletion only after verified tag rewrite and updates manifest', async () => {
    const plan = planEntryDeletion(mockManifest, 'photo.jpg');
    
    const verifications = [
      { tagUidHex: '04aabbccddeeff', chunkIndex: 0, verified: true, hashMatches: true },
      { tagUidHex: '04112233445566', chunkIndex: 1, verified: true, hashMatches: true },
    ];

    const result = await finalizeEntryDeletion(mockManifest, plan, verifications);
    expect(result.success).toBe(true);
    expect(result.deletedEntryName).toBe('photo.jpg');
    expect(result.rewrittenTagCount).toBe(2);
    expect(result.updatedManifest.files.length).toBe(1);
    expect(result.updatedManifest.files[0].fileName).toBe('notes.txt');
    expect(result.updatedManifest.tagMappings.length).toBe(1);
    expect(result.updatedManifest.tagMappings[0].tagUidHex).toBe('04998877665544');
  });

  test('aborts finalization if any tag verification failed', async () => {
    const plan = planEntryDeletion(mockManifest, 'photo.jpg');
    
    const failedVerifications = [
      { tagUidHex: '04aabbccddeeff', chunkIndex: 0, verified: true, hashMatches: true },
      { tagUidHex: '04112233445566', chunkIndex: 1, verified: false, hashMatches: false },
    ];

    await expect(finalizeEntryDeletion(mockManifest, plan, failedVerifications)).rejects.toThrow(
      /Write could not be verified/
    );
  });
});
