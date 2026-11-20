/**
 * @file bulkEnvelope.test.ts
 * @summary Unit Tests for Ghost-Tag Bulk Binary Envelope Specification (v2).
 *
 * Verifies the 134-byte fixed overhead, Little-Endian layout, 74-byte AAD binding,
 * serialization, parsing, and fuzzing resistance.
 */

import {
  BULK_FORMAT_VERSION_V2,
  RECORD_TYPE_BULK_CHUNK,
  BULK_ENVELOPE_FIXED_OVERHEAD,
  BULK_AAD_LENGTH,
  BulkOffsets,
} from '../contracts/bulkEnvelope';
import {
  serializeBulkEnvelope,
  parseBulkEnvelope,
  constructBulkAAD,
  computeChunkHash,
  validateBulkEnvelope,
} from '../crypto/bulkEnvelope';
import {
  buildBulkGhostTagNdefRecord,
  extractBulkGhostTagPayload,
} from '../nfc/bulkNdefBuilder';
import { GhostTagErrorCode } from '../contracts/errors';

describe('Bulk Binary Envelope Specification (v2)', () => {
  const dummyVaultId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
  const dummyFileId = new Uint8Array([16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1]);
  const dummyKeyId = new Uint8Array([20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35]);
  const dummyNonce = new Uint8Array([1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6]); // 12B
  const dummyGcmTag = new Uint8Array(16).fill(0xee); // 16B
  const sampleChunkCiphertext = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04]);

  test('Fixed binary overhead must equal exactly 134 bytes', () => {
    expect(BULK_ENVELOPE_FIXED_OVERHEAD).toBe(134);
    expect(BULK_AAD_LENGTH).toBe(74);
  });

  test('constructBulkAAD generates canonical 74-byte buffer with Little-Endian uint32s', () => {
    const aad = constructBulkAAD({
      vaultId: dummyVaultId,
      fileId: dummyFileId,
      keyId: dummyKeyId,
      globalChunkIndex: 5,
      totalVaultChunks: 86,
      fileChunkIndex: 2,
      totalFileChunks: 10,
      chunkCiphertextLength: 100,
    });

    expect(aad.length).toBe(74);

    // Magic
    expect(aad[0]).toBe(0x47);
    expect(aad[1]).toBe(0x54);
    expect(aad[2]).toBe(0x41);
    expect(aad[3]).toBe(0x47);

    // Version & Record Type
    expect(aad[4]).toBe(BULK_FORMAT_VERSION_V2);
    expect(aad[5]).toBe(RECORD_TYPE_BULK_CHUNK);

    // Little-Endian values
    const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
    expect(view.getUint32(54, true)).toBe(5);   // globalChunkIndex
    expect(view.getUint32(58, true)).toBe(86);  // totalVaultChunks
    expect(view.getUint32(62, true)).toBe(2);   // fileChunkIndex
    expect(view.getUint32(66, true)).toBe(10);  // totalFileChunks
    expect(view.getUint32(70, true)).toBe(100); // chunkCiphertextLength
  });

  test('serializeBulkEnvelope and parseBulkEnvelope round-trip with byte accuracy', () => {
    const chunkHash = computeChunkHash(sampleChunkCiphertext);
    expect(chunkHash.length).toBe(32);

    const serialized = serializeBulkEnvelope({
      vaultId: dummyVaultId,
      fileId: dummyFileId,
      keyId: dummyKeyId,
      globalChunkIndex: 42,
      totalVaultChunks: 100,
      fileChunkIndex: 7,
      totalFileChunks: 15,
      chunkCiphertext: sampleChunkCiphertext,
      chunkHash,
      nonce: dummyNonce,
      gcmTag: dummyGcmTag,
    });

    expect(serialized.length).toBe(134 + sampleChunkCiphertext.length);

    const parsed = parseBulkEnvelope(serialized);
    expect(parsed.header.formatVersion).toBe(0x02);
    expect(parsed.header.recordType).toBe(0x10);
    expect(parsed.header.globalChunkIndex).toBe(42);
    expect(parsed.header.totalVaultChunks).toBe(100);
    expect(parsed.header.fileChunkIndex).toBe(7);
    expect(parsed.header.totalFileChunks).toBe(15);
    expect(parsed.header.chunkCiphertextLength).toBe(sampleChunkCiphertext.length);

    expect(Array.from(parsed.header.vaultId)).toEqual(Array.from(dummyVaultId));
    expect(Array.from(parsed.header.fileId)).toEqual(Array.from(dummyFileId));
    expect(Array.from(parsed.header.keyId)).toEqual(Array.from(dummyKeyId));
    expect(Array.from(parsed.header.chunkHash)).toEqual(Array.from(chunkHash));
    expect(Array.from(parsed.header.nonce)).toEqual(Array.from(dummyNonce));
    expect(Array.from(parsed.ciphertext)).toEqual(Array.from(sampleChunkCiphertext));
    expect(Array.from(parsed.gcmTag)).toEqual(Array.from(dummyGcmTag));
  });

  test('Fuzzing & Validation: Rejects malformed and truncated buffers', () => {
    // Buffer too short (<134B)
    const shortBuf = new Uint8Array(100);
    expect(validateBulkEnvelope(shortBuf).isValid).toBe(false);

    // Invalid magic
    const chunkHash = computeChunkHash(sampleChunkCiphertext);
    const valid = serializeBulkEnvelope({
      vaultId: dummyVaultId,
      fileId: dummyFileId,
      keyId: dummyKeyId,
      globalChunkIndex: 0,
      totalVaultChunks: 1,
      fileChunkIndex: 0,
      totalFileChunks: 1,
      chunkCiphertext: sampleChunkCiphertext,
      chunkHash,
      nonce: dummyNonce,
      gcmTag: dummyGcmTag,
    });

    const badMagic = new Uint8Array(valid);
    badMagic[0] = 0x58; // 'X'
    expect(validateBulkEnvelope(badMagic).isValid).toBe(false);
    expect(validateBulkEnvelope(badMagic).errorCode).toBe(GhostTagErrorCode.INVALID_ENVELOPE);

    // Invalid version (0x01 instead of 0x02)
    const badVersion = new Uint8Array(valid);
    badVersion[BulkOffsets.FORMAT_VERSION] = 0x01;
    expect(validateBulkEnvelope(badVersion).isValid).toBe(false);
    expect(validateBulkEnvelope(badVersion).errorCode).toBe(GhostTagErrorCode.UNSUPPORTED_VERSION);

    // Out of bound chunk index
    const outOfBounds = new Uint8Array(valid);
    const view = new DataView(outOfBounds.buffer, outOfBounds.byteOffset, outOfBounds.byteLength);
    view.setUint32(BulkOffsets.GLOBAL_CHUNK_INDEX_START, 999, true); // 999 >= totalVaultChunks (1)
    expect(validateBulkEnvelope(outOfBounds).isValid).toBe(false);
    expect(validateBulkEnvelope(outOfBounds).errorCode).toBe(GhostTagErrorCode.CHUNK_INDEX_INVALID);
  });

  test('NDEF framing: Encodes and extracts MIME application/vnd.ghost.bulk', () => {
    const chunkHash = computeChunkHash(sampleChunkCiphertext);
    const serialized = serializeBulkEnvelope({
      vaultId: dummyVaultId,
      fileId: dummyFileId,
      keyId: dummyKeyId,
      globalChunkIndex: 0,
      totalVaultChunks: 1,
      fileChunkIndex: 0,
      totalFileChunks: 1,
      chunkCiphertext: sampleChunkCiphertext,
      chunkHash,
      nonce: dummyNonce,
      gcmTag: dummyGcmTag,
    });

    const ndefRecord = buildBulkGhostTagNdefRecord(serialized);
    expect(ndefRecord.tnf).toBe(2); // MIME_MEDIA

    const extracted = extractBulkGhostTagPayload(ndefRecord);
    expect(extracted.length).toBe(serialized.length);
    expect(Array.from(extracted)).toEqual(Array.from(serialized));
  });
});

