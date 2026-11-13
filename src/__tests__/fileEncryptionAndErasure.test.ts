/**
 * @file fileEncryptionAndErasure.test.ts
 * @summary Unit Tests for Binary File Encryption, Chunking, and Erasure Coding (v2).
 *
 * Verifies arbitrary binary stream encryption (text, images, video, zip),
 * double AES-256-GCM binding, SHA-256 ciphertext hash verification, and
 * Reed-Solomon / Cauchy-Vandermonde GF(2^8) erasure reconstruction.
 */

import { generateSecureRandom } from '../crypto/random';
import {
  encryptFile,
  decryptFile,
  splitCiphertext,
  joinChunks,
} from '../crypto/fileEncryption';
import {
  encodeErasureChunks,
  decodeErasureChunks,
  buildGeneratorMatrix,
  invertMatrix,
  gfAdd,
  gfMul,
  gfInv,
  AvailableChunk,
} from '../crypto/erasureCoding';
import { GhostTagErrorCode } from '../contracts/errors';

describe('File Encryption and Chunking Engine', () => {
  const dek = generateSecureRandom(32);
  const fileId = generateSecureRandom(16);

  test('Arbitrary binary file encryption and decryption round-trip (Text, PDF, Video, Zip)', () => {
    // 1. Text payload
    const textPlaintext = new TextEncoder().encode('Confidential offline recovery note 2026');
    const encText = encryptFile(dek, textPlaintext, fileId);
    expect(encText.fullEncryptedBytes.length).toBe(textPlaintext.length + 28);
    const decText = decryptFile(dek, encText.fullEncryptedBytes, fileId, encText.ciphertextSha256);
    expect(new TextDecoder().decode(decText)).toBe('Confidential offline recovery note 2026');

    // 2. Binary PDF/Video simulation (50 KB)
    const binaryFile = generateSecureRandom(50 * 1024);
    const encBin = encryptFile(dek, binaryFile, fileId);
    const decBin = decryptFile(dek, encBin.fullEncryptedBytes, fileId, encBin.ciphertextSha256);
    expect(Array.from(decBin)).toEqual(Array.from(binaryFile));

    // 3. Zero-length file edge case
    const emptyFile = new Uint8Array(0);
    const encEmpty = encryptFile(dek, emptyFile, fileId);
    const decEmpty = decryptFile(dek, encEmpty.fullEncryptedBytes, fileId, encEmpty.ciphertextSha256);
    expect(decEmpty.length).toBe(0);
  });

  test('Rejects tampered full-file ciphertext with FILE_HASH_MISMATCH', () => {
    const plaintext = new TextEncoder().encode('Tamper test payload');
    const enc = encryptFile(dek, plaintext, fileId);

    const tampered = new Uint8Array(enc.fullEncryptedBytes);
    tampered[tampered.length - 1] ^= 0x01; // flip 1 bit

    expect(() => {
      decryptFile(dek, tampered, fileId, enc.ciphertextSha256);
    }).toThrow(expect.objectContaining({ code: GhostTagErrorCode.FILE_HASH_MISMATCH }));
  });

  test('Chunk splitting and reassembly preserves exact byte sequence', () => {
    const data = generateSecureRandom(1000);
    const chunks = splitCiphertext(data, 120); // 1000 / 120 = 9 chunks
    expect(chunks.length).toBe(9);
    expect(chunks[0].length).toBe(120);
    expect(chunks[8].length).toBe(40); // 1000 - 8*120 = 40

    const rejoined = joinChunks(chunks);
    expect(Array.from(rejoined)).toEqual(Array.from(data));
  });
});

describe('Galois Field GF(2^8) and Erasure Coding Engine', () => {
  test('GF(2^8) arithmetic axioms', () => {
    // Addition is XOR
    expect(gfAdd(5, 5)).toBe(0);
    expect(gfAdd(10, 3)).toBe(10 ^ 3);

    // Multiplication & Inverses
    for (let i = 1; i < 20; i++) {
      const inv = gfInv(i);
      expect(gfMul(i, inv)).toBe(1);
    }
  });

  test('Matrix inversion over GF(2^8)', () => {
    const mat = [
      [1, 2],
      [3, 4],
    ];
    const inv = invertMatrix(mat);

    // Multiply mat * inv: should equal 2x2 Identity matrix
    const prod00 = gfAdd(gfMul(mat[0][0], inv[0][0]), gfMul(mat[0][1], inv[1][0]));
    const prod01 = gfAdd(gfMul(mat[0][0], inv[0][1]), gfMul(mat[0][1], inv[1][1]));
    const prod10 = gfAdd(gfMul(mat[1][0], inv[0][0]), gfMul(mat[1][1], inv[1][0]));
    const prod11 = gfAdd(gfMul(mat[1][0], inv[0][1]), gfMul(mat[1][1], inv[1][1]));

    expect(prod00).toBe(1);
    expect(prod01).toBe(0);
    expect(prod10).toBe(0);
    expect(prod11).toBe(1);
  });

  test('Erasure Coding: Systematic encoding produces K data chunks + M recovery chunks', () => {
    const d0 = new Uint8Array([1, 2, 3, 4]);
    const d1 = new Uint8Array([5, 6, 7, 8]);
    const d2 = new Uint8Array([9, 10, 11, 12]);
    const dataChunks = [d0, d1, d2]; // K = 3

    const encoded = encodeErasureChunks(dataChunks, 2); // M = 2, Total = 5
    expect(encoded.config.dataChunksK).toBe(3);
    expect(encoded.config.recoveryChunksM).toBe(2);
    expect(encoded.config.totalChunks).toBe(5);
    expect(encoded.chunks.length).toBe(5);

    // Systematic property: Chunks 0, 1, 2 match D0, D1, D2
    expect(Array.from(encoded.chunks[0])).toEqual(Array.from(d0));
    expect(Array.from(encoded.chunks[1])).toEqual(Array.from(d1));
    expect(Array.from(encoded.chunks[2])).toEqual(Array.from(d2));
  });

  test('Erasure Coding Recovery: Full reconstruction when 1 data chunk is missing', () => {
    const d0 = new Uint8Array([10, 20, 30, 40]);
    const d1 = new Uint8Array([50, 60, 70, 80]);
    const d2 = new Uint8Array([90, 100, 110, 120]);
    const dataChunks = [d0, d1, d2]; // K = 3

    const encoded = encodeErasureChunks(dataChunks, 1); // K = 3, M = 1 (Total 4)

    // Simulate losing chunk D1 (index 1)
    // Available chunks: index 0 (D0), index 2 (D2), index 3 (Recovery R0)
    const available: AvailableChunk[] = [
      { chunkIndex: 0, data: encoded.chunks[0] },
      { chunkIndex: 2, data: encoded.chunks[2] },
      { chunkIndex: 3, data: encoded.chunks[3] },
    ];

    const reconstructed = decodeErasureChunks(available, 3, 1, encoded.originalLengths);
    expect(reconstructed.length).toBe(3);
    expect(Array.from(reconstructed[0])).toEqual(Array.from(d0));
    expect(Array.from(reconstructed[1])).toEqual(Array.from(d1)); // Successfully recovered D1!
    expect(Array.from(reconstructed[2])).toEqual(Array.from(d2));
  });

  test('Erasure Coding Recovery: Full reconstruction when 2 data chunks are missing (K=4, M=2)', () => {
    const k = 4;
    const m = 2;
    const dataChunks = [
      generateSecureRandom(64),
      generateSecureRandom(64),
      generateSecureRandom(64),
      generateSecureRandom(64),
    ];

    const encoded = encodeErasureChunks(dataChunks, m); // 6 chunks total

    // Simulate losing D0 and D2. Available: D1 (index 1), D3 (index 3), R0 (index 4), R1 (index 5)
    const available: AvailableChunk[] = [
      { chunkIndex: 1, data: encoded.chunks[1] },
      { chunkIndex: 3, data: encoded.chunks[3] },
      { chunkIndex: 4, data: encoded.chunks[4] },
      { chunkIndex: 5, data: encoded.chunks[5] },
    ];

    const reconstructed = decodeErasureChunks(available, k, m, encoded.originalLengths);
    expect(reconstructed.length).toBe(k);
    for (let i = 0; i < k; i++) {
      expect(Array.from(reconstructed[i])).toEqual(Array.from(dataChunks[i]));
    }
  });

  test('Rejects reconstruction when fewer than K chunks are available with INSUFFICIENT_CHUNKS', () => {
    const available: AvailableChunk[] = [
      { chunkIndex: 0, data: new Uint8Array([1, 2]) },
      { chunkIndex: 1, data: new Uint8Array([3, 4]) },
    ];

    expect(() => {
      decodeErasureChunks(available, 3, 1); // Needs 3 chunks, only 2 provided
    }).toThrow(expect.objectContaining({ code: GhostTagErrorCode.INSUFFICIENT_CHUNKS }));
  });
});

