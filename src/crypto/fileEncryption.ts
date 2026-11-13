/**
 * @file fileEncryption.ts
 * @summary Arbitrary Binary File Encryption, Chunking, and Reassembly Engine.
 *
 * Provides end-to-end file encryption using AES-256-GCM, chunk splitting,
 * chunk reassembly, and full-file verification.
 *
 * Security Guarantees:
 * - Opaque Binary Handling: Treats every file (images, videos, PDFs, zip, etc.)
 *   as an unparsed binary stream.
 * - Double Cryptographic Binding:
 *   1. File-level AES-256-GCM encryption with complete ciphertext SHA-256 digest.
 *   2. Per-chunk envelope AES-256-GCM encryption with 74-byte AAD binding vault,
 *      file, and index coordinates.
 */

import QuickCrypto from 'react-native-quick-crypto';
import { encrypt, decrypt } from './aesGcm';
import { generateNonce } from './random';
import { computeChunkHash, computeFileCiphertextHash } from './bulkEnvelope';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

/**
 * Result of full file encryption before chunking.
 */
export interface EncryptedFilePackage {
  /** Combined self-contained encrypted payload (fileNonce [12B] || fileGcmTag [16B] || ciphertext). */
  readonly fullEncryptedBytes: Uint8Array;
  /** 32-byte SHA-256 digest of fullEncryptedBytes. */
  readonly ciphertextSha256: Uint8Array;
  /** Original file size in bytes before encryption. */
  readonly originalSizeBytes: number;
  /** Total encrypted byte size (originalSizeBytes + 28B). */
  readonly encryptedSizeBytes: number;
}

/**
 * Encrypts an arbitrary binary file using AES-256-GCM with the vault DEK.
 *
 * @param dek 32-byte Data Encryption Key.
 * @param fileBytes Raw binary file contents.
 * @param fileId Optional 16-byte file identifier used as AAD binding.
 * @returns Self-contained encrypted file package and SHA-256 digest.
 */
export function encryptFile(
  dek: Uint8Array,
  fileBytes: Uint8Array,
  fileId?: Uint8Array
): EncryptedFilePackage {
  const aad = fileId ?? new Uint8Array(0);
  const { ciphertext, nonce, tag } = encrypt(dek, fileBytes, aad);

  // Self-contained package layout: NONCE (12B) || GCM_TAG (16B) || CIPHERTEXT (varies)
  const fullBytes = new Uint8Array(nonce.length + tag.length + ciphertext.length);
  fullBytes.set(nonce, 0);
  fullBytes.set(tag, nonce.length);
  fullBytes.set(ciphertext, nonce.length + tag.length);

  const ciphertextSha256 = computeFileCiphertextHash(fullBytes);

  return {
    fullEncryptedBytes: fullBytes,
    ciphertextSha256,
    originalSizeBytes: fileBytes.length,
    encryptedSizeBytes: fullBytes.length,
  };
}

/**
 * Decrypts a full self-contained encrypted file package using AES-256-GCM and the vault DEK.
 *
 * @param dek 32-byte Data Encryption Key.
 * @param fullEncryptedBytes Combined encrypted bytes (fileNonce [12B] || fileGcmTag [16B] || ciphertext).
 * @param fileId Optional 16-byte file identifier used as AAD binding.
 * @param expectedSha256 Optional expected SHA-256 digest to verify integrity before decryption.
 * @returns Original decrypted plaintext bytes.
 */
export function decryptFile(
  dek: Uint8Array,
  fullEncryptedBytes: Uint8Array,
  fileId?: Uint8Array,
  expectedSha256?: Uint8Array
): Uint8Array {
  if (fullEncryptedBytes.length < 28) {
    throw new GhostTagError({
      code: GhostTagErrorCode.CHUNK_CORRUPT,
      userMessage: 'Encrypted file package is too small to contain nonce and auth tag',
      category: ErrorCategory.CRYPTO,
      severity: ErrorSeverity.ERROR,
    });
  }

  // Verify SHA-256 hash if expected digest provided
  if (expectedSha256) {
    const actualSha256 = computeFileCiphertextHash(fullEncryptedBytes);
    let matches = true;
    if (actualSha256.length !== expectedSha256.length) {
      matches = false;
    } else {
      for (let i = 0; i < actualSha256.length; i++) {
        if (actualSha256[i] !== expectedSha256[i]) {
          matches = false;
          break;
        }
      }
    }

    if (!matches) {
      throw new GhostTagError({
        code: GhostTagErrorCode.FILE_HASH_MISMATCH,
        userMessage: 'File ciphertext SHA-256 hash mismatch: file corrupted or modified',
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }
  }

  const nonce = fullEncryptedBytes.subarray(0, 12);
  const tag = fullEncryptedBytes.subarray(12, 28);
  const ciphertext = fullEncryptedBytes.subarray(28);
  const aad = fileId ?? new Uint8Array(0);

  return decrypt(dek, ciphertext, nonce, tag, aad);
}

/**
 * Splits a full ciphertext byte stream into sequential chunks of at most chunkSize bytes.
 *
 * @param fullBytes Full ciphertext bytes to split.
 * @param chunkSize Maximum byte size per chunk (determined by tag capacity - 134B overhead).
 * @returns Array of chunk Uint8Arrays.
 */
export function splitCiphertext(fullBytes: Uint8Array, chunkSize: number): Uint8Array[] {
  if (chunkSize <= 0) {
    throw new GhostTagError({
      code: GhostTagErrorCode.TAG_CAPACITY_INSUFFICIENT,
      userMessage: `Chunk size must be greater than zero, got ${chunkSize}`,
      category: ErrorCategory.OPERATION,
      severity: ErrorSeverity.ERROR,
    });
  }

  const chunks: Uint8Array[] = [];
  let offset = 0;
  while (offset < fullBytes.length) {
    const end = Math.min(offset + chunkSize, fullBytes.length);
    chunks.push(fullBytes.slice(offset, end));
    offset = end;
  }

  // Handle 0-byte file edge case
  if (chunks.length === 0) {
    chunks.push(new Uint8Array(0));
  }

  return chunks;
}

/**
 * Concatenates sequential data chunks into a continuous full ciphertext byte stream.
 *
 * @param chunks Array of sequential data chunks (indices 0..K-1).
 * @returns Continuous Uint8Array.
 */
export function joinChunks(chunks: Uint8Array[]): Uint8Array {
  let totalLength = 0;
  for (const chunk of chunks) {
    totalLength += chunk.length;
  }

  const joined = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    joined.set(chunk, offset);
    offset += chunk.length;
  }

  return joined;
}
