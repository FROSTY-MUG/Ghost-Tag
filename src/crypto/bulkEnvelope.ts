/**
 * @file bulkEnvelope.ts
 * @summary Binary envelope serializer, parser, and validator for Ghost-Tag Bulk Chunks (v2).
 *
 * Implements the 134-byte fixed-overhead binary layout in Little-Endian byte order.
 * Binary Layout:
 * - 00..03   (4B):  MAGIC = 0x47, 0x54, 0x41, 0x47 ("GTAG")
 * - 04       (1B):  FORMAT_VERSION = 0x02
 * - 05       (1B):  RECORD_TYPE = 0x10 (BULK_CHUNK)
 * - 06..21   (16B): VAULT_ID
 * - 22..37   (16B): FILE_ID
 * - 38..53   (16B): KEY_ID
 * - 54..57   (4B):  GLOBAL_CHUNK_INDEX (uint32 LE)
 * - 58..61   (4B):  TOTAL_VAULT_CHUNKS (uint32 LE)
 * - 62..65   (4B):  FILE_CHUNK_INDEX (uint32 LE)
 * - 66..69   (4B):  TOTAL_FILE_CHUNKS (uint32 LE)
 * - 70..73   (4B):  CHUNK_CIPHERTEXT_LENGTH (N, uint32 LE)
 * - 74..105  (32B): CHUNK_HASH (SHA-256)
 * - 106..117 (12B): NONCE (12B IV)
 * - 118..(118+N-1) (N bytes): CHUNK_CIPHERTEXT
 * - (118+N)..(133+N) (16B): GCM_TAG
 */

import QuickCrypto from 'react-native-quick-crypto';
import {
  BULK_ENVELOPE_MAGIC,
  BULK_FORMAT_VERSION_V2,
  RECORD_TYPE_BULK_CHUNK,
  BULK_ENVELOPE_FIXED_OVERHEAD,
  BULK_AAD_LENGTH,
  BULK_ID_LENGTH,
  BULK_HASH_LENGTH,
  BULK_NONCE_LENGTH,
  BULK_GCM_TAG_LENGTH,
  BulkOffsets,
  BulkEnvelopeHeader,
  BulkChunkEnvelope,
  BulkChunkEnvelopeParams,
} from '../contracts/bulkEnvelope';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

/**
 * Result of envelope structural validation.
 */
export interface BulkValidationResult {
  readonly isValid: boolean;
  readonly error?: string;
  readonly errorCode?: GhostTagErrorCode;
}

/**
 * Computes the 32-byte SHA-256 digest of chunk ciphertext bytes.
 */
export function computeChunkHash(chunkCiphertext: Uint8Array): Uint8Array {
  const hash = QuickCrypto.createHash('sha256');
  const buffer = QuickCrypto.Buffer.from(
    chunkCiphertext.buffer as ArrayBuffer,
    chunkCiphertext.byteOffset,
    chunkCiphertext.byteLength
  );
  hash.update(buffer);
  return new Uint8Array(hash.digest());
}

/**
 * Computes the 32-byte SHA-256 digest of complete file ciphertext bytes.
 */
export function computeFileCiphertextHash(fileCiphertext: Uint8Array): Uint8Array {
  const hash = QuickCrypto.createHash('sha256');
  const buffer = QuickCrypto.Buffer.from(
    fileCiphertext.buffer as ArrayBuffer,
    fileCiphertext.byteOffset,
    fileCiphertext.byteLength
  );
  hash.update(buffer);
  return new Uint8Array(hash.digest());
}

/**
 * Constructs the canonical 74-byte Additional Authenticated Data (AAD) for AES-256-GCM.
 *
 * Layout:
 * MAGIC (4B) || FORMAT_VERSION (1B) || RECORD_TYPE (1B) ||
 * VAULT_ID (16B) || FILE_ID (16B) || KEY_ID (16B) ||
 * GLOBAL_CHUNK_INDEX (4B LE) || TOTAL_VAULT_CHUNKS (4B LE) ||
 * FILE_CHUNK_INDEX (4B LE) || TOTAL_FILE_CHUNKS (4B LE) ||
 * CHUNK_CIPHERTEXT_LENGTH (4B LE)
 */
export function constructBulkAAD(
  params:
    | BulkEnvelopeHeader
    | BulkChunkEnvelopeParams
    | {
        vaultId: Uint8Array;
        fileId: Uint8Array;
        keyId: Uint8Array;
        globalChunkIndex: number;
        totalVaultChunks: number;
        fileChunkIndex: number;
        totalFileChunks: number;
        chunkCiphertextLength: number;
      }
): Uint8Array {
  const ctLen =
    'chunkCiphertextLength' in params
      ? params.chunkCiphertextLength
      : params.chunkCiphertext.length;

  if (params.vaultId.length !== BULK_ID_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid vaultId length for AAD: expected ${BULK_ID_LENGTH}B, got ${params.vaultId.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }
  if (params.fileId.length !== BULK_ID_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid fileId length for AAD: expected ${BULK_ID_LENGTH}B, got ${params.fileId.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }
  if (params.keyId.length !== BULK_ID_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid keyId length for AAD: expected ${BULK_ID_LENGTH}B, got ${params.keyId.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const aad = new Uint8Array(BULK_AAD_LENGTH);
  aad.set(BULK_ENVELOPE_MAGIC, BulkOffsets.MAGIC_START);
  aad[BulkOffsets.FORMAT_VERSION] = BULK_FORMAT_VERSION_V2;
  aad[BulkOffsets.RECORD_TYPE] = RECORD_TYPE_BULK_CHUNK;
  aad.set(params.vaultId, BulkOffsets.VAULT_ID_START);
  aad.set(params.fileId, BulkOffsets.FILE_ID_START);
  aad.set(params.keyId, BulkOffsets.KEY_ID_START);

  const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
  view.setUint32(BulkOffsets.GLOBAL_CHUNK_INDEX_START, params.globalChunkIndex, true);
  view.setUint32(BulkOffsets.TOTAL_VAULT_CHUNKS_START, params.totalVaultChunks, true);
  view.setUint32(BulkOffsets.FILE_CHUNK_INDEX_START, params.fileChunkIndex, true);
  view.setUint32(BulkOffsets.TOTAL_FILE_CHUNKS_START, params.totalFileChunks, true);
  view.setUint32(BulkOffsets.CHUNK_CIPHERTEXT_LENGTH_START, ctLen, true);

  return aad;
}

/**
 * Serializes a bulk chunk envelope into a binary Uint8Array.
 * Total size = 134 + params.chunkCiphertext.length bytes.
 */
export function serializeBulkEnvelope(params: BulkChunkEnvelopeParams): Uint8Array {
  const ctLen = params.chunkCiphertext.length;
  const totalLength = BULK_ENVELOPE_FIXED_OVERHEAD + ctLen;

  if (params.vaultId.length !== BULK_ID_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid vaultId length: expected ${BULK_ID_LENGTH}B, got ${params.vaultId.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }
  if (params.fileId.length !== BULK_ID_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid fileId length: expected ${BULK_ID_LENGTH}B, got ${params.fileId.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }
  if (params.keyId.length !== BULK_ID_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid keyId length: expected ${BULK_ID_LENGTH}B, got ${params.keyId.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }
  if (params.chunkHash.length !== BULK_HASH_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid chunkHash length: expected ${BULK_HASH_LENGTH}B, got ${params.chunkHash.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }
  if (params.nonce.length !== BULK_NONCE_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid nonce length: expected ${BULK_NONCE_LENGTH}B, got ${params.nonce.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }
  if (params.gcmTag.length !== BULK_GCM_TAG_LENGTH) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid gcmTag length: expected ${BULK_GCM_TAG_LENGTH}B, got ${params.gcmTag.length}B`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const envelope = new Uint8Array(totalLength);
  envelope.set(BULK_ENVELOPE_MAGIC, BulkOffsets.MAGIC_START);
  envelope[BulkOffsets.FORMAT_VERSION] = BULK_FORMAT_VERSION_V2;
  envelope[BulkOffsets.RECORD_TYPE] = RECORD_TYPE_BULK_CHUNK;
  envelope.set(params.vaultId, BulkOffsets.VAULT_ID_START);
  envelope.set(params.fileId, BulkOffsets.FILE_ID_START);
  envelope.set(params.keyId, BulkOffsets.KEY_ID_START);

  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  view.setUint32(BulkOffsets.GLOBAL_CHUNK_INDEX_START, params.globalChunkIndex, true);
  view.setUint32(BulkOffsets.TOTAL_VAULT_CHUNKS_START, params.totalVaultChunks, true);
  view.setUint32(BulkOffsets.FILE_CHUNK_INDEX_START, params.fileChunkIndex, true);
  view.setUint32(BulkOffsets.TOTAL_FILE_CHUNKS_START, params.totalFileChunks, true);
  view.setUint32(BulkOffsets.CHUNK_CIPHERTEXT_LENGTH_START, ctLen, true);

  envelope.set(params.chunkHash, BulkOffsets.CHUNK_HASH_START);
  envelope.set(params.nonce, BulkOffsets.NONCE_START);
  envelope.set(params.chunkCiphertext, BulkOffsets.CIPHERTEXT_START);
  envelope.set(params.gcmTag, BulkOffsets.CIPHERTEXT_START + ctLen);

  return envelope;
}

/**
 * Validates the binary structure of a bulk envelope without throwing.
 */
export function validateBulkEnvelope(buffer: Uint8Array): BulkValidationResult {
  if (!buffer || buffer.length < BULK_ENVELOPE_FIXED_OVERHEAD) {
    return {
      isValid: false,
      error: `Buffer too short: expected at least ${BULK_ENVELOPE_FIXED_OVERHEAD} bytes, got ${buffer?.length ?? 0}`,
      errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
    };
  }

  // Check magic
  for (let i = 0; i < BULK_ENVELOPE_MAGIC.length; i++) {
    if (buffer[i] !== BULK_ENVELOPE_MAGIC[i]) {
      return {
        isValid: false,
        error: 'Invalid envelope magic header: expected "GTAG"',
        errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
      };
    }
  }

  // Check format version
  if (buffer[BulkOffsets.FORMAT_VERSION] !== BULK_FORMAT_VERSION_V2) {
    return {
      isValid: false,
      error: `Unsupported envelope format version: expected 0x02, got 0x${buffer[BulkOffsets.FORMAT_VERSION].toString(16)}`,
      errorCode: GhostTagErrorCode.UNSUPPORTED_VERSION,
    };
  }

  // Check record type
  if (buffer[BulkOffsets.RECORD_TYPE] !== RECORD_TYPE_BULK_CHUNK) {
    return {
      isValid: false,
      error: `Unsupported record type: expected 0x10 (BULK_CHUNK), got 0x${buffer[BulkOffsets.RECORD_TYPE].toString(16)}`,
      errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
    };
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const globalIndex = view.getUint32(BulkOffsets.GLOBAL_CHUNK_INDEX_START, true);
  const totalVaultChunks = view.getUint32(BulkOffsets.TOTAL_VAULT_CHUNKS_START, true);
  const fileIndex = view.getUint32(BulkOffsets.FILE_CHUNK_INDEX_START, true);
  const totalFileChunks = view.getUint32(BulkOffsets.TOTAL_FILE_CHUNKS_START, true);
  const ctLen = view.getUint32(BulkOffsets.CHUNK_CIPHERTEXT_LENGTH_START, true);

  if (totalVaultChunks === 0 || totalFileChunks === 0) {
    return {
      isValid: false,
      error: 'Total chunks cannot be zero',
      errorCode: GhostTagErrorCode.CHUNK_INDEX_INVALID,
    };
  }

  if (globalIndex >= totalVaultChunks) {
    return {
      isValid: false,
      error: `Global chunk index ${globalIndex} exceeds total vault chunks ${totalVaultChunks}`,
      errorCode: GhostTagErrorCode.CHUNK_INDEX_INVALID,
    };
  }

  if (fileIndex >= totalFileChunks) {
    return {
      isValid: false,
      error: `File chunk index ${fileIndex} exceeds total file chunks ${totalFileChunks}`,
      errorCode: GhostTagErrorCode.CHUNK_INDEX_INVALID,
    };
  }

  if (buffer.length !== BULK_ENVELOPE_FIXED_OVERHEAD + ctLen) {
    return {
      isValid: false,
      error: `Envelope length mismatch: declared ${BULK_ENVELOPE_FIXED_OVERHEAD + ctLen} bytes, actual ${buffer.length} bytes`,
      errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
    };
  }

  return { isValid: true };
}

/**
 * Parses and verifies a raw bulk chunk envelope buffer into structured data.
 */
export function parseBulkEnvelope(buffer: Uint8Array): BulkChunkEnvelope {
  const validation = validateBulkEnvelope(buffer);
  if (!validation.isValid) {
    throw new GhostTagError({
      code: validation.errorCode ?? GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: validation.error ?? 'Failed to parse bulk chunk envelope',
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  const globalIndex = view.getUint32(BulkOffsets.GLOBAL_CHUNK_INDEX_START, true);
  const totalVaultChunks = view.getUint32(BulkOffsets.TOTAL_VAULT_CHUNKS_START, true);
  const fileIndex = view.getUint32(BulkOffsets.FILE_CHUNK_INDEX_START, true);
  const totalFileChunks = view.getUint32(BulkOffsets.TOTAL_FILE_CHUNKS_START, true);
  const ctLen = view.getUint32(BulkOffsets.CHUNK_CIPHERTEXT_LENGTH_START, true);

  const header: BulkEnvelopeHeader = {
    magic: buffer.slice(BulkOffsets.MAGIC_START, BulkOffsets.MAGIC_END),
    formatVersion: buffer[BulkOffsets.FORMAT_VERSION],
    recordType: buffer[BulkOffsets.RECORD_TYPE],
    vaultId: buffer.slice(BulkOffsets.VAULT_ID_START, BulkOffsets.VAULT_ID_END),
    fileId: buffer.slice(BulkOffsets.FILE_ID_START, BulkOffsets.FILE_ID_END),
    keyId: buffer.slice(BulkOffsets.KEY_ID_START, BulkOffsets.KEY_ID_END),
    globalChunkIndex: globalIndex,
    totalVaultChunks: totalVaultChunks,
    fileChunkIndex: fileIndex,
    totalFileChunks: totalFileChunks,
    chunkCiphertextLength: ctLen,
    chunkHash: buffer.slice(BulkOffsets.CHUNK_HASH_START, BulkOffsets.CHUNK_HASH_END),
    nonce: buffer.slice(BulkOffsets.NONCE_START, BulkOffsets.NONCE_END),
  };

  const ciphertextStart = BulkOffsets.CIPHERTEXT_START;
  const ciphertextEnd = ciphertextStart + ctLen;
  const ciphertext = buffer.slice(ciphertextStart, ciphertextEnd);
  const gcmTag = buffer.slice(ciphertextEnd, ciphertextEnd + BULK_GCM_TAG_LENGTH);

  return {
    header,
    ciphertext,
    gcmTag,
  };
}

