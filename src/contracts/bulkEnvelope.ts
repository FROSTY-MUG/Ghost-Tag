/**
 * @file bulkEnvelope.ts
 * @summary Ghost-Tag Bulk Chunk Binary Envelope Specification (v2).
 *
 * Defines the wire format, binary offsets, fixed overhead constants, and data
 * structures for storing distributed encrypted file chunks on standard NFC tags.
 *
 * Binary Layout (134-byte fixed overhead, Little-Endian integers):
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
 * - 74..105  (32B): CHUNK_HASH (SHA-256 of chunk ciphertext)
 * - 106..117 (12B): NONCE (AES-256-GCM IV)
 * - 118..(118+N-1) (N bytes): CHUNK_CIPHERTEXT
 * - (118+N)..(133+N) (16B): GCM_TAG
 *
 * Total fixed overhead: 134 bytes.
 * Authenticated Additional Data (AAD): Bytes 0..73 (74 bytes total).
 */

// ---------------------------------------------------------------------------
// Constants & Offsets
// ---------------------------------------------------------------------------

/** Four-byte ASCII magic identifier for Ghost-Tag binary envelopes: "GTAG" */
export const BULK_ENVELOPE_MAGIC = new Uint8Array([0x47, 0x54, 0x41, 0x47]);

/** Format version 2 for Bulk Distributed File Vault. */
export const BULK_FORMAT_VERSION_V2 = 0x02;

/** Record type identifier for distributed bulk chunks. */
export const RECORD_TYPE_BULK_CHUNK = 0x10;

/** NDEF MIME record type for Ghost-Tag bulk chunks. */
export const BULK_ENVELOPE_MIME_TYPE = 'application/vnd.ghost.bulk';

/** Total fixed binary overhead before payload ciphertext: 134 bytes. */
export const BULK_ENVELOPE_FIXED_OVERHEAD = 134;

/** Exact byte length of the Authenticated Additional Data (AAD) block: 74 bytes. */
export const BULK_AAD_LENGTH = 74;

/** Byte length of 128-bit UUID fields (VAULT_ID, FILE_ID, KEY_ID): 16 bytes. */
export const BULK_ID_LENGTH = 16;

/** Byte length of SHA-256 chunk digest: 32 bytes. */
export const BULK_HASH_LENGTH = 32;

/** Byte length of AES-GCM standard initialization vector: 12 bytes. */
export const BULK_NONCE_LENGTH = 12;

/** Byte length of AES-GCM authentication tag: 16 bytes. */
export const BULK_GCM_TAG_LENGTH = 16;

/**
 * Byte offset definitions for zero-copy parsing and slicing.
 */
export const BulkOffsets = {
  MAGIC_START: 0,
  MAGIC_END: 4,
  FORMAT_VERSION: 4,
  RECORD_TYPE: 5,
  VAULT_ID_START: 6,
  VAULT_ID_END: 22,
  FILE_ID_START: 22,
  FILE_ID_END: 38,
  KEY_ID_START: 38,
  KEY_ID_END: 54,
  GLOBAL_CHUNK_INDEX_START: 54,
  GLOBAL_CHUNK_INDEX_END: 58,
  TOTAL_VAULT_CHUNKS_START: 58,
  TOTAL_VAULT_CHUNKS_END: 62,
  FILE_CHUNK_INDEX_START: 62,
  FILE_CHUNK_INDEX_END: 66,
  TOTAL_FILE_CHUNKS_START: 66,
  TOTAL_FILE_CHUNKS_END: 70,
  CHUNK_CIPHERTEXT_LENGTH_START: 70,
  CHUNK_CIPHERTEXT_LENGTH_END: 74,
  CHUNK_HASH_START: 74,
  CHUNK_HASH_END: 106,
  NONCE_START: 106,
  NONCE_END: 118,
  CIPHERTEXT_START: 118,
} as const;

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * Header metadata extracted from a bulk chunk binary envelope.
 */
export interface BulkEnvelopeHeader {
  readonly magic: Uint8Array;
  readonly formatVersion: number;
  readonly recordType: number;
  readonly vaultId: Uint8Array; // 16 bytes
  readonly fileId: Uint8Array;  // 16 bytes
  readonly keyId: Uint8Array;   // 16 bytes
  readonly globalChunkIndex: number;
  readonly totalVaultChunks: number;
  readonly fileChunkIndex: number;
  readonly totalFileChunks: number;
  readonly chunkCiphertextLength: number;
  readonly chunkHash: Uint8Array; // 32 bytes SHA-256
  readonly nonce: Uint8Array;     // 12 bytes IV
}

/**
 * Complete deserialized bulk chunk envelope representation.
 */
export interface BulkChunkEnvelope {
  readonly header: BulkEnvelopeHeader;
  readonly ciphertext: Uint8Array;
  readonly gcmTag: Uint8Array;    // 16 bytes
}

/**
 * Raw input parameters required to construct and serialize a bulk chunk envelope.
 */
export interface BulkChunkEnvelopeParams {
  readonly vaultId: Uint8Array;
  readonly fileId: Uint8Array;
  readonly keyId: Uint8Array;
  readonly globalChunkIndex: number;
  readonly totalVaultChunks: number;
  readonly fileChunkIndex: number;
  readonly totalFileChunks: number;
  readonly chunkCiphertext: Uint8Array;
  readonly chunkHash: Uint8Array;
  readonly nonce: Uint8Array;
  readonly gcmTag: Uint8Array;
}
