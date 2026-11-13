/**
 * @file bulkVault.ts
 * @summary Ghost-Tag Bulk Distributed Vault & Journal Contracts.
 *
 * Defines the schemas for multi-file vault manifests, file records,
 * private local tag-to-chunk mappings, write journals, scan journals,
 * and erasure coding configurations.
 */

import { WrappedDEK } from './keyHierarchy';
import { RecoveryEnvelope } from './recovery';

// ---------------------------------------------------------------------------
// Erasure Coding Configuration
// ---------------------------------------------------------------------------

export interface ErasureCodingConfig {
  /** Number of systematic data chunks (K). */
  readonly dataChunksK: number;
  /** Number of parity / recovery chunks (M) to tolerate lost tags. */
  readonly recoveryChunksM: number;
  /** Total chunks generated = K + M. */
  readonly totalChunks: number;
}

// ---------------------------------------------------------------------------
// Bulk File Record
// ---------------------------------------------------------------------------

export interface BulkFileRecord {
  /** 16-byte binary UUID representing this file. */
  readonly fileId: Uint8Array;
  /** Human-readable original filename (e.g. "report.pdf"). Stored in local manifest ONLY. */
  readonly fileName: string;
  /** MIME type string (e.g. "application/pdf"). Stored in local manifest ONLY. */
  readonly mimeType: string;
  /** Plaintext file size in bytes before encryption. */
  readonly originalSizeBytes: number;
  /** AES-256-GCM ciphertext size in bytes before chunking. */
  readonly ciphertextSizeBytes: number;
  /** Total chunks for this file (data chunks + any recovery chunks). */
  readonly chunkCount: number;
  /** SHA-256 digest of each chunk's ciphertext (32 bytes per chunk). */
  readonly chunkHashes: Uint8Array[];
  /** SHA-256 digest of the complete file ciphertext (32 bytes). */
  readonly ciphertextSha256: Uint8Array;
  /** Erasure coding settings if redundancy was enabled for this file. */
  readonly erasureCoding?: ErasureCodingConfig;
  /** Unix timestamp in milliseconds when file was registered in vault. */
  readonly addedAt: number;
}

// ---------------------------------------------------------------------------
// Private Local Tag Mapping (NEVER written to NFC tag)
// ---------------------------------------------------------------------------

export interface TagMappingRecord {
  /** Physical NFC tag hardware UID (hex string). */
  readonly tagUidHex: string;
  /** Monotonic global chunk index in vault (0 to totalVaultChunks - 1). */
  readonly globalChunkIndex: number;
  /** 16-byte binary UUID of associated file. */
  readonly fileId: Uint8Array;
  /** Monotonic index of chunk within file (0 to totalFileChunks - 1). */
  readonly fileChunkIndex: number;
  /** Unix timestamp in milliseconds when tag was written. */
  readonly writtenAt: number;
}

// ---------------------------------------------------------------------------
// Bulk Vault Manifest
// ---------------------------------------------------------------------------

export interface BulkVaultManifest {
  /** 16-byte binary UUID uniquely identifying this bulk vault. */
  readonly vaultId: Uint8Array;
  /** Format version (2 for bulk scanning). */
  readonly formatVersion: number;
  /** Human-friendly vault name (e.g. "Offline Field Archive"). */
  readonly vaultName: string;
  /** Active wrapped Data Encryption Key (DEK). */
  readonly activeDekWrapped: WrappedDEK;
  /** Argon2id salt used for KEK derivation (32 bytes). */
  readonly kdfSalt: Uint8Array;
  /** Recovery envelope for seed phrase recovery. */
  readonly recoveryEnvelope: RecoveryEnvelope;
  /** Registered files contained in this bulk vault. */
  readonly files: BulkFileRecord[];
  /** Total chunks across all files in vault. */
  readonly totalVaultChunks: number;
  /** Private physical tag mapping (UID -> Chunk). Encrypted at rest in local storage. */
  readonly tagMappings: TagMappingRecord[];
  /** Timestamp created (ms). */
  readonly createdAt: number;
  /** Timestamp last modified (ms). */
  readonly updatedAt: number;
}

// ---------------------------------------------------------------------------
// Write Journal (Interrupted write recovery)
// ---------------------------------------------------------------------------

export type WriteSessionStatus = 'PLANNING' | 'WRITING' | 'COMPLETED' | 'ABORTED';

export interface WriteJournal {
  /** Unique ID for the write session. */
  readonly sessionId: string;
  /** Target vault ID. */
  readonly vaultId: Uint8Array;
  /** Required number of tags needed for all chunks. */
  readonly requiredTagCount: number;
  /** Total tags presented by user initially. */
  readonly presentedTagCount: number;
  /** Number of surplus tags instructed to be set aside. */
  readonly extraTagsExcludedCount: number;
  /** Global chunk indices successfully written and verified so far. */
  readonly completedChunkIndices: number[];
  /** Next global chunk index awaiting write. */
  readonly nextChunkIndex: number;
  /** Hardware UIDs of tags already consumed in this session. */
  readonly writtenTagUids: string[];
  /** Current operational status. */
  readonly status: WriteSessionStatus;
  /** Timestamp session started. */
  readonly startedAt: number;
  /** Timestamp last chunk written. */
  readonly updatedAt: number;
}

// ---------------------------------------------------------------------------
// Scan Journal & Temporary Chunk Cache (72-hour TTL)
// ---------------------------------------------------------------------------

export const CHUNK_CACHE_TTL_MS = 72 * 60 * 60 * 1000; // 72 Hours

export interface CachedChunk {
  /** Global chunk index. */
  readonly globalChunkIndex: number;
  /** 16-byte file UUID. */
  readonly fileId: Uint8Array;
  /** Index of chunk within file. */
  readonly fileChunkIndex: number;
  /** Total chunks for this file. */
  readonly totalFileChunks: number;
  /** Verified chunk ciphertext. */
  readonly ciphertext: Uint8Array;
  /** SHA-256 chunk hash. */
  readonly chunkHash: Uint8Array;
  /** Hardware UID of tag chunk was read from. */
  readonly tagUidHex: string;
  /** Timestamp when chunk was scanned and verified (ms). */
  readonly scannedAt: number;
  /** Expiration timestamp (ms) - automatically purged if now > expiresAt. */
  readonly expiresAt: number;
}

export interface ScanJournal {
  /** Unique ID for the scan session. */
  readonly sessionId: string;
  /** Vault ID being scanned. */
  readonly vaultId: Uint8Array;
  /** Target total chunks required across all files in vault. */
  readonly totalRequiredChunks: number;
  /** Set of global chunk indices already scanned and verified. */
  readonly collectedChunkIndices: number[];
  /** UIDs of physical tags scanned so far. */
  readonly scannedTagUids: string[];
  /** Session start timestamp. */
  readonly startedAt: number;
  /** Hard expiration timestamp for cached chunks. */
  readonly expiresAt: number;
}
