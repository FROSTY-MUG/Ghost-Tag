/**
 * @file erasureCoding.ts
 * @summary Reed-Solomon / Cauchy-Vandermonde Erasure Coding over GF(2^8).
 *
 * Implements systematic (K + M) erasure coding allowing full file reconstruction
 * from any K chunks out of the (K + M) total chunks generated.
 *
 * Mathematical Foundations:
 * - Galois Field GF(2^8) with irreducible polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1).
 * - Generator matrix G is (K + M) x K:
 *   - The top K rows form the K x K identity matrix (systematic property).
 *   - The bottom M rows form a Cauchy matrix where C[i, j] = 1 / (X[i] ^ Y[j]).
 * - Any K x K submatrix of G is strictly non-singular, guaranteeing reconstruction
 *   from any subset of K valid chunks via Gaussian elimination.
 */

import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { ErasureCodingConfig } from '../contracts/bulkVault';

// ---------------------------------------------------------------------------
// Galois Field GF(2^8) Tables & Arithmetic
// ---------------------------------------------------------------------------

const GF_SIZE = 256;
const GF_POLY = 0x11d; // x^8 + x^4 + x^3 + x^2 + 1

const EXP_TABLE = new Uint8Array(GF_SIZE * 2);
const LOG_TABLE = new Uint8Array(GF_SIZE);

// Precompute Log and Exp tables
(function initGF() {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP_TABLE[i] = x;
    EXP_TABLE[i + 255] = x;
    LOG_TABLE[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= GF_POLY;
    }
  }
  LOG_TABLE[0] = 0; // log(0) is mathematically undefined; sentinel
})();

/** Addition in GF(2^8) is bitwise XOR. */
export function gfAdd(a: number, b: number): number {
  return a ^ b;
}

/** Subtraction in GF(2^8) is bitwise XOR (identical to addition). */
export function gfSub(a: number, b: number): number {
  return a ^ b;
}

/** Multiplication in GF(2^8) using lookup tables. */
export function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a] + LOG_TABLE[b]];
}

/** Division in GF(2^8): returns a / b. Throws on division by zero. */
export function gfDiv(a: number, b: number): number {
  if (b === 0) {
    throw new Error('GF(2^8) division by zero');
  }
  if (a === 0) return 0;
  return EXP_TABLE[LOG_TABLE[a] - LOG_TABLE[b] + 255];
}

/** Multiplicative inverse in GF(2^8): returns 1 / a. */
export function gfInv(a: number): number {
  if (a === 0) {
    throw new Error('GF(2^8) inverse of zero');
  }
  return EXP_TABLE[255 - LOG_TABLE[a]];
}

// ---------------------------------------------------------------------------
// Matrix Operations over GF(2^8)
// ---------------------------------------------------------------------------

/**
 * Creates an (rows x cols) matrix initialized with zeros.
 */
function createMatrix(rows: number, cols: number): number[][] {
  const m: number[][] = [];
  for (let i = 0; i < rows; i++) {
    m.push(new Array(cols).fill(0));
  }
  return m;
}

/**
 * Inverts an (N x N) matrix over GF(2^8) using Gaussian elimination.
 * Throws if the matrix is singular.
 */
export function invertMatrix(mat: number[][]): number[][] {
  const n = mat.length;
  // Create augmented matrix [mat | I]
  const aug = createMatrix(n, n * 2);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      aug[i][j] = mat[i][j];
    }
    aug[i][n + i] = 1;
  }

  // Gaussian elimination with partial pivoting
  for (let col = 0; col < n; col++) {
    // Find pivot
    let pivotRow = -1;
    for (let row = col; row < n; row++) {
      if (aug[row][col] !== 0) {
        pivotRow = row;
        break;
      }
    }
    if (pivotRow === -1) {
      throw new GhostTagError({
        code: GhostTagErrorCode.INSUFFICIENT_CHUNKS,
        userMessage: 'Singular matrix encountered during erasure decoding',
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });
    }

    // Swap pivot row if needed
    if (pivotRow !== col) {
      const tmp = aug[col];
      aug[col] = aug[pivotRow];
      aug[pivotRow] = tmp;
    }

    // Scale pivot row so leading coefficient is 1
    const pivotVal = aug[col][col];
    const invPivot = gfInv(pivotVal);
    for (let j = 0; j < n * 2; j++) {
      aug[col][j] = gfMul(aug[col][j], invPivot);
    }

    // Eliminate column in other rows
    for (let row = 0; row < n; row++) {
      if (row !== col) {
        const factor = aug[row][col];
        if (factor !== 0) {
          for (let j = 0; j < n * 2; j++) {
            aug[row][j] = gfSub(aug[row][j], gfMul(factor, aug[col][j]));
          }
        }
      }
    }
  }

  // Extract inverse from right side of augmented matrix
  const inv = createMatrix(n, n);
  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      inv[i][j] = aug[i][n + j];
    }
  }
  return inv;
}

// ---------------------------------------------------------------------------
// Cauchy Generator Matrix
// ---------------------------------------------------------------------------

/**
 * Constructs a systematic Cauchy generator matrix G of dimension (K + M) x K.
 *
 * Rows 0..(K-1) form the K x K identity matrix (systematic data chunks).
 * Rows K..(K+M-1) form the Cauchy matrix:
 *   C[i, j] = 1 / (X[i] ^ Y[j]), where X[i] = K + i, Y[j] = j.
 * Since X and Y are disjoint sets in GF(2^8), X[i] ^ Y[j] != 0 for all i, j.
 */
export function buildGeneratorMatrix(k: number, m: number): number[][] {
  if (k + m > GF_SIZE) {
    throw new GhostTagError({
      code: GhostTagErrorCode.PAYLOAD_TOO_LARGE,
      userMessage: `Total chunks (K+M = ${k + m}) exceeds maximum field size (${GF_SIZE})`,
      category: ErrorCategory.OPERATION,
      severity: ErrorSeverity.ERROR,
    });
  }

  const rows = k + m;
  const g = createMatrix(rows, k);

  // Identity matrix on top K rows
  for (let i = 0; i < k; i++) {
    g[i][i] = 1;
  }

  // Cauchy matrix on bottom M rows
  for (let i = 0; i < m; i++) {
    const x = k + i; // Element from set X
    for (let j = 0; j < k; j++) {
      const y = j;   // Element from set Y
      g[k + i][j] = gfInv(x ^ y);
    }
  }

  return g;
}

// ---------------------------------------------------------------------------
// Encoding & Reconstruction
// ---------------------------------------------------------------------------

export interface EncodedChunks {
  /** Array of (K + M) chunks. Indices 0..K-1 are data, K..K+M-1 are recovery. */
  readonly chunks: Uint8Array[];
  /** Standard uniform chunk length in bytes (padded). */
  readonly chunkLength: number;
  /** Original unpadded length of data before padding. */
  readonly originalLengths: number[];
  readonly config: ErasureCodingConfig;
}

/**
 * Encodes K systematic data chunks into (K + M) chunks.
 *
 * @param dataChunks Array of K data chunk Uint8Arrays.
 * @param recoveryChunksM Number of recovery chunks to generate (M >= 0).
 * @returns All (K + M) chunks ready for tag writing.
 */
export function encodeErasureChunks(
  dataChunks: Uint8Array[],
  recoveryChunksM: number
): EncodedChunks {
  const k = dataChunks.length;
  if (k === 0) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INSUFFICIENT_CHUNKS,
      userMessage: 'Data chunk array cannot be empty',
      category: ErrorCategory.OPERATION,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (recoveryChunksM <= 0) {
    // No erasure coding redundancy requested; return unmodified data chunks
    return {
      chunks: dataChunks,
      chunkLength: dataChunks[0]?.length ?? 0,
      originalLengths: dataChunks.map((c) => c.length),
      config: { dataChunksK: k, recoveryChunksM: 0, totalChunks: k },
    };
  }

  // Determine maximum chunk length and record original lengths
  let maxLen = 0;
  const originalLengths: number[] = [];
  for (const chunk of dataChunks) {
    if (chunk.length > maxLen) maxLen = chunk.length;
    originalLengths.push(chunk.length);
  }

  // Pad all data chunks to uniform maxLen
  const paddedData: Uint8Array[] = dataChunks.map((chunk) => {
    if (chunk.length === maxLen) return chunk;
    const padded = new Uint8Array(maxLen);
    padded.set(chunk, 0);
    return padded;
  });

  const g = buildGeneratorMatrix(k, recoveryChunksM);
  const totalChunks = k + recoveryChunksM;
  const allChunks: Uint8Array[] = new Array(totalChunks);

  // The first K chunks are the systematic data chunks
  for (let i = 0; i < k; i++) {
    allChunks[i] = paddedData[i];
  }

  // Compute the M recovery chunks: R[i] = sum(G[K + i][j] * D[j])
  //
  // Optimization: iterate the Cauchy row coefficients outer and the chunk
  // bytes inner, XOR-ing into the recovery chunk — this avoids re-reading
  // paddedData[j] and re-evaluating gRow[j] per byte, and skips zero
  // coefficients entirely.
  for (let i = 0; i < recoveryChunksM; i++) {
    const recoveryChunk = new Uint8Array(maxLen);
    const gRow = g[k + i];
    for (let j = 0; j < k; j++) {
      const coef = gRow[j];
      if (coef === 0) {
        continue;
      }
      const dataChunk = paddedData[j];
      for (let byteIdx = 0; byteIdx < maxLen; byteIdx++) {
        const val = dataChunk[byteIdx];
        if (val !== 0) {
          recoveryChunk[byteIdx] ^= gfMul(coef, val);
        }
      }
    }
    allChunks[k + i] = recoveryChunk;
  }

  return {
    chunks: allChunks,
    chunkLength: maxLen,
    originalLengths,
    config: {
      dataChunksK: k,
      recoveryChunksM,
      totalChunks,
    },
  };
}

export interface AvailableChunk {
  /** Index in the range [0, K + M - 1]. */
  readonly chunkIndex: number;
  /** Chunk payload bytes. */
  readonly data: Uint8Array;
}

/**
 * Reconstructs the original K systematic data chunks from ANY K available chunks.
 *
 * @param availableChunks Array of at least K valid chunks with their respective chunkIndex.
 * @param k Number of systematic data chunks required (K).
 * @param m Number of recovery chunks configured (M).
 * @param originalLengths Optional array of original chunk lengths before uniform padding.
 * @returns Array of K reconstructed data chunks.
 */
export function decodeErasureChunks(
  availableChunks: AvailableChunk[],
  k: number,
  m: number,
  originalLengths?: readonly number[]
): Uint8Array[] {
  if (availableChunks.length < k) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INSUFFICIENT_CHUNKS,
      userMessage: `Insufficient chunks for reconstruction: have ${availableChunks.length}, need ${k}`,
      category: ErrorCategory.OPERATION,
      severity: ErrorSeverity.ERROR,
    });
  }

  // Sort and deduplicate by chunkIndex
  const sorted = [...availableChunks].sort((a, b) => a.chunkIndex - b.chunkIndex);
  const uniqueChunks: AvailableChunk[] = [];
  const seenIndices = new Set<number>();
  for (const c of sorted) {
    if (!seenIndices.has(c.chunkIndex)) {
      seenIndices.add(c.chunkIndex);
      uniqueChunks.push(c);
    }
  }

  if (uniqueChunks.length < k) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INSUFFICIENT_CHUNKS,
      userMessage: `Insufficient unique chunks: have ${uniqueChunks.length}, need ${k}`,
      category: ErrorCategory.OPERATION,
      severity: ErrorSeverity.ERROR,
    });
  }

  // O(1) chunk lookup index: chunkIndex -> AvailableChunk.
  // Replaces the previous per-lookup O(K) linear scan of uniqueChunks.
  const chunkByIndex = new Map<number, AvailableChunk>();
  for (const c of uniqueChunks) {
    chunkByIndex.set(c.chunkIndex, c);
  }

  // Fast path: if all first K data chunks are already present (systematic chunks 0..K-1)
  let allSystematicPresent = true;
  for (let i = 0; i < k; i++) {
    if (!seenIndices.has(i)) {
      allSystematicPresent = false;
      break;
    }
  }

  if (allSystematicPresent) {
    const result: Uint8Array[] = new Array(k);
    for (let i = 0; i < k; i++) {
      const chunk = chunkByIndex.get(i)!.data;
      if (originalLengths && originalLengths[i] !== undefined) {
        result[i] = chunk.subarray(0, originalLengths[i]);
      } else {
        result[i] = chunk;
      }
    }
    return result;
  }

  // Need reconstruction using erasure decoding: pick first K available unique chunks
  const selected = uniqueChunks.slice(0, k);
  const chunkLen = selected[0].data.length;

  // Build full generator matrix G
  const fullG = buildGeneratorMatrix(k, m);

  // Extract K x K submatrix corresponding to the selected chunk rows
  const subMatrix = createMatrix(k, k);
  for (let i = 0; i < k; i++) {
    const rowIdx = selected[i].chunkIndex;
    for (let j = 0; j < k; j++) {
      subMatrix[i][j] = fullG[rowIdx][j];
    }
  }

  // Invert submatrix
  const invSubMatrix = invertMatrix(subMatrix);

  // Multiply invSubMatrix by selected chunks to recover D[0..K-1]
  const recoveredData: Uint8Array[] = [];
  for (let outIdx = 0; outIdx < k; outIdx++) {
    const row = invSubMatrix[outIdx];
    const recoveredChunk = new Uint8Array(chunkLen);
    for (let byteIdx = 0; byteIdx < chunkLen; byteIdx++) {
      let acc = 0;
      for (let inIdx = 0; inIdx < k; inIdx++) {
        const coef = row[inIdx];
        const val = selected[inIdx].data[byteIdx];
        if (coef !== 0 && val !== 0) {
          acc ^= gfMul(coef, val);
        }
      }
      recoveredChunk[byteIdx] = acc;
    }

    if (originalLengths && originalLengths[outIdx] !== undefined) {
      recoveredData.push(recoveredChunk.subarray(0, originalLengths[outIdx]));
    } else {
      recoveredData.push(recoveredChunk);
    }
  }

  return recoveredData;
}

