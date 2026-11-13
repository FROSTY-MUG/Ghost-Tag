/**
 * @file tags.ts
 * @summary Ghost-Tag NFC Tag Hardware Matrix and Capacity Specification.
 *
 * Defines supported NFC Forum Type 2 Tag families, exact user memory capacities,
 * usable NDEF message capacities, and tag metadata interfaces.
 *
 * Memory & Capacity Notes:
 * - NFC Forum Type 2 Tags organize memory in 4-byte pages.
 * - Usable NDEF capacity = Total User Memory minus Type 2 NDEF TLV container overhead.
 * - Fixed envelope overhead is 54 bytes (ENVELOPE_FIXED_OVERHEAD_BYTES).
 * - Plaintext Payload Capacity = Usable NDEF Capacity minus 54 bytes.
 */

import { ENVELOPE_FIXED_OVERHEAD_BYTES } from './envelope';

// ---------------------------------------------------------------------------
// Supported Tag Families
// ---------------------------------------------------------------------------

/**
 * NFC Forum Type 2 Tag families officially supported by Ghost-Tag.
 */
export enum SupportedTagFamily {
  /** NXP NTAG213: 144 bytes user memory (36 pages x 4B). */
  NTAG213 = 'NTAG213',
  /** NXP NTAG215: 504 bytes user memory (126 pages x 4B). */
  NTAG215 = 'NTAG215',
  /** NXP NTAG216: 888 bytes user memory (222 pages x 4B). */
  NTAG216 = 'NTAG216',
  /** NXP MIFARE Ultralight (MF0ICU1): 48 bytes user memory (12 pages x 4B). */
  MIFARE_ULTRALIGHT = 'MIFARE_ULTRALIGHT',
  /** NXP MIFARE Ultralight C: 144 bytes user memory (36 pages x 4B). */
  MIFARE_ULTRALIGHT_C = 'MIFARE_ULTRALIGHT_C',
  /** NXP MIFARE Ultralight EV1 (MF0UL21): 128 bytes user memory (32 pages x 4B). */
  MIFARE_ULTRALIGHT_EV1 = 'MIFARE_ULTRALIGHT_EV1',
}

// ---------------------------------------------------------------------------
// Unsupported Tag Families
// ---------------------------------------------------------------------------

/**
 * Non-supported tag hardware architectures.
 *
 * Rationale:
 * - MIFARE Classic uses proprietary, broken Crypto-1 cipher and non-standard framing.
 * - MIFARE DESFire uses Type 4 framing not aligned with Type 2 lightweight envelopes.
 * - FeliCa / ISO 15693 (Type V) use incompatible command sets and RF protocols.
 */
export enum UnsupportedTagFamily {
  MIFARE_CLASSIC_1K = 'MIFARE_CLASSIC_1K',
  MIFARE_CLASSIC_4K = 'MIFARE_CLASSIC_4K',
  MIFARE_DESFIRE = 'MIFARE_DESFIRE',
  FELICA = 'FELICA',
  ISO15693 = 'ISO15693',
  TOPAZ_512 = 'TOPAZ_512',
  ICODE_SLIX = 'ICODE_SLIX',
}

// ---------------------------------------------------------------------------
// Tag Capacity Definitions
// ---------------------------------------------------------------------------

/**
 * Memory specifications for a supported tag family.
 */
export interface TagMemoryProfile {
  /** Tag family identifier. */
  readonly family: SupportedTagFamily;
  /** Total raw user memory area in bytes (excluding UID, lock bits, OTP). */
  readonly rawUserMemoryBytes: number;
  /** Exact maximum usable NDEF payload in bytes after standard TLV framing. */
  readonly usableNdefBytes: number;
  /**
   * Maximum encrypted payload size in bytes after deducting 54 bytes envelope overhead.
   * If negative, the tag cannot hold a Ghost-Tag envelope.
   */
  readonly maxPlaintextPayloadBytes: number;
  /** Typical page count in user memory area (4 bytes per page). */
  readonly userPages: number;
}

/**
 * Canonical capacity map per supported tag type.
 *
 * Security & Sizing Notes:
 * - NTAG213: 137 usable NDEF bytes - 54B overhead = 83 bytes maximum plaintext.
 * - NTAG215: 492 usable NDEF bytes - 54B overhead = 438 bytes maximum plaintext.
 * - NTAG216: 872 usable NDEF bytes - 54B overhead = 818 bytes maximum plaintext.
 * - MIFARE_ULTRALIGHT: 46 usable NDEF bytes - 54B overhead = -8 bytes (CANNOT fit envelope;
 *   triggers TAG_CAPACITY_INSUFFICIENT).
 * - MIFARE_ULTRALIGHT_C: 137 usable NDEF bytes - 54B overhead = 83 bytes maximum plaintext.
 * - MIFARE_ULTRALIGHT_EV1: 120 usable NDEF bytes (MF0UL21) - 54B overhead = 66 bytes maximum plaintext.
 */
export const TAG_CAPACITIES: Readonly<Record<SupportedTagFamily, TagMemoryProfile>> = {
  [SupportedTagFamily.NTAG213]: {
    family: SupportedTagFamily.NTAG213,
    rawUserMemoryBytes: 144,
    usableNdefBytes: 137,
    maxPlaintextPayloadBytes: 137 - ENVELOPE_FIXED_OVERHEAD_BYTES, // 83 bytes
    userPages: 36,
  },
  [SupportedTagFamily.NTAG215]: {
    family: SupportedTagFamily.NTAG215,
    rawUserMemoryBytes: 504,
    usableNdefBytes: 492,
    maxPlaintextPayloadBytes: 492 - ENVELOPE_FIXED_OVERHEAD_BYTES, // 438 bytes
    userPages: 126,
  },
  [SupportedTagFamily.NTAG216]: {
    family: SupportedTagFamily.NTAG216,
    rawUserMemoryBytes: 888,
    usableNdefBytes: 872,
    maxPlaintextPayloadBytes: 872 - ENVELOPE_FIXED_OVERHEAD_BYTES, // 818 bytes
    userPages: 222,
  },
  [SupportedTagFamily.MIFARE_ULTRALIGHT]: {
    family: SupportedTagFamily.MIFARE_ULTRALIGHT,
    rawUserMemoryBytes: 48,
    usableNdefBytes: 46,
    maxPlaintextPayloadBytes: 46 - ENVELOPE_FIXED_OVERHEAD_BYTES, // -8 (insufficient)
    userPages: 12,
  },
  [SupportedTagFamily.MIFARE_ULTRALIGHT_C]: {
    family: SupportedTagFamily.MIFARE_ULTRALIGHT_C,
    rawUserMemoryBytes: 144,
    usableNdefBytes: 137,
    maxPlaintextPayloadBytes: 137 - ENVELOPE_FIXED_OVERHEAD_BYTES, // 83 bytes
    userPages: 36,
  },
  [SupportedTagFamily.MIFARE_ULTRALIGHT_EV1]: {
    family: SupportedTagFamily.MIFARE_ULTRALIGHT_EV1,
    rawUserMemoryBytes: 128,
    usableNdefBytes: 120,
    maxPlaintextPayloadBytes: 120 - ENVELOPE_FIXED_OVERHEAD_BYTES, // 66 bytes
    userPages: 32,
  },
} as const;

// ---------------------------------------------------------------------------
// Tag Information Interface
// ---------------------------------------------------------------------------

/**
 * Diagnostic and physical properties of a detected NFC tag.
 *
 * Security Properties:
 * - `uid` is treated as sensitive telemetry to prevent cross-location user tracking.
 * - Hardware lock statuses (`isReadOnly`, `isLocked`) must be verified before attempting writes
 *   to avoid half-write or bricking risks.
 */
export interface TagInfo {
  /** Detected tag family. */
  readonly family: SupportedTagFamily;

  /** Total usable NDEF capacity in bytes. */
  readonly capacity: number;

  /** Whether the tag currently contains valid NDEF formatting. */
  readonly isNdefFormatted: boolean;

  /** Whether hardware static/dynamic lock bits are permanently engaged. */
  readonly isReadOnly: boolean;

  /** Whether password or authentication protection is currently locked. */
  readonly isLocked: boolean;

  /** Length of the hardware Unique Identifier (typically 7 bytes for Type 2). */
  readonly uidLength: number;

  /** Hardware UID (hex string or raw bytes). */
  readonly uid?: string | Uint8Array;
}

// ---------------------------------------------------------------------------
// Capacity Calculation Helper Signatures
// ---------------------------------------------------------------------------

/**
 * Calculates maximum allowable plaintext payload size for a given tag family.
 */
export type CalculateMaxPayloadBytes = (family: SupportedTagFamily) => number;

/**
 * Assesses whether a plaintext payload can fit onto a tag family inside a Ghost-Tag envelope.
 */
export type CanFitEnvelope = (
  family: SupportedTagFamily,
  plaintextLengthBytes: number
) => boolean;
