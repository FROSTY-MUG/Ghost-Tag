/**
 * @file tagInfo.ts
 * @summary NFC Tag Hardware Identification, Capacity Analysis, and Compatibility Checking.
 *
 * Provides inspection of detected NFC tags against the Ghost-Tag hardware support matrix,
 * calculating physical memory, NDEF TLV overhead, MIME framing overhead, and maximum
 * usable plaintext capacity.
 */

import { TagEvent } from 'react-native-nfc-manager';
import {
  SupportedTagFamily,
  UnsupportedTagFamily,
  TAG_CAPACITIES,
  TagInfo as ContractTagInfo,
} from '../contracts/tags';
import {
  ENVELOPE_FIXED_OVERHEAD_BYTES,
  ENVELOPE_MIME_TYPE,
} from '../contracts/envelope';

/**
 * Standard alias for react-native-nfc-manager TagEvent across the Ghost-Tag NFC module.
 */
export type NfcTag = TagEvent;

/**
 * Detailed hardware identification result for a scanned tag.
 */
export interface TagIdentification {
  /** The identified tag hardware family. */
  readonly family: SupportedTagFamily | UnsupportedTagFamily | 'UNKNOWN';
  /** Whether this tag family is officially supported by Ghost-Tag. */
  readonly isSupported: boolean;
  /** Total user EEPROM memory capacity in bytes. */
  readonly rawUserMemoryBytes: number;
  /** Number of 4-byte user memory pages available on this tag. */
  readonly userPages: number;
  /** Hardware Unique Identifier (UID) as hex string, if available. */
  readonly uid?: string;
  /** Answer To Request - Type A (ATQA) discovery bytes. */
  readonly atqa?: number[];
  /** Select Acknowledge (SAK) discovery byte. */
  readonly sak?: number;
  /** NFC technologies supported by this tag reported by the host operating system. */
  readonly techTypes: string[];
}

/**
 * Granular memory and overhead breakdown for a tag.
 */
export interface TagCapacity {
  /** Tag family detected. */
  readonly family: SupportedTagFamily | 'UNKNOWN';
  /** Total physical user memory on chip (excluding UID, lock bits, OTP). */
  readonly rawUserMemoryBytes: number;
  /** Usable NDEF payload area after standard TLV framing. */
  readonly usableNdefBytes: number;
  /** NFC Forum Type 2 NDEF TLV container overhead in bytes (0x03 len ... 0xFE). */
  readonly ndefTlvOverheadBytes: number;
  /** NDEF MIME record header and type framing overhead ("application/vnd.ghost.secure"). */
  readonly mimeRecordOverheadBytes: number;
  /** Fixed Ghost-Tag binary envelope overhead (54 bytes: header + GCM auth tag). */
  readonly envelopeOverheadBytes: number;
  /** Total cumulative overhead subtracted from raw tag user capacity. */
  readonly totalOverheadBytes: number;
  /** Theoretical maximum plaintext payload bytes. May be negative for undersized tags. */
  readonly maxPlaintextBytes: number;
  /** Available plaintext capacity in bytes (clamped to 0 if payload cannot fit). */
  readonly availablePlaintextBytes: number;
}

/**
 * Type 2 Tag MIME record header length:
 * Flag byte (1B) + Type Length (1B) + Type string (28B) + Payload Length (1B for short record, 4B for long).
 */
const MIME_TYPE_LENGTH = ENVELOPE_MIME_TYPE.length; // 28 bytes
const SHORT_RECORD_MIME_OVERHEAD = 1 + 1 + 1 + MIME_TYPE_LENGTH; // 31 bytes
const LONG_RECORD_MIME_OVERHEAD = 1 + 1 + 4 + MIME_TYPE_LENGTH; // 34 bytes

const BULK_MIME_TYPE_LENGTH = 26; // 'application/vnd.ghost.bulk'.length
const SHORT_BULK_MIME_OVERHEAD = 1 + 1 + 1 + BULK_MIME_TYPE_LENGTH; // 29 bytes
const LONG_BULK_MIME_OVERHEAD = 1 + 1 + 4 + BULK_MIME_TYPE_LENGTH; // 32 bytes
const BULK_ENVELOPE_OVERHEAD = 134;

/**
 * Bulk Tag capacity calculation breakdown.
 */
export interface BulkTagCapacity {
  readonly family: SupportedTagFamily | 'UNKNOWN';
  readonly rawUserMemoryBytes: number;
  readonly usableNdefBytes: number;
  readonly ndefTlvOverheadBytes: number;
  readonly mimeRecordOverheadBytes: number;
  readonly bulkEnvelopeOverheadBytes: number;
  readonly totalOverheadBytes: number;
  readonly maxChunkBytes: number;
  readonly usableChunkBytes: number;
}

/**
 * Service class for identifying NFC tags and calculating exact capacity limits.
 */
export class TagInfo {
  /**
   * Identifies the tag hardware family, UID, and Type 2 compliance from tag discovery telemetry.
   *
   * @param tag The detected NFC tag event.
   * @returns TagIdentification detailing family, support status, and page structure.
   */
  public identifyTag(tag: NfcTag): TagIdentification {
    const techTypes = tag.techTypes ?? [];
    const sak = tag.sak;
    const maxSize = tag.maxSize ?? 0;
    const typeStr = (tag.type ?? '').toUpperCase();
    const uid = tag.id;
    const atqa = tag.atqa;

    // Check for known unsupported tag technologies
    if (
      techTypes.some((t) => t.toLowerCase().includes('mifareclassic')) ||
      sak === 0x08 ||
      sak === 0x18
    ) {
      return {
        family: sak === 0x18 ? UnsupportedTagFamily.MIFARE_CLASSIC_4K : UnsupportedTagFamily.MIFARE_CLASSIC_1K,
        isSupported: false,
        rawUserMemoryBytes: sak === 0x18 ? 4096 : 1024,
        userPages: sak === 0x18 ? 256 : 64,
        uid,
        atqa,
        sak,
        techTypes,
      };
    }

    if (
      (techTypes.some((t) => t.toLowerCase().includes('isodep')) &&
        !techTypes.some((t) => t.toLowerCase().includes('mifareultralight'))) ||
      sak === 0x20
    ) {
      return {
        family: UnsupportedTagFamily.MIFARE_DESFIRE,
        isSupported: false,
        rawUserMemoryBytes: 0,
        userPages: 0,
        uid,
        atqa,
        sak,
        techTypes,
      };
    }

    if (techTypes.some((t) => t.toLowerCase().includes('nfcf'))) {
      return {
        family: UnsupportedTagFamily.FELICA,
        isSupported: false,
        rawUserMemoryBytes: 0,
        userPages: 0,
        uid,
        atqa,
        sak,
        techTypes,
      };
    }

    if (techTypes.some((t) => t.toLowerCase().includes('nfcv') || t.toLowerCase().includes('iso15693'))) {
      return {
        family: UnsupportedTagFamily.ISO15693,
        isSupported: false,
        rawUserMemoryBytes: 0,
        userPages: 0,
        uid,
        atqa,
        sak,
        techTypes,
      };
    }

    // Match Supported Type 2 Tag Families by chip type string or reported maxSize
    let resolvedFamily: SupportedTagFamily | null = null;

    if (typeStr.includes('216') || maxSize >= 800) {
      resolvedFamily = SupportedTagFamily.NTAG216;
    } else if (typeStr.includes('215') || (maxSize >= 450 && maxSize < 800)) {
      resolvedFamily = SupportedTagFamily.NTAG215;
    } else if (typeStr.includes('213')) {
      resolvedFamily = SupportedTagFamily.NTAG213;
    } else if (typeStr.includes('EV1') || (maxSize >= 100 && maxSize <= 130)) {
      resolvedFamily = SupportedTagFamily.MIFARE_ULTRALIGHT_EV1;
    } else if (typeStr.includes('ULTRALIGHT C') || typeStr.includes('TYPE C')) {
      resolvedFamily = SupportedTagFamily.MIFARE_ULTRALIGHT_C;
    } else if (maxSize > 0 && maxSize < 100) {
      resolvedFamily = SupportedTagFamily.MIFARE_ULTRALIGHT;
    } else if (maxSize >= 130 && maxSize < 450) {
      resolvedFamily = SupportedTagFamily.NTAG213;
    }

    if (resolvedFamily) {
      const profile = TAG_CAPACITIES[resolvedFamily];
      return {
        family: resolvedFamily,
        isSupported: true,
        rawUserMemoryBytes: profile.rawUserMemoryBytes,
        userPages: profile.userPages,
        uid,
        atqa,
        sak,
        techTypes,
      };
    }

    // Check if tag at least reports NfcA or MifareUltralight or Ndef
    const isGenericType2 = techTypes.some(
      (t) =>
        t.toLowerCase().includes('mifareultralight') ||
        t.toLowerCase().includes('nfca') ||
        t.toLowerCase().includes('ndef')
    );

    if (isGenericType2) {
      // Default to NTAG213 baseline for generic Type 2 tags
      const defaultProfile = TAG_CAPACITIES[SupportedTagFamily.NTAG213];
      return {
        family: SupportedTagFamily.NTAG213,
        isSupported: true,
        rawUserMemoryBytes: defaultProfile.rawUserMemoryBytes,
        userPages: defaultProfile.userPages,
        uid,
        atqa,
        sak,
        techTypes,
      };
    }

    return {
      family: 'UNKNOWN',
      isSupported: false,
      rawUserMemoryBytes: 0,
      userPages: 0,
      uid,
      atqa,
      sak,
      techTypes,
    };
  }

  /**
   * Calculates comprehensive capacity breakdown including physical memory, TLV framing,
   * MIME record overhead, and available plaintext space.
   *
   * Formula:
   * Available space = tag_capacity - NDEF_TLV_overhead - MIME_record_overhead - Ghost_Tag_envelope_overhead
   *
   * @param tag The detected NFC tag.
   * @returns TagCapacity breakdown.
   */
  public getCapacity(tag: NfcTag): TagCapacity {
    const ident = this.identifyTag(tag);

    if (!ident.isSupported || ident.family === 'UNKNOWN') {
      return {
        family: 'UNKNOWN',
        rawUserMemoryBytes: 0,
        usableNdefBytes: 0,
        ndefTlvOverheadBytes: 0,
        mimeRecordOverheadBytes: SHORT_RECORD_MIME_OVERHEAD,
        envelopeOverheadBytes: ENVELOPE_FIXED_OVERHEAD_BYTES,
        totalOverheadBytes: SHORT_RECORD_MIME_OVERHEAD + ENVELOPE_FIXED_OVERHEAD_BYTES,
        maxPlaintextBytes: -(SHORT_RECORD_MIME_OVERHEAD + ENVELOPE_FIXED_OVERHEAD_BYTES),
        availablePlaintextBytes: 0,
      };
    }

    const family = ident.family as SupportedTagFamily;
    const profile = TAG_CAPACITIES[family];

    const rawUserMemoryBytes = profile.rawUserMemoryBytes;
    const usableNdefBytes = profile.usableNdefBytes;

    // NDEF TLV container overhead is the difference between raw user memory and usable NDEF message area
    const ndefTlvOverheadBytes = Math.max(0, rawUserMemoryBytes - usableNdefBytes);

    // MIME record overhead (31B for <255B payload, 34B for >=255B payload)
    const mimeRecordOverheadBytes =
      usableNdefBytes >= 255 ? LONG_RECORD_MIME_OVERHEAD : SHORT_RECORD_MIME_OVERHEAD;

    const envelopeOverheadBytes = ENVELOPE_FIXED_OVERHEAD_BYTES; // 54B

    // Available space = tag_capacity - NDEF_TLV_overhead - MIME_record_overhead - Ghost_Tag_envelope_overhead
    const totalOverheadBytes =
      ndefTlvOverheadBytes + mimeRecordOverheadBytes + envelopeOverheadBytes;

    const maxPlaintextBytes = rawUserMemoryBytes - totalOverheadBytes;
    const availablePlaintextBytes = Math.max(0, maxPlaintextBytes);

    return {
      family,
      rawUserMemoryBytes,
      usableNdefBytes,
      ndefTlvOverheadBytes,
      mimeRecordOverheadBytes,
      envelopeOverheadBytes,
      totalOverheadBytes,
      maxPlaintextBytes,
      availablePlaintextBytes,
    };
  }

  /**
   * Calculates the exact maximum usable plaintext payload size in bytes that will fit
   * onto this tag inside an authenticated Ghost-Tag envelope.
   *
   * @param tag The detected NFC tag.
   * @returns Maximum plaintext bytes (0 if tag cannot accommodate envelope).
   */
  public calculateAvailableSpace(tag: NfcTag): number {
    const capacity = this.getCapacity(tag);
    return capacity.availablePlaintextBytes;
  }

  /**
   * Assesses whether the tag hardware is supported by Ghost-Tag.
   *
   * @param tag The detected NFC tag.
   * @returns True if tag belongs to a supported Type 2 Tag family.
   */
  public isTagSupported(tag: NfcTag): boolean {
    const ident = this.identifyTag(tag);
    return ident.isSupported;
  }

  /**
   * Assesses whether the tag is currently writable (not locked or configured read-only).
   *
   * @param tag The detected NFC tag.
   * @returns True if tag supports write operations.
   */
  public isTagWritable(tag: NfcTag): boolean {
    if (!this.isTagSupported(tag)) {
      return false;
    }
    // Android reports isWritable on NDEF tags; if undefined or null, assume writable unless flagged
    return tag.isWritable !== false;
  }

  /**
   * Converts a detected NfcTag into the Ghost-Tag canonical TagInfo contract representation.
   *
   * @param tag The detected NFC tag.
   * @returns Canonical TagInfo object from contracts.
   */
  public toContractTagInfo(tag: NfcTag): ContractTagInfo {
    const ident = this.identifyTag(tag);
    const capacity = this.getCapacity(tag);
    const family = ident.isSupported ? (ident.family as SupportedTagFamily) : SupportedTagFamily.NTAG213;

    return {
      family,
      capacity: capacity.usableNdefBytes,
      isNdefFormatted: Array.isArray(tag.ndefMessage) && tag.ndefMessage.length > 0,
      isReadOnly: tag.isWritable === false,
      isLocked: false,
      uidLength: tag.id ? tag.id.length / 2 : 7,
      uid: tag.id,
    };
  }

  /**
   * Calculates granular memory capacity available for a bulk encrypted chunk (v2).
   *
   * Formula:
   * usable_capacity_per_tag = actual_tag_user_memory - NDEF_TLV_overhead (7B) - NDEF_record_overhead (29B/32B) - bulk_envelope_overhead (134B)
   */
  public calculateBulkChunkCapacity(tag: NfcTag): BulkTagCapacity {
    const ident = this.identifyTag(tag);

    if (!ident.isSupported || ident.family === 'UNKNOWN') {
      return {
        family: 'UNKNOWN',
        rawUserMemoryBytes: 0,
        usableNdefBytes: 0,
        ndefTlvOverheadBytes: 0,
        mimeRecordOverheadBytes: SHORT_BULK_MIME_OVERHEAD,
        bulkEnvelopeOverheadBytes: BULK_ENVELOPE_OVERHEAD,
        totalOverheadBytes: SHORT_BULK_MIME_OVERHEAD + BULK_ENVELOPE_OVERHEAD,
        maxChunkBytes: -(SHORT_BULK_MIME_OVERHEAD + BULK_ENVELOPE_OVERHEAD),
        usableChunkBytes: 0,
      };
    }

    const family = ident.family as SupportedTagFamily;
    const profile = TAG_CAPACITIES[family];

    const rawUserMemoryBytes = profile.rawUserMemoryBytes;
    const usableNdefBytes = profile.usableNdefBytes;

    const ndefTlvOverheadBytes = Math.max(0, rawUserMemoryBytes - usableNdefBytes);
    const mimeRecordOverheadBytes =
      usableNdefBytes >= 255 ? LONG_BULK_MIME_OVERHEAD : SHORT_BULK_MIME_OVERHEAD;

    const bulkEnvelopeOverheadBytes = BULK_ENVELOPE_OVERHEAD; // 134 bytes
    const totalOverheadBytes =
      ndefTlvOverheadBytes + mimeRecordOverheadBytes + bulkEnvelopeOverheadBytes;

    const maxChunkBytes = rawUserMemoryBytes - totalOverheadBytes;
    const usableChunkBytes = Math.max(0, maxChunkBytes);

    return {
      family,
      rawUserMemoryBytes,
      usableNdefBytes,
      ndefTlvOverheadBytes,
      mimeRecordOverheadBytes,
      bulkEnvelopeOverheadBytes,
      totalOverheadBytes,
      maxChunkBytes,
      usableChunkBytes,
    };
  }

  /**
   * Calculates the exact number of NFC tags required to store files.
   *
   * @param totalFileSizeBytes Total size in bytes of files to store (including encryption packaging).
   * @param usableChunkBytesPerTag Usable payload capacity per tag from calculateBulkChunkCapacity().
   * @param redundancyM Number of Reed-Solomon recovery chunks to generate (M >= 0).
   * @returns Breakdown of required tags, data chunks K, and recovery chunks M.
   */
  public calculateRequiredTags(
    totalFileSizeBytes: number,
    usableChunkBytesPerTag: number,
    redundancyM: number = 0
  ): {
    requiredTags: number;
    dataChunksK: number;
    recoveryChunksM: number;
  } {
    if (usableChunkBytesPerTag <= 0) {
      throw new Error(`Invalid usable chunk capacity: ${usableChunkBytesPerTag}`);
    }

    const dataChunksK = Math.max(1, Math.ceil(totalFileSizeBytes / usableChunkBytesPerTag));
    const recoveryChunksM = Math.max(0, redundancyM);
    const requiredTags = dataChunksK + recoveryChunksM;

    return {
      requiredTags,
      dataChunksK,
      recoveryChunksM,
    };
  }
}

/**
 * Shared singleton instance of TagInfo service.
 */
export const tagInfo = new TagInfo();
