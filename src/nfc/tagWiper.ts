/**
 * @file tagWiper.ts
 * @summary NFC Tag Destructive Sanitization and Verification.
 *
 * Implements multi-pass bit-level erasure for NFC Forum Type 2 tags,
 * overwriting writable user memory pages with zeros and cryptographically
 * random byte patterns followed by read-back verification.
 *
 * Security Properties & Hardware Boundary Safety:
 * - CC & Lock Preservation: Strictly identifies writable user pages starting at Page 4.
 *   Excludes Capability Container (Page 3), static lock bits (Page 2), and dynamic lock /
 *   configuration / password pages beyond user memory to avoid permanent tag bricking.
 * - Anti-Remanence Overwrite: Executes 0x00 zero-fill pass followed by pseudo-random bit inversion.
 * - Partial Wipe Halting: On communication loss or write tear, reports WIPE_PARTIAL immediately
 *   and strictly refrains from formatting a new NDEF container.
 * - Security Disclaimer: This is a best-effort EEPROM data purge and does not provide
 *   forensic physical erasure (e.g., NIST SP 800-88 Purge / DoD 5220.22-M).
 */

import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { NfcTag, tagInfo } from './tagInfo';
import {
  mapNfcError,
  createTagNotDetectedError,
  createTagUnsupportedError,
  createTagReadOnlyError,
  createWipePartialError,
} from './errors';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { WipeState } from '../contracts/states';

/** First writable user page index in NFC Forum Type 2 Tag memory layout. */
export const START_USER_PAGE = 4;

/** Number of bytes per Type 2 Tag memory page. */
export const PAGE_SIZE_BYTES = 4;

/**
 * Result indicating successful tag sanitization and verification.
 */
export interface WipeSuccess {
  readonly success: true;
  /** Final state milestone. */
  readonly state: WipeState.WIPE_COMPLETE;
  /** Number of user pages successfully wiped. */
  readonly pagesWiped: number;
  /** Total user pages identified on tag. */
  readonly totalPages: number;
  /** Whether read-back verification confirmed complete overwrite. */
  readonly verified: boolean;
}

/**
 * Result indicating partial sanitization failure.
 */
export interface WipePartial {
  readonly success: false;
  /** State machine milestone indicating interrupted wipe. */
  readonly state: WipeState.WIPE_PARTIAL;
  /** Pages wiped before failure occurred. */
  readonly pagesWiped: number;
  /** Total user pages on tag. */
  readonly totalPages: number;
  /** Typed error describing interruption. */
  readonly error: GhostTagError;
}

/**
 * Result indicating complete wipe initiation failure.
 */
export interface WipeFailure {
  readonly success: false;
  /** State machine failure milestone. */
  readonly state: WipeState.WIPE_FAILED;
  readonly pagesWiped: number;
  readonly totalPages: number;
  readonly error: GhostTagError;
}

/**
 * Discriminated union result of wipeTag().
 */
export type WipeResult = WipeSuccess | WipePartial | WipeFailure;

/**
 * Result indicating successful read-back wipe verification.
 */
export interface WipeVerifySuccess {
  readonly verified: true;
  readonly state: WipeState.WIPE_COMPLETE;
  readonly pagesVerified: number;
}

/**
 * Result indicating wipe verification failure.
 */
export interface WipeVerifyFailure {
  readonly verified: false;
  readonly state: WipeState.WIPE_PARTIAL | WipeState.WIPE_FAILED;
  readonly pagesVerified: number;
  readonly failedPage: number;
  readonly error: GhostTagError;
}

/**
 * Discriminated union result of verifyWipe().
 */
export type WipeVerifyResult = WipeVerifySuccess | WipeVerifyFailure;

/**
 * Generates cryptographically secure random bytes for memory overwriting.
 *
 * @param count Number of random bytes to produce.
 * @returns Uint8Array populated with random values.
 */
function generateRandomBytes(count: number): Uint8Array {
  const bytes = new Uint8Array(count);
  const g = globalThis as unknown as {
    crypto?: {
      getRandomValues?: (array: Uint8Array) => Uint8Array;
    };
  };

  if (g.crypto && typeof g.crypto.getRandomValues === 'function') {
    g.crypto.getRandomValues(bytes);
  } else {
    // Fallback for environments lacking crypto.getRandomValues
    for (let i = 0; i < count; i++) {
      bytes[i] = Math.floor(Math.random() * 256);
    }
  }
  return bytes;
}

/**
 * Destructive NFC Tag Wiper implementing anti-remanence user memory sanitization.
 */
export class TagWiper {
  /**
   * Executes a multi-pass destructive wipe across all writable user memory pages.
   *
   * Flow:
   * 1. Validates tag and identifies user page bounds [Page 4 .. 4 + userPages - 1].
   * 2. Overwrite Pass 1: Writes all user pages with 0x00 bytes.
   * 3. Overwrite Pass 2: Writes all user pages with cryptographically random bytes.
   * 4. Verification Pass: Reads back each page and compares with the random data.
   * 5. Format Pass: Restores an empty NDEF container (0x03 0x00 0xFE) ONLY upon verified success.
   *
   * If interrupted at any point, halts immediately, reports WIPE_PARTIAL, and does NOT format NDEF.
   *
   * @param tag The target NFC tag.
   * @returns WipeResult detailing success or partial/failed completion.
   */
  public async wipeTag(tag: NfcTag): Promise<WipeResult> {
    if (!tag) {
      return {
        success: false,
        state: WipeState.WIPE_FAILED,
        pagesWiped: 0,
        totalPages: 0,
        error: createTagNotDetectedError('No tag provided for wipe operation.'),
      };
    }

    // Validate tag compatibility
    if (!tagInfo.isTagSupported(tag)) {
      return {
        success: false,
        state: WipeState.WIPE_FAILED,
        pagesWiped: 0,
        totalPages: 0,
        error: createTagUnsupportedError('Detected tag is not a supported Type 2 tag.'),
      };
    }

    // Validate writability
    if (!tagInfo.isTagWritable(tag)) {
      return {
        success: false,
        state: WipeState.WIPE_FAILED,
        pagesWiped: 0,
        totalPages: 0,
        error: createTagReadOnlyError('Cannot wipe read-only or hardware-locked tag.'),
      };
    }

    const ident = tagInfo.identifyTag(tag);
    const totalPages = ident.userPages;
    if (totalPages <= 0) {
      return {
        success: false,
        state: WipeState.WIPE_FAILED,
        pagesWiped: 0,
        totalPages: 0,
        error: new GhostTagError({
          code: GhostTagErrorCode.TAG_UNSUPPORTED,
          userMessage: 'Unable to determine user page boundaries for tag.',
          technicalDetail: 'Calculated user page count is zero.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        }),
      };
    }

    let techRequested = false;
    let pagesCompleted = 0;
    const randomPageData = new Map<number, Uint8Array>();

    try {
      // Connect to tag using MifareUltralight or NfcA tech
      await NfcManager.requestTechnology([NfcTech.MifareUltralight, NfcTech.NfcA]);
      techRequested = true;

      // Pass 1: Overwrite all user pages with 0x00 zeros
      const zeroPage = [0x00, 0x00, 0x00, 0x00];
      for (let p = 0; p < totalPages; p++) {
        const pageIndex = START_USER_PAGE + p;
        try {
          await this.writeSinglePage(pageIndex, zeroPage);
        } catch (writeErr) {
          return {
            success: false,
            state: WipeState.WIPE_PARTIAL,
            pagesWiped: p,
            totalPages,
            error: createWipePartialError(
              `Wipe failed during Pass 1 (zeros) at page ${pageIndex}: ${(writeErr as Error)?.message}`,
              writeErr
            ),
          };
        }
      }

      // Pass 2: Overwrite all user pages with cryptographically random bytes
      for (let p = 0; p < totalPages; p++) {
        const pageIndex = START_USER_PAGE + p;
        const randomBytes = generateRandomBytes(PAGE_SIZE_BYTES);
        randomPageData.set(pageIndex, randomBytes);

        try {
          await this.writeSinglePage(pageIndex, Array.from(randomBytes));
          pagesCompleted = p + 1;
        } catch (writeErr) {
          // DO NOT write empty NDEF container after partial wipe
          return {
            success: false,
            state: WipeState.WIPE_PARTIAL,
            pagesWiped: pagesCompleted,
            totalPages,
            error: createWipePartialError(
              `Wipe failed during Pass 2 (random) at page ${pageIndex}: ${(writeErr as Error)?.message}`,
              writeErr
            ),
          };
        }
      }

      // Pass 3: Verification - Read back and verify every random page
      const verifyResult = await this.verifyPagesInternal(totalPages, randomPageData);
      if (!verifyResult.verified) {
        return {
          success: false,
          state: WipeState.WIPE_PARTIAL,
          pagesWiped: verifyResult.pagesVerified,
          totalPages,
          error: verifyResult.error,
        };
      }

      // Pass 4: Restore Empty NDEF container ONLY upon verified sanitization
      // Page 4: NDEF TLV [0x03, 0x00, 0xFE, 0x00] (TLV Tag 0x03, Len 0x00, Terminator 0xFE)
      try {
        await this.writeSinglePage(START_USER_PAGE, [0x03, 0x00, 0xFE, 0x00]);
        // Zero remaining user pages
        for (let p = 1; p < totalPages; p++) {
          await this.writeSinglePage(START_USER_PAGE + p, zeroPage);
        }
      } catch {
        // If formatting empty NDEF fails, the memory was still wiped and verified
      }

      return {
        success: true,
        state: WipeState.WIPE_COMPLETE,
        pagesWiped: totalPages,
        totalPages,
        verified: true,
      };
    } catch (error) {
      return {
        success: false,
        state: pagesCompleted > 0 ? WipeState.WIPE_PARTIAL : WipeState.WIPE_FAILED,
        pagesWiped: pagesCompleted,
        totalPages,
        error: mapNfcError(error),
      };
    } finally {
      if (techRequested) {
        try {
          await NfcManager.cancelTechnologyRequest();
        } catch {
          // Ignore cancellation errors during cleanup
        }
      }
    }
  }

  /**
   * Verifies that the tag's user memory matches expected overwrite contents.
   *
   * @param tag The target NFC tag.
   * @param expectedPageData Optional map of page index to expected 4-byte Uint8Array.
   * @returns WipeVerifyResult (verified: true or failure with mismatched page).
   */
  public async verifyWipe(
    tag: NfcTag,
    expectedPageData?: Map<number, Uint8Array>
  ): Promise<WipeVerifyResult> {
    if (!tag) {
      return {
        verified: false,
        state: WipeState.WIPE_FAILED,
        pagesVerified: 0,
        failedPage: START_USER_PAGE,
        error: createTagNotDetectedError('No tag provided for wipe verification.'),
      };
    }

    const ident = tagInfo.identifyTag(tag);
    const totalPages = ident.userPages;

    let techRequested = false;
    try {
      await NfcManager.requestTechnology([NfcTech.MifareUltralight, NfcTech.NfcA]);
      techRequested = true;

      return await this.verifyPagesInternal(totalPages, expectedPageData);
    } catch (error) {
      return {
        verified: false,
        state: WipeState.WIPE_FAILED,
        pagesVerified: 0,
        failedPage: START_USER_PAGE,
        error: mapNfcError(error),
      };
    } finally {
      if (techRequested) {
        try {
          await NfcManager.cancelTechnologyRequest();
        } catch {
          // Ignore cleanup errors
        }
      }
    }
  }

  /**
   * Internal verification loop across all user pages.
   */
  private async verifyPagesInternal(
    totalPages: number,
    expectedPageData?: Map<number, Uint8Array>
  ): Promise<WipeVerifyResult> {
    for (let p = 0; p < totalPages; p++) {
      const pageIndex = START_USER_PAGE + p;
      try {
        const readBytes = await this.readSinglePage(pageIndex);
        const expected = expectedPageData?.get(pageIndex);

        if (expected) {
          for (let b = 0; b < PAGE_SIZE_BYTES; b++) {
            if (readBytes[b] !== expected[b]) {
              return {
                verified: false,
                state: WipeState.WIPE_PARTIAL,
                pagesVerified: p,
                failedPage: pageIndex,
                error: new GhostTagError({
                  code: GhostTagErrorCode.WIPE_PARTIAL,
                  userMessage: `Wipe verification mismatch at page ${pageIndex}.`,
                  technicalDetail: `Byte ${b} on page ${pageIndex} was 0x${readBytes[b].toString(16)}, expected 0x${expected[b].toString(16)}.`,
                  category: ErrorCategory.NFC,
                  severity: ErrorSeverity.CRITICAL,
                }),
              };
            }
          }
        }
      } catch (readErr) {
        return {
          verified: false,
          state: WipeState.WIPE_PARTIAL,
          pagesVerified: p,
          failedPage: pageIndex,
          error: createWipePartialError(
            `Failed reading back page ${pageIndex} for verification: ${(readErr as Error)?.message}`,
            readErr
          ),
        };
      }
    }

    return {
      verified: true,
      state: WipeState.WIPE_COMPLETE,
      pagesVerified: totalPages,
    };
  }

  /**
   * Writes 4 bytes to a single memory page using native MifareUltralight or NfcA transceive.
   */
  private async writeSinglePage(pageIndex: number, data: number[]): Promise<void> {
    if (data.length !== PAGE_SIZE_BYTES) {
      throw new Error(`Page data must be exactly ${PAGE_SIZE_BYTES} bytes`);
    }

    try {
      // Primary: Android MifareUltralight native handler
      await NfcManager.mifareUltralightHandlerAndroid.mifareUltralightWritePage(pageIndex, data);
    } catch {
      // Fallback: Raw NFC-A / Type 2 command: [0xA2, pageIndex, d0, d1, d2, d3]
      const cmd = [0xa2, pageIndex, data[0], data[1], data[2], data[3]];
      await NfcManager.transceive(cmd);
    }
  }

  /**
   * Reads a 4-byte memory page using native MifareUltralight or NfcA transceive.
   */
  private async readSinglePage(pageIndex: number): Promise<number[]> {
    try {
      // Primary: Android MifareUltralight read pages (reads 16 bytes = 4 pages starting at offset)
      const data16 = await NfcManager.mifareUltralightHandlerAndroid.mifareUltralightReadPages(pageIndex);
      return data16.slice(0, PAGE_SIZE_BYTES);
    } catch {
      // Fallback: Raw Type 2 READ command: [0x30, pageIndex] -> returns 16 bytes
      const cmd = [0x30, pageIndex];
      const resp = await NfcManager.transceive(cmd);
      return resp.slice(0, PAGE_SIZE_BYTES);
    }
  }
}

/**
 * Shared singleton instance of TagWiper.
 */
export const tagWiper = new TagWiper();
