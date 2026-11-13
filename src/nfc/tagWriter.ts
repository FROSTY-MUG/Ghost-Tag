/**
 * @file tagWriter.ts
 * @summary NFC Tag NDEF Envelope Writing with Mandatory Read-Back Verification.
 *
 * Implements high-reliability writing of encrypted Ghost-Tag envelopes to NFC Forum Type 2
 * tags with strict anti-tear protection and post-write read-back verification.
 *
 * Security Properties:
 * - Anti-Tear Verification: A write operation is ONLY deemed successful after a full
 *   read-back and byte-by-byte comparison against the source buffer.
 * - Field-Level Integrity: Independently verifies GCM auth tag, Key ID, Ciphertext length,
 *   and MIME media type during verification.
 * - Strict State Invariance: Under no circumstances does the writer report WRITE_VERIFIED
 *   without successful, bit-for-bit read-back confirmation.
 */

import NfcManager, { NfcTech } from 'react-native-nfc-manager';
import { NfcTag, tagInfo } from './tagInfo';
import { tagReader } from './tagReader';
import { encodeGhostTagNdefMessage } from './ndefBuilder';
import {
  mapNfcError,
  createTagNotDetectedError,
  createTagUnsupportedError,
  createTagReadOnlyError,
  createTagCapacityInsufficientError,
  createTagWriteFailedError,
  createTagWriteUnverifiedError,
} from './errors';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import {
  ENVELOPE_MIME_TYPE,
  ENVELOPE_OFFSET_KEY_ID,
  ENVELOPE_KEY_ID_SIZE,
  ENVELOPE_OFFSET_CIPHERTEXT_LENGTH,
  ENVELOPE_CIPHERTEXT_LENGTH_SIZE,
  ENVELOPE_GCM_TAG_SIZE,
} from '../contracts/envelope';
import { WriteState } from '../contracts/states';

/**
 * Result returned upon completion of the initial write phase.
 */
export interface WriteSuccess {
  readonly success: true;
  /** Byte count of the serialized envelope written to tag. */
  readonly bytesWritten: number;
  /** State machine milestone indicating write transmission finished. */
  readonly state: WriteState.WRITE_COMPLETE;
}

/**
 * Result returned when write transmission fails.
 */
export interface WriteFailure {
  readonly success: false;
  /** Typed error detailing the write failure. */
  readonly error: GhostTagError;
  /** State machine milestone. */
  readonly state: WriteState.WRITE_FAILED;
}

/**
 * Discriminated union result of writeEnvelope().
 */
export type WriteResult = WriteSuccess | WriteFailure;

/**
 * Result returned upon successful read-back verification.
 */
export interface VerifySuccess {
  readonly verified: true;
  /** Number of bytes matched during read-back. */
  readonly matchedBytes: number;
  /** State machine milestone confirming authenticated write. */
  readonly state: WriteState.WRITE_VERIFIED;
}

/**
 * Result returned when read-back verification fails.
 */
export interface VerifyFailure {
  readonly verified: false;
  /** Typed error detailing the verification failure. */
  readonly error: GhostTagError;
  /** State machine milestone. */
  readonly state: WriteState.WRITE_UNVERIFIED;
  /** Byte offset where mismatch was detected, if applicable. */
  readonly mismatchedIndex?: number;
  /** Specific envelope field that failed verification, if applicable. */
  readonly mismatchedField?: string;
}

/**
 * Discriminated union result of verifyWrite().
 */
export type VerifyResult = VerifySuccess | VerifyFailure;

/**
 * Comprehensive result of atomic write-and-verify lifecycle.
 */
export interface WriteVerifySuccess {
  readonly success: true;
  readonly state: WriteState.WRITE_VERIFIED;
  readonly bytesWritten: number;
  readonly envelope: Uint8Array;
}

/**
 * Comprehensive failure result of write-and-verify lifecycle.
 */
export interface WriteVerifyFailure {
  readonly success: false;
  readonly state: WriteState.WRITE_FAILED | WriteState.WRITE_UNVERIFIED;
  readonly error: GhostTagError;
}

/**
 * Discriminated union result of writeAndVerify().
 */
export type WriteVerifyResult = WriteVerifySuccess | WriteVerifyFailure;

/**
 * Service for writing and verifying Ghost-Tag envelopes on NFC tags.
 */
export class TagWriter {
  /**
   * Encodes a Ghost-Tag envelope into an NDEF MIME record and transmits it to the tag.
   *
   * Enforces:
   * - Hardware compatibility with Type 2 Tag matrix
   * - Tag writable status (non-read-only)
   * - User memory capacity verification against encoded NDEF byte length
   *
   * @param tag The target NFC tag.
   * @param envelope The raw serialized binary envelope to write.
   * @returns WriteResult (success or typed error failure).
   */
  public async writeEnvelope(tag: NfcTag, envelope: Uint8Array): Promise<WriteResult> {
    if (!tag) {
      return {
        success: false,
        error: createTagNotDetectedError('No tag instance provided to writer.'),
        state: WriteState.WRITE_FAILED,
      };
    }

    try {
      // Validate tag hardware compatibility
      if (!tagInfo.isTagSupported(tag)) {
        return {
          success: false,
          error: createTagUnsupportedError('Detected tag is not a supported Type 2 tag.'),
          state: WriteState.WRITE_FAILED,
        };
      }

      // Validate tag writability
      if (!tagInfo.isTagWritable(tag)) {
        return {
          success: false,
          error: createTagReadOnlyError('Tag is configured as read-only or hardware locked.'),
          state: WriteState.WRITE_FAILED,
        };
      }

      // Encode NDEF message bytes
      const encodedNdefBytes = encodeGhostTagNdefMessage(envelope);

      // Validate capacity
      const capacity = tagInfo.getCapacity(tag);
      if (capacity.usableNdefBytes > 0 && encodedNdefBytes.length > capacity.usableNdefBytes) {
        return {
          success: false,
          error: createTagCapacityInsufficientError(
            `Encoded NDEF message (${encodedNdefBytes.length}B) exceeds usable tag memory (${capacity.usableNdefBytes}B).`
          ),
          state: WriteState.WRITE_FAILED,
        };
      }

      // Transmit NDEF message over RF link
      await NfcManager.writeNdefMessage(encodedNdefBytes);

      return {
        success: true,
        bytesWritten: envelope.length,
        state: WriteState.WRITE_COMPLETE,
      };
    } catch (error) {
      return {
        success: false,
        error: mapNfcError(error),
        state: WriteState.WRITE_FAILED,
      };
    }
  }

  /**
   * Reads back the written payload from the tag and performs comprehensive verification:
   * 1. Confirms presence of "application/vnd.ghost.secure" MIME record
   * 2. Confirms byte-for-byte match of 16-byte GCM authentication tag
   * 3. Confirms byte-for-byte match of 16-byte Key ID
   * 4. Confirms uint32 LE ciphertext length header field
   * 5. Confirms full byte-by-byte identity with source envelope buffer
   *
   * @param tag The target NFC tag.
   * @param expectedEnvelope The source binary envelope buffer written previously.
   * @returns VerifyResult (verified: true or typed failure).
   */
  public async verifyWrite(tag: NfcTag, expectedEnvelope: Uint8Array): Promise<VerifyResult> {
    try {
      // Read back NDEF message directly from tag
      const readResult = await tagReader.readTag(tag);
      if (!readResult.success) {
        return {
          verified: false,
          error: createTagWriteUnverifiedError(
            `Read-back failed: ${readResult.error.userMessage}`,
            readResult.error
          ),
          state: WriteState.WRITE_UNVERIFIED,
        };
      }

      const readBackEnvelope = readResult.rawEnvelope;

      // Check MIME type confirmation
      if (readResult.ghostTagRecord.mimeType !== ENVELOPE_MIME_TYPE) {
        return {
          verified: false,
          error: createTagWriteUnverifiedError('MIME type mismatch on read-back verification.'),
          state: WriteState.WRITE_UNVERIFIED,
          mismatchedField: 'MIME_TYPE',
        };
      }

      // Check total envelope length
      if (readBackEnvelope.length !== expectedEnvelope.length) {
        return {
          verified: false,
          error: createTagWriteUnverifiedError(
            `Envelope size mismatch: wrote ${expectedEnvelope.length}B, read back ${readBackEnvelope.length}B.`
          ),
          state: WriteState.WRITE_UNVERIFIED,
          mismatchedField: 'TOTAL_LENGTH',
        };
      }

      // Verify GCM Tag (last 16 bytes)
      const expectedGcmTagOffset = expectedEnvelope.length - ENVELOPE_GCM_TAG_SIZE;
      const readBackGcmTagOffset = readBackEnvelope.length - ENVELOPE_GCM_TAG_SIZE;

      for (let i = 0; i < ENVELOPE_GCM_TAG_SIZE; i++) {
        if (expectedEnvelope[expectedGcmTagOffset + i] !== readBackEnvelope[readBackGcmTagOffset + i]) {
          return {
            verified: false,
            error: createTagWriteUnverifiedError('GCM authentication tag mismatch during read-back.'),
            state: WriteState.WRITE_UNVERIFIED,
            mismatchedField: 'GCM_TAG',
            mismatchedIndex: expectedGcmTagOffset + i,
          };
        }
      }

      // Verify Key ID (bytes 6..21)
      for (let i = 0; i < ENVELOPE_KEY_ID_SIZE; i++) {
        if (expectedEnvelope[ENVELOPE_OFFSET_KEY_ID + i] !== readBackEnvelope[ENVELOPE_OFFSET_KEY_ID + i]) {
          return {
            verified: false,
            error: createTagWriteUnverifiedError('Key ID mismatch during read-back verification.'),
            state: WriteState.WRITE_UNVERIFIED,
            mismatchedField: 'KEY_ID',
            mismatchedIndex: ENVELOPE_OFFSET_KEY_ID + i,
          };
        }
      }

      // Verify Ciphertext Length (bytes 34..37)
      for (let i = 0; i < ENVELOPE_CIPHERTEXT_LENGTH_SIZE; i++) {
        if (
          expectedEnvelope[ENVELOPE_OFFSET_CIPHERTEXT_LENGTH + i] !==
          readBackEnvelope[ENVELOPE_OFFSET_CIPHERTEXT_LENGTH + i]
        ) {
          return {
            verified: false,
            error: createTagWriteUnverifiedError('Ciphertext length header mismatch during read-back verification.'),
            state: WriteState.WRITE_UNVERIFIED,
            mismatchedField: 'CIPHERTEXT_LENGTH',
            mismatchedIndex: ENVELOPE_OFFSET_CIPHERTEXT_LENGTH + i,
          };
        }
      }

      // Complete full byte-by-byte comparison
      for (let i = 0; i < expectedEnvelope.length; i++) {
        if (expectedEnvelope[i] !== readBackEnvelope[i]) {
          return {
            verified: false,
            error: createTagWriteUnverifiedError(`Byte mismatch at offset ${i} during read-back verification.`),
            state: WriteState.WRITE_UNVERIFIED,
            mismatchedIndex: i,
          };
        }
      }

      return {
        verified: true,
        matchedBytes: expectedEnvelope.length,
        state: WriteState.WRITE_VERIFIED,
      };
    } catch (error) {
      return {
        verified: false,
        error: createTagWriteUnverifiedError('Exception occurred during read-back verification.', error),
        state: WriteState.WRITE_UNVERIFIED,
      };
    }
  }

  /**
   * Atomically executes envelope writing followed immediately by mandatory read-back verification.
   *
   * A write is strictly deemed successful ONLY when byte-for-byte read-back verification completes.
   *
   * @param tag The target NFC tag.
   * @param envelope The raw binary envelope to commit.
   * @returns WriteVerifyResult confirming verified write or failure.
   */
  public async writeAndVerify(tag: NfcTag, envelope: Uint8Array): Promise<WriteVerifyResult> {
    let techRequested = false;

    try {
      // Connect to NDEF technology
      await NfcManager.requestTechnology(NfcTech.Ndef);
      techRequested = true;

      // Phase 1: Write envelope to tag
      const writeResult = await this.writeEnvelope(tag, envelope);
      if (!writeResult.success) {
        return {
          success: false,
          state: WriteState.WRITE_FAILED,
          error: writeResult.error,
        };
      }

      // Phase 2: Read-back verification
      const verifyResult = await this.verifyWrite(tag, envelope);
      if (!verifyResult.verified) {
        return {
          success: false,
          state: WriteState.WRITE_UNVERIFIED,
          error: verifyResult.error,
        };
      }

      return {
        success: true,
        state: WriteState.WRITE_VERIFIED,
        bytesWritten: writeResult.bytesWritten,
        envelope,
      };
    } catch (error) {
      return {
        success: false,
        state: WriteState.WRITE_FAILED,
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
}

/**
 * Shared singleton instance of TagWriter.
 */
export const tagWriter = new TagWriter();
