/**
 * @file tagReader.ts
 * @summary NFC Tag NDEF Reading and Envelope Extraction.
 *
 * Implements NDEF payload extraction from detected NFC Forum Type 2 tags,
 * locating the "application/vnd.ghost.secure" MIME record and returning
 * the raw binary envelope buffer with typed error results.
 *
 * Security Properties:
 * - Fail-Safe Result Types: All methods return typed discriminated unions, never throwing
 *   unhandled exceptions across the native bridge boundary.
 * - Envelope Integrity Pre-Validation: Verifies fixed overhead bounds (>=54B) and "GTAG"
 *   magic marker prior to releasing envelope buffers to cryptographic decoders.
 */

import { Platform } from 'react-native';
import NfcManager from 'react-native-nfc-manager';
import { NfcTag, tagInfo } from './tagInfo';
import { NdefMessage, GhostTagRecord, extractGhostTagPayload } from './ndefBuilder';
export type { GhostTagRecord };
import {
  mapNfcError,
  createTagNotDetectedError,
  createTagUnsupportedError,
  createTagNotNdefError,
} from './errors';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import {
  ENVELOPE_MIME_TYPE,
  ENVELOPE_FIXED_OVERHEAD_BYTES,
  ENVELOPE_MAGIC_BYTES,
} from '../contracts/envelope';
import { ScanState } from '../contracts/states';

/**
 * Result indicating successful tag reading and envelope extraction.
 */
export interface TagReadSuccess {
  readonly success: true;
  /** The source NFC tag event. */
  readonly tag: NfcTag;
  /** Complete NDEF message parsed from the tag. */
  readonly message: NdefMessage;
  /** Extracted Ghost-Tag MIME record. */
  readonly ghostTagRecord: GhostTagRecord;
  /** Raw binary envelope bytes ready for envelope parsing and decryption. */
  readonly rawEnvelope: Uint8Array;
  /** Alias for rawEnvelope for backward compatibility. */
  readonly envelopeBytes: Uint8Array;
  /** State machine milestone. */
  readonly state: ScanState.NDEF_READ_COMPLETE;
}

/**
 * Result indicating a tag read failure.
 */
export interface TagReadFailure {
  readonly success: false;
  /** The typed error specifying failure reason. */
  readonly error: GhostTagError;
  /** Terminal state machine failure state. */
  readonly state: ScanState.ERROR;
  /** The source NFC tag event, if available before failure. */
  readonly tag?: NfcTag;
}

/**
 * Discriminated union result of a tag reading operation.
 */
export type TagReadResult = TagReadSuccess | TagReadFailure;

/**
 * Service for reading and extracting encrypted Ghost-Tag envelopes from NFC tags.
 */
export class TagReader {
  /**
   * Reads an NFC tag, retrieves its NDEF message, and extracts the Ghost-Tag binary envelope.
   *
   * Enforces:
   * - Tag presence and technology validation
   * - Type 2 Tag hardware matrix compliance
   * - Presence of "application/vnd.ghost.secure" MIME record
   * - Envelope size >= 54 bytes and valid "GTAG" magic marker
   *
   * @param tag The detected NFC tag.
   * @returns TagReadResult (success with raw envelope or typed error failure).
   */
  public async readTag(tag: NfcTag): Promise<TagReadResult> {
    if (!tag) {
      return {
        success: false,
        error: createTagNotDetectedError('No tag instance provided to reader.'),
        state: ScanState.ERROR,
      };
    }

    try {
      // Validate tag hardware compatibility.
      //
      // iOS: CoreNFC discovery events carry only the NDEF message (no SAK/ATQA/maxSize
      // telemetry), so TagInfo cannot classify the tag — accept any CoreNFC-discovered
      // tag (iOS only surfaces NDEF-capable Type 2 tags) and rely on Ghost envelope
      // validation in readNdefMessage/findGhostTagRecord below.
      if (!tagInfo.isTagSupported(tag) && Platform.OS !== 'ios') {
        return {
          success: false,
          error: createTagUnsupportedError('Detected tag technology is not a supported Type 2 tag.'),
          state: ScanState.ERROR,
          tag,
        };
      }

      // Read NDEF message blocks
      const message = await this.readNdefMessage(tag);
      if (!message || message.length === 0) {
        return {
          success: false,
          error: createTagNotNdefError('Tag does not contain any NDEF records.'),
          state: ScanState.ERROR,
          tag,
        };
      }

      // Search for Ghost-Tag secure envelope record
      const ghostRecord = this.findGhostTagRecord(message);
      if (!ghostRecord) {
        return {
          success: false,
          error: new GhostTagError({
            code: GhostTagErrorCode.INVALID_ENVELOPE,
            userMessage: 'This tag does not contain a Ghost-Tag secure payload.',
            technicalDetail: `NDEF message found with ${message.length} record(s), but none matched MIME type ${ENVELOPE_MIME_TYPE}.`,
            category: ErrorCategory.ENVELOPE,
            severity: ErrorSeverity.ERROR,
          }),
          state: ScanState.ERROR,
          tag,
        };
      }

      const envelope = ghostRecord.payload;

      // Validate envelope length against fixed overhead
      if (envelope.length < ENVELOPE_FIXED_OVERHEAD_BYTES) {
        return {
          success: false,
          error: new GhostTagError({
            code: GhostTagErrorCode.INVALID_ENVELOPE,
            userMessage: 'Corrupted tag: envelope payload is truncated.',
            technicalDetail: `Payload length (${envelope.length}B) is less than minimum envelope overhead (${ENVELOPE_FIXED_OVERHEAD_BYTES}B).`,
            category: ErrorCategory.ENVELOPE,
            severity: ErrorSeverity.ERROR,
          }),
          state: ScanState.ERROR,
          tag,
        };
      }

      // Validate "GTAG" magic marker
      for (let i = 0; i < ENVELOPE_MAGIC_BYTES.length; i++) {
        if (envelope[i] !== ENVELOPE_MAGIC_BYTES[i]) {
          return {
            success: false,
            error: new GhostTagError({
              code: GhostTagErrorCode.INVALID_ENVELOPE,
              userMessage: 'Corrupted tag: invalid envelope header format.',
              technicalDetail: `Envelope magic byte mismatch at offset ${i}: 0x${envelope[i].toString(16)}.`,
              category: ErrorCategory.ENVELOPE,
              severity: ErrorSeverity.ERROR,
            }),
            state: ScanState.ERROR,
            tag,
          };
        }
      }

      return {
        success: true,
        tag,
        message,
        ghostTagRecord: ghostRecord,
        rawEnvelope: envelope,
        envelopeBytes: envelope,
        state: ScanState.NDEF_READ_COMPLETE,
      };
    } catch (error) {
      return {
        success: false,
        error: mapNfcError(error),
        state: ScanState.ERROR,
        tag,
      };
    }
  }

  /**
   * Retrieves the raw NDEF message from a tag, checking cached discovery metadata
   * or querying the native NDEF handler if necessary.
   *
   * @param tag The detected NFC tag.
   * @returns Complete NdefMessage array.
   * @throws GhostTagError if reading fails or no NDEF message exists.
   */
  public async readNdefMessage(tag: NfcTag): Promise<NdefMessage> {
    // Check if discovery event already captured the NDEF message
    if (Array.isArray(tag?.ndefMessage) && tag.ndefMessage.length > 0) {
      return tag.ndefMessage;
    }

    try {
      const tagEvent = await NfcManager.getNdefMessage();
      if (Array.isArray(tagEvent?.ndefMessage) && tagEvent.ndefMessage.length > 0) {
        return tagEvent.ndefMessage;
      }
    } catch (error) {
      throw mapNfcError(error);
    }

    throw createTagNotNdefError('Tag does not contain an active NDEF message.');
  }

  /**
   * Searches an NDEF message for a record matching the Ghost-Tag MIME type
   * "application/vnd.ghost.secure".
   *
   * @param message The NDEF message containing records to search.
   * @returns GhostTagRecord if found, or null if absent.
   */
  public findGhostTagRecord(message: NdefMessage): GhostTagRecord | null {
    if (!Array.isArray(message)) {
      return null;
    }

    for (const record of message) {
      const payload = extractGhostTagPayload(record);
      if (payload !== null) {
        return {
          record,
          mimeType: ENVELOPE_MIME_TYPE,
          payload,
        };
      }
    }

    return null;
  }
}

/**
 * Shared singleton instance of TagReader.
 */
export const tagReader = new TagReader();
