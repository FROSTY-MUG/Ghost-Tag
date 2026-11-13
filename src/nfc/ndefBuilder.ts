/**
 * @file ndefBuilder.ts
 * @summary NDEF Message and Record Construction for Ghost-Tag Envelopes.
 *
 * Implements construction and parsing of NFC Forum NDEF MIME media records
 * carrying raw binary Ghost-Tag envelopes under the registered MIME type
 * "application/vnd.ghost.secure".
 *
 * Security Properties:
 * - Direct Binary Framing: Never encodes envelope payloads as Base64 or JSON,
 *   preventing 33% bloat on constrained Type 2 tag memory.
 * - Strict MIME Validation: Payload extraction rejects non-MIME or mismatched record types.
 */

import { Ndef, NdefRecord } from 'react-native-nfc-manager';
import {
  ENVELOPE_MIME_TYPE,
  ENVELOPE_FIXED_OVERHEAD_BYTES,
  ENVELOPE_MAGIC_BYTES,
} from '../contracts/envelope';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

/**
 * Representation of an NDEF message as an array of NDEF records.
 */
export type NdefMessage = NdefRecord[];

/**
 * Validated Ghost-Tag NDEF record representation with extracted raw binary payload.
 */
export interface GhostTagRecord {
  /** The underlying NdefRecord from react-native-nfc-manager. */
  readonly record: NdefRecord;
  /** Verified MIME media type. */
  readonly mimeType: typeof ENVELOPE_MIME_TYPE;
  /** Raw binary envelope bytes (unmodified, non-Base64). */
  readonly payload: Uint8Array;
}

/**
 * Constructs an NDEF MIME Media record containing the raw binary Ghost-Tag envelope.
 *
 * The resulting record has:
 * - TNF: TNF_MIME_MEDIA (0x02)
 * - Type: "application/vnd.ghost.secure"
 * - ID: Empty byte array
 * - Payload: Array of unsigned 8-bit integers directly mirroring the envelope buffer.
 *
 * @param envelope The raw serialized binary envelope to encode.
 * @returns NdefRecord formatted for react-native-nfc-manager.
 * @throws GhostTagError if envelope is empty or shorter than the 54-byte minimum header.
 */
export function buildGhostTagNdefRecord(envelope: Uint8Array): NdefRecord {
  if (!envelope || envelope.length < ENVELOPE_FIXED_OVERHEAD_BYTES) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: 'Cannot construct NDEF record with an invalid or truncated envelope.',
      technicalDetail: `Envelope length (${envelope?.length ?? 0}B) is below minimum fixed overhead (${ENVELOPE_FIXED_OVERHEAD_BYTES}B).`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  // Verify magic bytes "GTAG"
  for (let i = 0; i < ENVELOPE_MAGIC_BYTES.length; i++) {
    if (envelope[i] !== ENVELOPE_MAGIC_BYTES[i]) {
      throw new GhostTagError({
        code: GhostTagErrorCode.INVALID_ENVELOPE,
        userMessage: 'Envelope magic header is corrupted.',
        technicalDetail: `Byte at offset ${i} is 0x${envelope[i].toString(16)}, expected 0x${ENVELOPE_MAGIC_BYTES[i].toString(16)}.`,
        category: ErrorCategory.ENVELOPE,
        severity: ErrorSeverity.ERROR,
      });
    }
  }

  // Convert Uint8Array to regular number array as required by react-native-nfc-manager NDEF library
  const payloadArray = Array.from(envelope);

  return Ndef.record(
    Ndef.TNF_MIME_MEDIA,
    ENVELOPE_MIME_TYPE,
    [],
    payloadArray
  );
}

/**
 * Builds a single-record NDEF message containing a Ghost-Tag MIME record.
 *
 * @param envelope The raw binary envelope bytes.
 * @returns An NdefMessage (array of records) ready for transmission.
 */
export function buildGhostTagNdefMessage(envelope: Uint8Array): NdefMessage {
  const record = buildGhostTagNdefRecord(envelope);
  return [record];
}

/**
 * Encodes a raw Ghost-Tag envelope directly into raw NDEF message bytes
 * suitable for `NfcManager.writeNdefMessage()`.
 *
 * @param envelope The raw binary envelope bytes.
 * @returns An array of byte values (number[]) representing the complete NDEF TLV message.
 */
export function encodeGhostTagNdefMessage(envelope: Uint8Array): number[] {
  const message = buildGhostTagNdefMessage(envelope);
  return Ndef.encodeMessage(message);
}

/**
 * Extracts and validates the raw binary payload from a candidate Ghost-Tag NDEF record.
 *
 * Ensures:
 * - Record TNF is TNF_MIME_MEDIA (0x02)
 * - Record Type matches "application/vnd.ghost.secure" (case-insensitive)
 * - Payload is returned as a Uint8Array containing pure raw binary data
 *
 * @param record The NDEF record to inspect.
 * @returns The raw Uint8Array payload, or null if the record does not match the Ghost-Tag specification.
 */
export function extractGhostTagPayload(record: NdefRecord): Uint8Array | null {
  if (!record || record.tnf !== Ndef.TNF_MIME_MEDIA) {
    return null;
  }

  // Resolve record type string from either string or byte array
  let recordType = '';
  if (typeof record.type === 'string') {
    recordType = record.type;
  } else if (Array.isArray(record.type)) {
    recordType = String.fromCharCode(...record.type);
  }

  if (recordType.trim().toLowerCase() !== ENVELOPE_MIME_TYPE.toLowerCase()) {
    return null;
  }

  // Extract raw payload bytes
  if (record.payload instanceof Uint8Array) {
    return record.payload;
  }

  if (Array.isArray(record.payload)) {
    return new Uint8Array(record.payload);
  }

  if (typeof record.payload === 'string') {
    const bytes = Ndef.util.stringToBytes(record.payload);
    return new Uint8Array(bytes);
  }

  return null;
}
