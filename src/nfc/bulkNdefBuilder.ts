/**
 * @file bulkNdefBuilder.ts
 * @summary NDEF Message and Record Construction for Ghost-Tag Bulk Chunks (v2).
 *
 * Implements construction and parsing of NFC Forum NDEF MIME media records
 * carrying raw binary Ghost-Tag bulk chunk envelopes under the registered MIME type
 * "application/vnd.ghost.bulk".
 *
 * Security Properties:
 * - Direct Binary Framing: Zero Base64 or JSON conversion.
 * - Strict MIME Validation: Rejects mismatched MIME types or truncated payloads.
 */

import { Ndef, NdefRecord } from 'react-native-nfc-manager';
import {
  BULK_ENVELOPE_MIME_TYPE,
  BULK_ENVELOPE_FIXED_OVERHEAD,
  BULK_ENVELOPE_MAGIC,
} from '../contracts/bulkEnvelope';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

/**
 * Validated Ghost-Tag Bulk NDEF record.
 */
export interface BulkGhostTagRecord {
  readonly record: NdefRecord;
  readonly mimeType: typeof BULK_ENVELOPE_MIME_TYPE;
  readonly payload: Uint8Array;
}

/**
 * Constructs an NDEF MIME Media record containing the raw binary bulk chunk envelope.
 *
 * @param bulkEnvelope The raw serialized binary bulk envelope to encode.
 * @returns NdefRecord formatted for react-native-nfc-manager.
 */
export function buildBulkGhostTagNdefRecord(bulkEnvelope: Uint8Array): NdefRecord {
  if (!bulkEnvelope || bulkEnvelope.length < BULK_ENVELOPE_FIXED_OVERHEAD) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Cannot build bulk NDEF record: envelope must be at least ${BULK_ENVELOPE_FIXED_OVERHEAD} bytes`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  // Verify magic header
  for (let i = 0; i < BULK_ENVELOPE_MAGIC.length; i++) {
    if (bulkEnvelope[i] !== BULK_ENVELOPE_MAGIC[i]) {
      throw new GhostTagError({
        code: GhostTagErrorCode.INVALID_ENVELOPE,
        userMessage: 'Bulk envelope payload does not contain valid "GTAG" magic header',
        category: ErrorCategory.ENVELOPE,
        severity: ErrorSeverity.ERROR,
      });
    }
  }

  const payloadArray = Array.from(bulkEnvelope);

  return Ndef.record(
    Ndef.TNF_MIME_MEDIA,
    BULK_ENVELOPE_MIME_TYPE,
    [],
    payloadArray
  );
}

/**
 * Encodes a raw bulk envelope into complete NDEF message bytes suitable for transmission.
 */
export function encodeBulkGhostTagNdefMessage(bulkEnvelope: Uint8Array): number[] {
  const record = buildBulkGhostTagNdefRecord(bulkEnvelope);
  return Ndef.encodeMessage([record]);
}

/**
 * Extracts and validates raw bulk chunk envelope bytes from an NDEF record.
 *
 * @param record Raw NdefRecord retrieved from NFC tag.
 * @returns Raw bulk envelope Uint8Array.
 */
export function extractBulkGhostTagPayload(record: NdefRecord): Uint8Array {
  if (!record || record.tnf !== Ndef.TNF_MIME_MEDIA) {
    const tnfVal = record && record.tnf !== undefined ? `0x${record.tnf.toString(16)}` : 'undefined';
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `NDEF record TNF mismatch: expected MIME Media (0x02), got ${tnfVal}`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  let typeStr = '';
  if (typeof record.type === 'string') {
    typeStr = record.type;
  } else if (Array.isArray(record.type)) {
    typeStr = String.fromCharCode(...record.type);
  }

  if (typeStr.trim().toLowerCase() !== BULK_ENVELOPE_MIME_TYPE.toLowerCase()) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `NDEF MIME type mismatch: expected "${BULK_ENVELOPE_MIME_TYPE}", got "${typeStr}"`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const payload = new Uint8Array(record.payload);
  if (payload.length < BULK_ENVELOPE_FIXED_OVERHEAD) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Extracted bulk payload too small: expected >= ${BULK_ENVELOPE_FIXED_OVERHEAD} bytes, got ${payload.length}`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  return payload;
}
