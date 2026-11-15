/**
 * @file envelope.ts
 * @summary Binary envelope serializer, parser, and validator for Ghost-Tag NFC payloads.
 *
 * Implements the canonical 54-byte fixed-overhead binary layout in Little-Endian byte order.
 * Binary Layout:
 * +-------------------+-----------------------+---------------------------------------+
 * | Offset (Bytes)    | Field Name            | Size / Description                    |
 * +-------------------+-----------------------+---------------------------------------+
 * | 00..03 (4B)       | MAGIC                 | ASCII "GTAG" (0x47, 0x54, 0x41, 0x47) |
 * | 04 (1B)           | FORMAT_VERSION        | 0x01 (starts at v1)                   |
 * | 05 (1B)           | PURPOSE               | EnvelopePurpose enum                  |
 * | 06..21 (16B)      | KEY_ID                | 128-bit unique DEK identifier         |
 * | 22..33 (12B)      | NONCE                 | 96-bit AES-256-GCM IV (never reused)  |
 * | 34..37 (4B)       | CIPHERTEXT_LENGTH     | uint32 LE, length in bytes            |
 * | 38..N-17 (varies) | CIPHERTEXT            | AES-256-GCM encrypted payload bytes   |
 * | N-16..N-1 (16B)   | GCM_TAG               | 128-bit AES-256-GCM auth tag          |
 * +-------------------+-----------------------+---------------------------------------+
 */

import {
  ENVELOPE_MAGIC,
  ENVELOPE_MAGIC_BYTES,
  ENVELOPE_FORMAT_VERSION_V1,
  ENVELOPE_HEADER_SIZE,
  ENVELOPE_FIXED_OVERHEAD_BYTES,
  ENVELOPE_AAD_SIZE,
  ENVELOPE_KEY_ID_SIZE,
  ENVELOPE_NONCE_SIZE,
  ENVELOPE_GCM_TAG_SIZE,
  ENVELOPE_OFFSET_CIPHERTEXT,
  ENVELOPE_OFFSET_CIPHERTEXT_LENGTH,
  EnvelopeHeader,
  EnvelopePurpose,
  GhostTagEnvelope,
  SerializedEnvelope,
} from '../contracts/envelope';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';

/**
 * Result of envelope structural validation.
 */
export interface ValidationResult {
  /** Whether the envelope data passes all format and length checks. */
  readonly isValid: boolean;
  /** Alias for isValid for ergonomic compatibility. */
  readonly valid: boolean;
  /** Human-readable explanation if validation failed. */
  readonly error?: string;
  /** Typed error code if validation failed. */
  readonly errorCode?: GhostTagErrorCode;
  /** Diagnostic detail. */
  readonly details?: string;
}

/**
 * Constructs the canonical 26-byte Additional Authenticated Data (AAD) for AES-256-GCM.
 *
 * Layout:
 * MAGIC (4B) || FORMAT_VERSION (1B) || PURPOSE (1B) || KEY_ID (16B) || CIPHERTEXT_LENGTH (4B LE)
 *
 * Supports both positional parameters and a partial EnvelopeHeader object.
 *
 * @param versionOrHeader Format version byte OR an object with { formatVersion, purpose, keyId, ciphertextLength }
 * @param purpose Optional purpose flag byte (when using positional parameters)
 * @param keyId Optional 16-byte key identifier (when using positional parameters)
 * @param ciphertextLength Optional uint32 payload byte count (when using positional parameters)
 * @returns 26-byte AAD Uint8Array.
 */
export function constructAAD(
  versionOrHeader:
    | number
    | Pick<EnvelopeHeader, 'formatVersion' | 'purpose' | 'keyId' | 'ciphertextLength'>,
  purpose?: number,
  keyId?: Uint8Array,
  ciphertextLength?: number
): Uint8Array {
  let version: number;
  let p: number;
  let kid: Uint8Array;
  let ctLen: number;

  if (typeof versionOrHeader === 'object' && versionOrHeader !== null) {
    version = versionOrHeader.formatVersion;
    p = versionOrHeader.purpose;
    kid = versionOrHeader.keyId;
    ctLen = versionOrHeader.ciphertextLength;
  } else {
    version = versionOrHeader as number;
    p = purpose!;
    kid = keyId!;
    ctLen = ciphertextLength!;
  }

  if (!kid || kid.length !== ENVELOPE_KEY_ID_SIZE) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Invalid keyId length for AAD: expected ${ENVELOPE_KEY_ID_SIZE} bytes, got ${kid?.length ?? 0}.`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const aad = new Uint8Array(ENVELOPE_AAD_SIZE);
  aad.set(ENVELOPE_MAGIC_BYTES, 0);
  aad[4] = version & 0xff;
  aad[5] = p & 0xff;
  aad.set(kid, 6);

  const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
  view.setUint32(22, ctLen, true); // Little-Endian 32-bit unsigned int

  return aad;
}

/**
 * Validates the raw binary byte layout of a candidate envelope before parsing.
 *
 * Checks:
 * 1. Non-null Uint8Array
 * 2. Minimum length >= 54 bytes (ENVELOPE_FIXED_OVERHEAD_BYTES)
 * 3. Magic identifier matches ASCII "GTAG" ([0x47, 0x54, 0x41, 0x47])
 * 4. Format version is supported (0x01)
 * 5. Declared ciphertext length matches actual payload buffer length exactly (rejects truncated or oversized envelopes)
 *
 * @param data Raw byte array from NFC tag.
 * @returns ValidationResult with isValid status and optional diagnostic error code.
 */
export function validateEnvelope(data: Uint8Array): ValidationResult {
  if (!data || !(data instanceof Uint8Array)) {
    return {
      isValid: false,
      valid: false,
      errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
      error: 'Envelope payload must be a non-null Uint8Array.',
    };
  }

  if (data.length < ENVELOPE_FIXED_OVERHEAD_BYTES) {
    return {
      isValid: false,
      valid: false,
      errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
      error: `Envelope truncated: received ${data.length} bytes, minimum overhead is ${ENVELOPE_FIXED_OVERHEAD_BYTES} bytes.`,
    };
  }

  for (let i = 0; i < ENVELOPE_MAGIC_BYTES.length; i++) {
    if (data[i] !== ENVELOPE_MAGIC_BYTES[i]) {
      return {
        isValid: false,
        valid: false,
        errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
        error: `Invalid envelope magic header: expected ASCII "${ENVELOPE_MAGIC}".`,
      };
    }
  }

  const version = data[4];
  if (version !== ENVELOPE_FORMAT_VERSION_V1) {
    return {
      isValid: false,
      valid: false,
      errorCode: GhostTagErrorCode.UNSUPPORTED_VERSION,
      error: `Unsupported envelope format version: 0x${version.toString(16)}.`,
    };
  }

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const declaredCiphertextLength = view.getUint32(
    ENVELOPE_OFFSET_CIPHERTEXT_LENGTH,
    true
  );
  const expectedTotalBytes =
    ENVELOPE_FIXED_OVERHEAD_BYTES + declaredCiphertextLength;

  if (data.length < expectedTotalBytes) {
    return {
      isValid: false,
      valid: false,
      errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
      error: `Envelope truncated: declared payload requires ${expectedTotalBytes} bytes, found ${data.length} bytes.`,
    };
  }

  if (data.length > expectedTotalBytes) {
    return {
      isValid: false,
      valid: false,
      errorCode: GhostTagErrorCode.INVALID_ENVELOPE,
      error: `Envelope oversized: declared payload requires ${expectedTotalBytes} bytes, found ${data.length} bytes (trailing data rejected).`,
    };
  }

  return {
    isValid: true,
    valid: true,
  };
}

/**
 * Serializes a structured GhostTagEnvelope into canonical binary Little-Endian format.
 *
 * @param envelope Complete GhostTagEnvelope instance.
 * @returns Serialized byte array ready for tag writing.
 * @throws {GhostTagError} If envelope properties fail layout constraints.
 */
export function serializeEnvelope(envelope: GhostTagEnvelope): Uint8Array {
  if (!envelope || !envelope.header) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: 'Cannot serialize null or invalid envelope structure.',
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const { header, ciphertext, gcmTag } = envelope;

  if (header.formatVersion !== ENVELOPE_FORMAT_VERSION_V1) {
    throw new GhostTagError({
      code: GhostTagErrorCode.UNSUPPORTED_VERSION,
      userMessage: `Cannot serialize unsupported envelope format version: 0x${header.formatVersion.toString(16)}.`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (!header.keyId || header.keyId.length !== ENVELOPE_KEY_ID_SIZE) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Header keyId must be ${ENVELOPE_KEY_ID_SIZE} bytes.`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (!header.nonce || header.nonce.length !== ENVELOPE_NONCE_SIZE) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Header nonce must be ${ENVELOPE_NONCE_SIZE} bytes.`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (header.ciphertextLength !== ciphertext.length) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `Header declared ciphertext length (${header.ciphertextLength}) does not match ciphertext byte length (${ciphertext.length}).`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  if (!gcmTag || gcmTag.length !== ENVELOPE_GCM_TAG_SIZE) {
    throw new GhostTagError({
      code: GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: `GCM authentication tag must be ${ENVELOPE_GCM_TAG_SIZE} bytes.`,
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const totalLength = ENVELOPE_FIXED_OVERHEAD_BYTES + ciphertext.length;
  const out = new Uint8Array(totalLength);

  // 00..03: MAGIC
  out.set(ENVELOPE_MAGIC_BYTES, 0);
  // 04: FORMAT_VERSION
  out[4] = header.formatVersion;
  // 05: PURPOSE
  out[5] = header.purpose;
  // 06..21: KEY_ID (16 bytes)
  out.set(header.keyId, 6);
  // 22..33: NONCE (12 bytes)
  out.set(header.nonce, 22);

  // 34..37: CIPHERTEXT_LENGTH (uint32 Little-Endian)
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint32(ENVELOPE_OFFSET_CIPHERTEXT_LENGTH, ciphertext.length, true);

  // 38..N-17: CIPHERTEXT
  out.set(ciphertext, ENVELOPE_OFFSET_CIPHERTEXT);

  // N-16..N-1: GCM_TAG (16 bytes)
  out.set(gcmTag, ENVELOPE_OFFSET_CIPHERTEXT + ciphertext.length);

  return out as SerializedEnvelope;
}

/**
 * Parses a raw binary byte array into a structured GhostTagEnvelope.
 *
 * Enforces strict validation:
 * - Rejects truncated data
 * - Rejects oversized data (trailing bytes)
 * - Rejects invalid magic identifier
 * - Rejects unsupported versions
 *
 * @param data Raw byte array from NFC tag.
 * @returns Structured GhostTagEnvelope.
 * @throws {GhostTagError} If data is malformed or invalid.
 */
export function parseEnvelope(data: Uint8Array): GhostTagEnvelope {
  const validation = validateEnvelope(data);
  if (!validation.isValid) {
    throw new GhostTagError({
      code: validation.errorCode ?? GhostTagErrorCode.INVALID_ENVELOPE,
      userMessage: validation.error ?? 'Envelope parsing failed.',
      category: ErrorCategory.ENVELOPE,
      severity: ErrorSeverity.ERROR,
    });
  }

  const formatVersion = data[4];
  const purpose = data[5] as EnvelopePurpose;

  // Defensive copies of byte ranges to avoid shared mutability
  const keyId = new Uint8Array(data.slice(6, 22));
  const nonce = new Uint8Array(data.slice(22, 34));

  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const ciphertextLength = view.getUint32(
    ENVELOPE_OFFSET_CIPHERTEXT_LENGTH,
    true
  );

  const ctStart = ENVELOPE_OFFSET_CIPHERTEXT;
  const ctEnd = ctStart + ciphertextLength;
  const ciphertext = new Uint8Array(data.slice(ctStart, ctEnd));

  const tagStart = ctEnd;
  const tagEnd = tagStart + ENVELOPE_GCM_TAG_SIZE;
  const gcmTag = new Uint8Array(data.slice(tagStart, tagEnd));

  const header: EnvelopeHeader = {
    magic: ENVELOPE_MAGIC,
    formatVersion,
    purpose,
    keyId,
    nonce,
    ciphertextLength,
  };

  return {
    header,
    ciphertext,
    gcmTag,
  };
}

