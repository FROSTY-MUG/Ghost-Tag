/**
 * @file envelope.ts
 * @summary Ghost-Tag Binary Envelope Specification.
 *
 * Defines the canonical binary envelope format for encrypted NFC tag payloads.
 * All multi-byte integer fields are encoded in Little-Endian byte order.
 * Fixed envelope overhead is precisely 54 bytes.
 *
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
 * Where N = 38 + CIPHERTEXT_LENGTH + 16. Total overhead = 54 bytes.
 */

/**
 * Envelope magic ASCII string identifying Ghost-Tag binary format.
 */
export const ENVELOPE_MAGIC = 'GTAG' as const;

/**
 * 4-byte ASCII array for "GTAG": [0x47, 0x54, 0x41, 0x47].
 */
export const ENVELOPE_MAGIC_BYTES: readonly number[] = [0x47, 0x54, 0x41, 0x47] as const;

/**
 * Current canonical envelope format version.
 */
export const ENVELOPE_FORMAT_VERSION_V1 = 0x01 as const;

/**
 * Standard NDEF MIME type registered for Ghost-Tag payloads.
 */
export const ENVELOPE_MIME_TYPE = 'application/vnd.ghost.secure' as const;

// ---------------------------------------------------------------------------
// Field Sizes (Bytes)
// ---------------------------------------------------------------------------

/** Size of the magic marker in bytes. */
export const ENVELOPE_MAGIC_SIZE = 4 as const;

/** Size of the format version byte. */
export const ENVELOPE_FORMAT_VERSION_SIZE = 1 as const;

/** Size of the purpose flag byte. */
export const ENVELOPE_PURPOSE_SIZE = 1 as const;

/** Size of the 128-bit DEK identifier in bytes. */
export const ENVELOPE_KEY_ID_SIZE = 16 as const;

/** Size of the standard 96-bit AES-GCM nonce (IV) in bytes. */
export const ENVELOPE_NONCE_SIZE = 12 as const;

/**
 * Size of the payload length header field (uint32 Little-Endian) in bytes.
 * Byte order: Little-Endian (LE).
 */
export const ENVELOPE_CIPHERTEXT_LENGTH_SIZE = 4 as const;

/**
 * Total fixed header size preceding ciphertext in bytes.
 * MAGIC (4) + FORMAT_VERSION (1) + PURPOSE (1) + KEY_ID (16) + NONCE (12) + CIPHERTEXT_LENGTH (4) = 38.
 */
export const ENVELOPE_HEADER_SIZE = 38 as const;

/** Size of the 128-bit AES-256-GCM authentication tag in bytes. */
export const ENVELOPE_GCM_TAG_SIZE = 16 as const;

/**
 * Total fixed envelope overhead in bytes:
 * Header (38 bytes) + GCM Auth Tag (16 bytes) = 54 bytes.
 * Usable tag payload capacity = (Tag Capacity) - 54 bytes.
 */
export const ENVELOPE_FIXED_OVERHEAD_BYTES = 54 as const;

/**
 * Total length of Additional Authenticated Data (AAD) in bytes:
 * MAGIC (4) + FORMAT_VERSION (1) + PURPOSE (1) + KEY_ID (16) + CIPHERTEXT_LENGTH (4) = 26 bytes.
 * Byte order for CIPHERTEXT_LENGTH inside AAD: Little-Endian (LE).
 */
export const ENVELOPE_AAD_SIZE = 26 as const;

// ---------------------------------------------------------------------------
// Byte Offsets
// ---------------------------------------------------------------------------

/** Offset of the 4-byte MAGIC field (bytes 0..3). */
export const ENVELOPE_OFFSET_MAGIC = 0 as const;

/** Offset of the 1-byte FORMAT_VERSION field (byte 4). */
export const ENVELOPE_OFFSET_FORMAT_VERSION = 4 as const;

/** Offset of the 1-byte PURPOSE field (byte 5). */
export const ENVELOPE_OFFSET_PURPOSE = 5 as const;

/** Offset of the 16-byte KEY_ID field (bytes 6..21). */
export const ENVELOPE_OFFSET_KEY_ID = 6 as const;

/** Offset of the 12-byte NONCE field (bytes 22..33). */
export const ENVELOPE_OFFSET_NONCE = 22 as const;

/**
 * Offset of the 4-byte CIPHERTEXT_LENGTH field (bytes 34..37).
 * Encoded as 32-bit unsigned integer, Little-Endian.
 */
export const ENVELOPE_OFFSET_CIPHERTEXT_LENGTH = 34 as const;

/** Offset where the variable-length CIPHERTEXT begins (byte 38). */
export const ENVELOPE_OFFSET_CIPHERTEXT = 38 as const;

// ---------------------------------------------------------------------------
// Purpose Enum
// ---------------------------------------------------------------------------

/**
 * High-level intent / category of the encrypted payload stored in the envelope.
 * Encoded as a single unsigned byte (0x00 - 0xFF).
 */
export enum EnvelopePurpose {
  /** Secure plaintext notes or secret memos. */
  NOTE = 0x01,
  /** Authentication credentials, tokens, or passwords. */
  CREDENTIAL = 0x02,
  /** Device or application configuration profiles. */
  CONFIG = 0x03,
  /** Pointer or metadata linking to a recovery envelope. */
  RECOVERY_POINTER = 0x04,
  /** Physical/digital asset identity or inventory tracking token. */
  ASSET_ID = 0x05,
  /** Custom application-defined payload format. */
  CUSTOM = 0xFF,
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

/**
 * Binary header preceding the ciphertext payload.
 *
 * Security Properties:
 * - Unencrypted, but cryptographically authenticated via AES-256-GCM Additional
 *   Authenticated Data (AAD) covering MAGIC, FORMAT_VERSION, PURPOSE, KEY_ID,
 *   and CIPHERTEXT_LENGTH.
 * - Any unauthorized tampering with header fields will cause GCM authentication tag
 *   verification to fail during decryption, preventing forgery and substitution attacks.
 */
export interface EnvelopeHeader {
  /**
   * 4-byte ASCII magic identifier ("GTAG").
   */
  readonly magic: typeof ENVELOPE_MAGIC;

  /**
   * Version of the binary envelope schema (starts at 0x01).
   */
  readonly formatVersion: number;

  /**
   * Categorical purpose indicator for payload handling.
   */
  readonly purpose: EnvelopePurpose;

  /**
   * 16-byte unique identifier of the Data Encryption Key (DEK) used to encrypt the payload.
   * Enables the decryptor to look up the corresponding wrapped DEK without decrypting the payload.
   */
  readonly keyId: Uint8Array;

  /**
   * 12-byte (96-bit) initialization vector (nonce) for AES-256-GCM.
   * MUST be cryptographically random or monotonically generated and MUST NEVER be repeated
   * with the same key.
   */
  readonly nonce: Uint8Array;

  /**
   * Length in bytes of the variable ciphertext payload.
   * Little-endian unsigned 32-bit integer.
   */
  readonly ciphertextLength: number;
}

/**
 * Structured representation of a decoded Ghost-Tag envelope.
 *
 * Security Properties:
 * - Confidentiality: Ciphertext is encrypted using AES-256 in Galois/Counter Mode (GCM).
 * - Authenticity & Integrity: 128-bit GCM authentication tag guarantees that neither
 *   the header (via AAD) nor the ciphertext has been modified in transit or on tag.
 */
export interface GhostTagEnvelope {
  /**
   * Envelope header containing routing metadata, key identifier, and GCM nonce.
   */
  readonly header: EnvelopeHeader;

  /**
   * Variable-length AES-256-GCM encrypted payload.
   * Length must strictly match header.ciphertextLength.
   */
  readonly ciphertext: Uint8Array;

  /**
   * 16-byte (128-bit) AES-256-GCM authentication tag protecting ciphertext and AAD.
   */
  readonly gcmTag: Uint8Array;
}

/**
 * Raw serialized byte array of a complete Ghost-Tag envelope ready for NDEF writing.
 * Guaranteed to be at least ENVELOPE_FIXED_OVERHEAD_BYTES (54 bytes) in length.
 */
export type SerializedEnvelope = Uint8Array & {
  readonly __brand: unique symbol;
};

// ---------------------------------------------------------------------------
// Additional Authenticated Data (AAD) Specification
// ---------------------------------------------------------------------------

/**
 * Specification for constructing Additional Authenticated Data (AAD) for AES-256-GCM.
 *
 * Construction rule:
 * AAD = MAGIC (4B) || FORMAT_VERSION (1B) || PURPOSE (1B) || KEY_ID (16B) || CIPHERTEXT_LENGTH (4B LE)
 *
 * Total AAD length: 26 bytes.
 * Byte order for CIPHERTEXT_LENGTH: Little-Endian (uint32 LE).
 *
 * Security Rationale:
 * Binding these fields via AAD prevents:
 * 1. Version downgrade attacks.
 * 2. Purpose switching attacks (e.g. interpreting a CONFIG payload as a NOTE).
 * 3. Key ID substitution / cross-key confusion.
 * 4. Ciphertext truncation or extension attacks.
 */
export type ConstructAadFunction = (
  header: Pick<EnvelopeHeader, 'formatVersion' | 'purpose' | 'keyId' | 'ciphertextLength'>
) => Uint8Array;
