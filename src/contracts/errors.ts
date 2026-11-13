/**
 * @file errors.ts
 * @summary Ghost-Tag Error Code Registry and Error Classes.
 *
 * Defines the canonical set of error codes, error categories, severity tiers,
 * and the primary `GhostTagError` exception class.
 */

// ---------------------------------------------------------------------------
// Error Categories and Severity
// ---------------------------------------------------------------------------

/**
 * Functional subsystem category where the error originated.
 */
export enum ErrorCategory {
  /** Hardware NFC transceiver or controller errors. */
  NFC = 'NFC',
  /** Cryptographic primitives, KDF, or cipher operations. */
  CRYPTO = 'CRYPTO',
  /** Vault storage, metadata integrity, or key wrapping errors. */
  VAULT = 'VAULT',
  /** Binary envelope layout, parsing, or serialization errors. */
  ENVELOPE = 'ENVELOPE',
  /** Higher-level application lifecycle, scan/write, or user operations. */
  OPERATION = 'OPERATION',
  /** Hardware integrity, anti-tampering, anti-debugging, or reverse-engineering violations. */
  SECURITY = 'SECURITY',
}

/**
 * Severity tier indicating the impact on system security and operational state.
 */
export enum ErrorSeverity {
  /** Informational diagnostic event; operational state unchanged. */
  INFO = 'INFO',
  /** Transient or non-fatal anomaly; retry or user adjustment possible. */
  WARNING = 'WARNING',
  /** Operation failed; session intact, tag or vault data unharmed. */
  ERROR = 'ERROR',
  /** Potential security breach or data integrity violation; session may require abort. */
  CRITICAL = 'CRITICAL',
  /** Unrecoverable vault corruption or fatal hardware/subsystem failure. */
  FATAL = 'FATAL',
}

// ---------------------------------------------------------------------------
// Canonical Error Codes
// ---------------------------------------------------------------------------

/**
 * Exhaustive registry of error codes across the Ghost-Tag system.
 * Defined as a const enum with string values for compile-time safety and runtime serialization.
 */
export const enum GhostTagErrorCode {
  /** Host device NFC controller is turned off in operating system settings. */
  NFC_DISABLED = 'NFC_DISABLED',

  /** Host device does not possess NFC hardware or required Type 2 Tag capabilities. */
  NFC_UNSUPPORTED = 'NFC_UNSUPPORTED',

  /** No compatible NFC tag discovered within the antenna RF field. */
  TAG_NOT_DETECTED = 'TAG_NOT_DETECTED',

  /** RF communication link with the tag was terminated prematurely during an active operation. */
  TAG_LOST = 'TAG_LOST',

  /** Detected tag hardware is not an allowed Type 2 Tag family (e.g. MIFARE Classic). */
  TAG_UNSUPPORTED = 'TAG_UNSUPPORTED',

  /** Tag does not contain a valid NDEF container or records. */
  TAG_NOT_NDEF = 'TAG_NOT_NDEF',

  /** Tag has hardware static or dynamic lock bits set, preventing write operations. */
  TAG_READ_ONLY = 'TAG_READ_ONLY',

  /** Tag is protected by a vendor password or lock command that has not been satisfied. */
  TAG_LOCKED = 'TAG_LOCKED',

  /** Usable memory of the detected tag is smaller than the required envelope overhead (54B). */
  TAG_CAPACITY_INSUFFICIENT = 'TAG_CAPACITY_INSUFFICIENT',

  /** Plaintext payload exceeds maximum capacity of the tag after accounting for 54B overhead. */
  PAYLOAD_TOO_LARGE = 'PAYLOAD_TOO_LARGE',

  /** Binary data on tag fails envelope layout validation (bad magic, truncated fields). */
  INVALID_ENVELOPE = 'INVALID_ENVELOPE',

  /** Envelope format version is not supported by this version of Ghost-Tag. */
  UNSUPPORTED_VERSION = 'UNSUPPORTED_VERSION',

  /** Key identifier in envelope does not match any active or rotated DEK in the vault. */
  KEY_NOT_FOUND = 'KEY_NOT_FOUND',

  /** DEK exists in vault but cannot be unwrapped because the vault is currently locked. */
  KEY_UNAVAILABLE = 'KEY_UNAVAILABLE',

  /** Vault is locked and requires user master passphrase entry before proceeding. */
  PASSPHRASE_REQUIRED = 'PASSPHRASE_REQUIRED',

  /** Provided master passphrase failed to decrypt vault manifest / KEK verification. */
  PASSPHRASE_INVALID = 'PASSPHRASE_INVALID',

  /** Argon2id key derivation failed due to memory allocation or worker thread error. */
  ARGON2ID_FAILED = 'ARGON2ID_FAILED',

  /** AES-256-GCM authentication tag verification failed; payload or AAD tampered with. */
  GCM_AUTH_FAILED = 'GCM_AUTH_FAILED',

  /** Generic write failure encountered during tag transmission. */
  WRITE_FAILED = 'WRITE_FAILED',

  /** Tag write completed without low-level transport error, but read-back verification failed. */
  WRITE_UNVERIFIED = 'WRITE_UNVERIFIED',

  /** Partial tag wipe occurred: some sectors cleared, but operation failed before full erase. */
  WIPE_PARTIAL = 'WIPE_PARTIAL',

  /** Vault metadata or manifest signature corrupted; structural invariant violated. */
  VAULT_CORRUPT = 'VAULT_CORRUPT',

  /** Provided recovery phrase or recovery envelope failed authentication or checksum. */
  RECOVERY_INVALID = 'RECOVERY_INVALID',

  /** Low-level command error executing write sectors on NFC tag. */
  TAG_WRITE_FAILED = 'TAG_WRITE_FAILED',

  /** Read-back verification byte comparison did not match written envelope data. */
  TAG_WRITE_UNVERIFIED = 'TAG_WRITE_UNVERIFIED',

  /** Tag is blank or formatted with a proprietary non-NDEF structure. */
  TAG_NOT_NDEF_FORMATTED = 'TAG_NOT_NDEF_FORMATTED',

  /** Tag has already received a chunk during the current bulk write session. */
  CHUNK_ALREADY_WRITTEN = 'CHUNK_ALREADY_WRITTEN',

  /** Chunk envelope failed cryptographic authentication, framing, or parsing. */
  CHUNK_CORRUPT = 'CHUNK_CORRUPT',

  /** Chunk with identical global index has already been cached in this scan session. */
  CHUNK_ALREADY_CACHED = 'CHUNK_ALREADY_CACHED',

  /** Scanned chunk envelope belongs to a different vault identifier than current session. */
  CHUNK_WRONG_VAULT = 'CHUNK_WRONG_VAULT',

  /** Chunk index exceeds declared total chunks or violates monotonic bounds. */
  CHUNK_INDEX_INVALID = 'CHUNK_INDEX_INVALID',

  /** SHA-256 digest of decrypted or cached chunk ciphertext does not match envelope header. */
  CHUNK_HASH_MISMATCH = 'CHUNK_HASH_MISMATCH',

  /** SHA-256 digest of reassembled full-file ciphertext does not match vault manifest. */
  FILE_HASH_MISMATCH = 'FILE_HASH_MISMATCH',

  /** Cached chunk records have exceeded the 72-hour time-to-live and were purged. */
  CACHE_EXPIRED = 'CACHE_EXPIRED',

  /** Insufficient valid chunks collected to complete reconstruction or Reed-Solomon decode. */
  INSUFFICIENT_CHUNKS = 'INSUFFICIENT_CHUNKS',

  /** Extra tags beyond required count were excluded from write session. */
  EXTRA_TAGS_EXCLUDED = 'EXTRA_TAGS_EXCLUDED',

  /** Host device integrity check failed; environment is compromised or untrusted. */
  DEVICE_INTEGRITY_COMPROMISED = 'DEVICE_INTEGRITY_COMPROMISED',

  /** Active native or runtime debugger detected attaching to the process. */
  DEBUGGER_DETECTED = 'DEBUGGER_DETECTED',

  /** Dynamic instrumentation or hooking framework (Frida, Xposed, Substrate) detected. */
  HOOKING_DETECTED = 'HOOKING_DETECTED',

  /** Elevated privileges, su binary, or root management tools detected on device. */
  ROOT_DETECTED = 'ROOT_DETECTED',

  /** Code tampering, signature mismatch, or unauthorized binary modification detected. */
  TAMPERING_DETECTED = 'TAMPERING_DETECTED',
}

// ---------------------------------------------------------------------------
// Error Class
// ---------------------------------------------------------------------------

/**
 * Error configuration descriptor passed during error construction.
 */
export interface GhostTagErrorOptions {
  /** Technical error code from the canonical registry. */
  readonly code: GhostTagErrorCode;
  /** Human-readable message suitable for display in end-user interfaces. */
  readonly userMessage: string;
  /** Technical diagnostic detail (never include sensitive keys or passphrases). */
  readonly technicalDetail?: string;
  /** Subsystem category responsible for this error. */
  readonly category: ErrorCategory;
  /** Operational severity tier. */
  readonly severity: ErrorSeverity;
  /** Underlying cause or nested exception, if applicable. */
  readonly cause?: unknown;
}

/**
 * Primary exception class for all Ghost-Tag runtime and contract errors.
 *
 * Security Properties:
 * - Sanitized Messages: `userMessage` must never contain cryptographic secrets, key material,
 *   or user passwords.
 * - Categorization: Enables defensive state-machine unwinding and immediate sanitization
 *   upon encountering CRITICAL or FATAL errors (such as zeroing session memory on auth failure).
 */
export class GhostTagError extends Error {
  /**
   * Technical error code.
   */
  public readonly code: GhostTagErrorCode;

  /**
   * User-facing localized message.
   */
  public readonly userMessage: string;

  /**
   * Diagnostic details for logging and debugging.
   * MUST NEVER contain plaintext keys, passphrases, or plain payloads.
   */
  public readonly technicalDetail?: string;

  /**
   * Subsystem origin.
   */
  public readonly category: ErrorCategory;

  /**
   * Impact severity tier.
   */
  public readonly severity: ErrorSeverity;

  constructor(options: GhostTagErrorOptions) {
    super(options.userMessage);
    this.name = 'GhostTagError';
    this.code = options.code;
    this.userMessage = options.userMessage;
    this.technicalDetail = options.technicalDetail;
    this.category = options.category;
    this.severity = options.severity;

    // Attach cause if supported in runtime environment
    if (options.cause !== undefined) {
      (this as { cause?: unknown }).cause = options.cause;
    }

    // Maintain proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, GhostTagError.prototype);
  }
}
