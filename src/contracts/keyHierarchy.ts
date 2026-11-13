/**
 * @file keyHierarchy.ts
 * @summary Ghost-Tag Key Hierarchy and Cryptographic Key Management Specification.
 *
 * Defines the two-tier key architecture:
 * 1. Key Encryption Key (KEK): Derived from user master passphrase via Argon2id. Never persisted.
 * 2. Data Encryption Key (DEK): High-entropy 256-bit symmetric key per vault/tag.
 *    Stored strictly in wrapped form (AES-256-GCM authenticated ciphertext).
 *
 * All multi-byte integers are serialized in Little-Endian byte order.
 */

// ---------------------------------------------------------------------------
// Cryptographic Size Constants (Bytes)
// ---------------------------------------------------------------------------

/** Length of 256-bit Key Encryption Key (KEK) in bytes. */
export const KEK_BYTE_LENGTH = 32 as const;

/** Length of 256-bit Data Encryption Key (DEK) in bytes. */
export const DEK_BYTE_LENGTH = 32 as const;

/** Length of salt used for primary Argon2id KEK derivation in bytes. */
export const PRIMARY_KDF_SALT_BYTE_LENGTH = 16 as const;

/** Length of salt used for recovery Argon2id KEK derivation in bytes. */
export const RECOVERY_KDF_SALT_BYTE_LENGTH = 32 as const;

/** Length of AES-256-GCM initialization vector (nonce) for key wrapping in bytes. */
export const KEY_WRAP_NONCE_BYTE_LENGTH = 12 as const;

/** Length of AES-256-GCM authentication tag for key wrapping in bytes. */
export const KEY_WRAP_TAG_BYTE_LENGTH = 16 as const;

/** Length of the canonical DEK identifier in bytes (128-bit GUID/random bytes). */
export const KEY_ID_BYTE_LENGTH = 16 as const;

/** Single-byte domain separation purpose indicator for key wrapping AAD: 0x57 (ASCII 'W'). */
export const KEY_WRAP_PURPOSE_BYTE = 0x57 as const;

/** Size of the KDF version field in key wrap AAD (uint16 Little-Endian). */
export const KEY_WRAP_KDF_VERSION_SIZE = 2 as const;

/**
 * Total AAD length for DEK wrapping in bytes:
 * KEY_WRAP_PURPOSE (1B) + KEY_ID (16B) + KDF_VERSION (2B LE) = 19 bytes.
 */
export const KEY_WRAP_AAD_BYTE_LENGTH = 19 as const;

// ---------------------------------------------------------------------------
// Device Hardware Tiers & KDF Defaults
// ---------------------------------------------------------------------------

/**
 * Device compute tier for configuring Argon2id resistance against brute-force attacks
 * while maintaining acceptable user unlock latency (<1.5s on target hardware).
 */
export enum DeviceTier {
  /** Flagship mobile devices and desktop computers. */
  HIGH_END = 'HIGH_END',
  /** Standard mid-range mobile devices. */
  STANDARD = 'STANDARD',
  /** Resource-constrained mobile devices or older hardware. */
  LOW_END = 'LOW_END',
}

/**
 * Parameters for Argon2id Key Derivation Function (RFC 9106).
 *
 * Security Properties:
 * - Argon2id provides hybrid defense against GPU-accelerated brute force (side-channel
 *   resistant data-independent memory passes combined with memory-hard data-dependent passes).
 * - Parameters are permanently recorded in the vault manifest to ensure deterministic
 *   re-derivation regardless of future hardware tier changes.
 */
export interface KdfParameters {
  /**
   * 16-byte cryptographically secure random salt.
   */
  readonly salt: Uint8Array;

  /**
   * Memory size in KiB (kibibytes).
   */
  readonly memoryCost: number;

  /**
   * Number of iterations (time cost / passes).
   */
  readonly timeCost: number;

  /**
   * Degree of parallelism (number of concurrent threads/lanes).
   */
  readonly parallelism: number;

  /**
   * Argon2 algorithm version identifier (0x13 for Argon2 v1.3).
   * Little-endian unsigned 16-bit integer when serialized.
   */
  readonly version: number;
}

/**
 * Baseline Argon2id parameter profiles tuned for user unlock latency vs resistance.
 */
export const DEFAULT_KDF_PARAMETERS_BY_TIER: Readonly<Record<DeviceTier, Omit<KdfParameters, 'salt'>>> = {
  [DeviceTier.HIGH_END]: {
    memoryCost: 65536, // 64 MiB
    timeCost: 4,
    parallelism: 4,
    version: 0x13,
  },
  [DeviceTier.STANDARD]: {
    memoryCost: 32768, // 32 MiB
    timeCost: 3,
    parallelism: 2,
    version: 0x13,
  },
  [DeviceTier.LOW_END]: {
    memoryCost: 16384, // 16 MiB
    timeCost: 2,
    parallelism: 1,
    version: 0x13,
  },
} as const;

// ---------------------------------------------------------------------------
// Recovery KDF Parameters
// ---------------------------------------------------------------------------

/**
 * Parameters for deriving the Recovery KEK from a 256-bit recovery secret or mnemonic phrase.
 *
 * Security Properties:
 * - MUST use a distinct, dedicated 32-byte salt completely isolated from the primary vault salt.
 * - Higher time/memory cost may be tolerated since recovery is a rare administrative event.
 */
export interface RecoveryKdfParameters {
  /**
   * 32-byte cryptographically secure random salt dedicated to recovery.
   */
  readonly salt: Uint8Array;

  /**
   * Memory size in KiB.
   */
  readonly memoryCost: number;

  /**
   * Iteration count.
   */
  readonly timeCost: number;

  /**
   * Parallel threads.
   */
  readonly parallelism: number;

  /**
   * Argon2 version (0x13).
   */
  readonly version: number;
}

/**
 * Default parameters for recovery key derivation.
 */
export const DEFAULT_RECOVERY_KDF_CONFIG: Omit<RecoveryKdfParameters, 'salt'> = {
  memoryCost: 65536, // 64 MiB
  timeCost: 5,
  parallelism: 4,
  version: 0x13,
} as const;

// ---------------------------------------------------------------------------
// Key Status & Wrapped DEK
// ---------------------------------------------------------------------------

/**
 * Lifecycle state of a Data Encryption Key.
 */
export enum KeyStatus {
  /** Active for both encrypting new tag payloads and decrypting existing tags. */
  ACTIVE = 'ACTIVE',
  /** Retained for decrypting historical tags, but forbidden for new tag writes. */
  ROTATED = 'ROTATED',
  /** Permanently disabled; decryption attempts will be rejected. */
  REVOKED = 'REVOKED',
}

/**
 * Encrypted Data Encryption Key stored at rest in the vault.
 *
 * Security Properties:
 * - The raw 256-bit DEK is encrypted using AES-256-GCM under the ephemeral KEK.
 * - Authenticated with AAD = KEY_WRAP_PURPOSE (1B) || keyId (16B) || kdfVersion (2B LE).
 * - A compromised or stolen vault file never exposes plaintext DEKs without KEK recovery.
 * - Key wrapping prevents cut-and-paste key substitution attacks across vault entries.
 */
export interface WrappedDEK {
  /**
   * 16-byte unique identifier matching the KEY_ID field in Ghost-Tag binary envelopes.
   * Can be formatted as a 32-character hexadecimal string or 16 raw bytes.
   */
  readonly keyId: string;

  /**
   * 32-byte ciphertext of the raw DEK encrypted via AES-256-GCM under the KEK.
   */
  readonly wrappedCiphertext: Uint8Array;

  /**
   * 12-byte (96-bit) AES-GCM nonce used during the wrapping operation.
   * MUST NEVER be reused under the same KEK.
   */
  readonly nonce: Uint8Array;

  /**
   * 16-byte (128-bit) AES-GCM authentication tag validating wrapped DEK and AAD.
   */
  readonly tag: Uint8Array;

  /**
   * Epoch timestamp in milliseconds when this DEK was generated.
   */
  readonly creationTime: number;

  /**
   * Monotonically incrementing key version number.
   * Serialized as Little-Endian unsigned integer.
   */
  readonly keyVersion: number;

  /**
   * Operational status of the key.
   */
  readonly status: KeyStatus;
}

// ---------------------------------------------------------------------------
// Key Wrap AAD Function Signature
// ---------------------------------------------------------------------------

/**
 * Signature for constructing AAD passed to AES-256-GCM key wrapping.
 *
 * Format:
 * KEY_WRAP_PURPOSE (1B: 0x57) || KEY_ID (16B raw) || KDF_VERSION (2B Little-Endian)
 */
export type ConstructKeyWrapAadFunction = (
  keyId: Uint8Array,
  kdfVersion: number
) => Uint8Array;
