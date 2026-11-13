/**
 * @file recovery.ts
 * @summary Ghost-Tag Recovery Envelope Specification.
 *
 * Defines the recovery envelope, 256-bit mnemonic recovery phrase parameters,
 * recovery-wrapped DEKs, and recovery workflow state transitions.
 *
 * All multi-byte integers are serialized in Little-Endian byte order.
 */

import { RecoveryKdfParameters } from './keyHierarchy';

// ---------------------------------------------------------------------------
// Recovery Constants
// ---------------------------------------------------------------------------

/** Length of the raw 256-bit recovery entropy secret in bytes. */
export const RECOVERY_SECRET_BYTE_LENGTH = 32 as const;

/** Entropy length in bits for the recovery phrase (256 bits). */
export const RECOVERY_ENTROPY_BITS = 256 as const;

/** Number of checksum bits appended to entropy in BIP39 format (8 bits). */
export const RECOVERY_CHECKSUM_BITS = 8 as const;

/** Total bit length of encoded recovery sequence (256 + 8 = 264 bits). */
export const RECOVERY_TOTAL_BITS = 264 as const;

/** Bits per word index (11 bits = 2^11 = 2048 words). */
export const RECOVERY_BITS_PER_WORD = 11 as const;

/** Standard word count for the 256-bit recovery phrase (264 / 11 = 24 words). */
export const RECOVERY_PHRASE_WORD_COUNT = 24 as const;

/** Wordlist dictionary size (BIP39 English standard). */
export const RECOVERY_WORDLIST_SIZE = 2048 as const;

/** Length of nonce used in recovery key wrapping (bytes). */
export const RECOVERY_NONCE_BYTE_LENGTH = 12 as const;

/** Length of GCM tag used in recovery key wrapping (bytes). */
export const RECOVERY_TAG_BYTE_LENGTH = 16 as const;

/** Single-byte purpose flag for recovery key wrap AAD: 0x52 (ASCII 'R'). */
export const RECOVERY_KEY_WRAP_PURPOSE_BYTE = 0x52 as const;

// ---------------------------------------------------------------------------
// Recovery Phrase Configuration
// ---------------------------------------------------------------------------

/**
 * Specification and formatting metadata for BIP39-style recovery phrases.
 *
 * Security Properties:
 * - 256-bit cryptographically secure entropy provides ~128 bits of quantum resistance
 *   and full 256-bit classical brute-force resistance.
 * - 8-bit checksum detects typos, transpositions, and invalid words before expensive
 *   Argon2id derivation is triggered.
 */
export interface RecoveryPhraseConfig {
  /** Number of words in the mnemonic phrase (24 words). */
  readonly wordCount: typeof RECOVERY_PHRASE_WORD_COUNT;
  /** Bits of raw entropy encoded in the phrase (256 bits). */
  readonly entropyBits: typeof RECOVERY_ENTROPY_BITS;
  /** Bits of checksum appended to entropy (8 bits). */
  readonly checksumBits: typeof RECOVERY_CHECKSUM_BITS;
  /** Dictionary size (2048 words). */
  readonly wordlistSize: typeof RECOVERY_WORDLIST_SIZE;
}

// ---------------------------------------------------------------------------
// Recovery Flow State Machine
// ---------------------------------------------------------------------------

/**
 * States of the emergency out-of-band recovery workflow.
 */
export enum RecoveryFlowState {
  /** Vault has not configured a recovery envelope. */
  UNINITIALIZED = 'UNINITIALIZED',
  /** Recovery envelope configured; system in normal operational state. */
  IDLE = 'IDLE',
  /** Recovery mode initiated; user prompted for 24-word recovery phrase. */
  PHRASE_REQUESTED = 'PHRASE_REQUESTED',
  /** Words inputted; phrase awaiting syntax and dictionary verification. */
  PHRASE_ENTERED = 'PHRASE_ENTERED',
  /** Checksum calculation and wordlist index validation in progress. */
  PHRASE_VALIDATING = 'PHRASE_VALIDATING',
  /** Argon2id derivation of recovery KEK in progress. */
  KDF_DERIVING = 'KDF_DERIVING',
  /** Attempting to unwrap DEKs using the derived recovery KEK. */
  DECRYPTING_DEKS = 'DECRYPTING_DEKS',
  /** DEKs successfully restored; user prompted to create new master passphrase. */
  RECOVERY_SUCCESSFUL = 'RECOVERY_SUCCESSFUL',
  /** Checksum mismatch, invalid word, or AES-GCM authentication failure. */
  RECOVERY_FAILED = 'RECOVERY_FAILED',
}

// ---------------------------------------------------------------------------
// Recovery Wrapped DEK
// ---------------------------------------------------------------------------

/**
 * Data Encryption Key wrapped under the Recovery KEK.
 *
 * Security Properties:
 * - Encrypted via AES-256-GCM under the Recovery KEK.
 * - Authenticated with AAD = RECOVERY_KEY_WRAP_PURPOSE_BYTE (1B: 0x52) || keyId (16B) || keyVersion (2B LE).
 * - Enables full restoration of all tag DEKs even if the primary master passphrase is lost.
 */
export interface RecoveryWrappedDEK {
  /**
   * 16-byte unique identifier matching the KEY_ID in the binary envelope.
   */
  readonly keyId: string;

  /**
   * 32-byte AES-256-GCM ciphertext of the raw DEK.
   */
  readonly wrappedDEK: Uint8Array;

  /**
   * 12-byte initialization vector (nonce) for AES-256-GCM.
   */
  readonly nonce: Uint8Array;

  /**
   * 16-byte authentication tag verifying ciphertext and AAD.
   */
  readonly tag: Uint8Array;

  /**
   * Monotonically incrementing key version number (Little-Endian uint16).
   */
  readonly keyVersion: number;
}

// ---------------------------------------------------------------------------
// Recovery Envelope
// ---------------------------------------------------------------------------

/**
 * Standalone emergency recovery container embedded in the vault.
 *
 * Security Properties:
 * - Decoupled Cryptographic Path: Uses a distinct 32-byte salt and Argon2id parameters
 *   separate from the primary vault passphrase.
 * - Tamper Evidence: Protected by a 16-byte authentication tag covering recovery manifest metadata.
 * - Zero Leakage: The recovery phrase itself is NEVER stored; only the wrapped DEKs
 *   and derivation parameters are persisted.
 */
export interface RecoveryEnvelope {
  /**
   * Unique UUIDv4 identifier for the recovery configuration.
   */
  readonly recoveryId: string;

  /**
   * 32-byte random salt used exclusively for recovery KEK derivation.
   */
  readonly salt: Uint8Array;

  /**
   * Argon2id parameters configured for recovery key derivation.
   */
  readonly params: RecoveryKdfParameters;

  /**
   * Array of DEKs wrapped under the recovery KEK.
   */
  readonly wrappedDEKs: readonly RecoveryWrappedDEK[];

  /**
   * 16-byte AES-256-GCM verification checksum / auth tag.
   */
  readonly checksum: Uint8Array;

  /**
   * Timestamp when recovery was configured (epoch milliseconds).
   */
  readonly createdAt: number;
}
