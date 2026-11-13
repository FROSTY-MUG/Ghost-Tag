/**
 * @file states.ts
 * @summary Ghost-Tag Operation State Machine Specifications.
 *
 * Defines explicit finite state machine (FSM) states, events, and contexts
 * for NFC tag scanning, writing, and secure sanitization (wiping).
 *
 * Security Properties:
 * - Deterministic Transitions: Unhandled errors transition immediately to terminal failure states.
 * - Anti-Tear Write Verification: The write state machine mandates an independent read-back
 *   and byte-by-byte comparison phase before declaring success.
 * - Multi-Pass Wipe: Overwrite passes ensure physical bit-level remanence mitigation
 *   followed by empty NDEF structure restoration.
 */

import { GhostTagEnvelope } from './envelope';
import { GhostTagErrorCode } from './errors';
import { SupportedTagFamily, TagInfo } from './tags';

// ---------------------------------------------------------------------------
// Scan State Machine
// ---------------------------------------------------------------------------

/**
 * Progression states for scanning and decrypting an encrypted Ghost-Tag envelope.
 *
 * Flow:
 * IDLE -> TAG_DETECTED -> TECHNOLOGY_IDENTIFIED -> NDEF_READING -> NDEF_READ_COMPLETE
 *      -> ENVELOPE_PARSING -> KEY_RESOLVING -> DECRYPTING -> VERIFIED -> DISPLAYING
 */
export enum ScanState {
  /** RF receiver listening; no tag present. */
  IDLE = 'IDLE',
  /** Tag entered antenna RF field; polling response received. */
  TAG_DETECTED = 'TAG_DETECTED',
  /** ISO 14443-3A / Type 2 Tag technology confirmed. */
  TECHNOLOGY_IDENTIFIED = 'TECHNOLOGY_IDENTIFIED',
  /** Reading NDEF message blocks across tag memory pages. */
  NDEF_READING = 'NDEF_READING',
  /** Raw NDEF payload successfully retrieved into buffer. */
  NDEF_READ_COMPLETE = 'NDEF_READ_COMPLETE',
  /** Validating binary envelope layout, magic bytes, and AAD boundaries. */
  ENVELOPE_PARSING = 'ENVELOPE_PARSING',
  /** Looking up keyId in vault wrapped DEK table. */
  KEY_RESOLVING = 'KEY_RESOLVING',
  /** Unwrapping DEK (if locked) and decrypting ciphertext with AES-256-GCM. */
  DECRYPTING = 'DECRYPTING',
  /** AES-256-GCM authentication tag verified; integrity confirmed. */
  VERIFIED = 'VERIFIED',
  /** Plaintext payload rendered to secure display buffer. */
  DISPLAYING = 'DISPLAYING',
  /** Error encountered during scan; terminal state. */
  ERROR = 'ERROR',
  /** Operation cancelled by user or timeout; terminal state. */
  CANCELLED = 'CANCELLED',
}

/**
 * Operational context maintained across the scan lifecycle.
 */
export interface ScanContext {
  /** Current state of the scan state machine. */
  readonly state: ScanState;
  /** Diagnostic information regarding the detected tag. */
  readonly tagInfo?: TagInfo;
  /** Raw bytes read from the tag's NDEF record. */
  readonly rawNdefBytes?: Uint8Array;
  /** Parsed binary envelope structure. */
  readonly envelope?: GhostTagEnvelope;
  /** 16-byte hex identifier of the resolved key. */
  readonly resolvedKeyId?: string;
  /** Decrypted plaintext payload (ephemeral; cleared on display exit). */
  readonly decryptedPayload?: Uint8Array;
  /** Error code if state transitioned to ERROR. */
  readonly errorCode?: GhostTagErrorCode;
}

// ---------------------------------------------------------------------------
// Write State Machine
// ---------------------------------------------------------------------------

/**
 * Progression states for encrypting and committing a payload to an NFC tag.
 *
 * Flow:
 * IDLE -> TAG_DETECTED -> CAPACITY_CHECKED -> ENVELOPE_PREPARED -> WRITE_IN_PROGRESS
 *      -> WRITE_COMPLETE -> READ_BACK_IN_PROGRESS -> [WRITE_VERIFIED | WRITE_FAILED | WRITE_UNVERIFIED]
 */
export enum WriteState {
  /** Awaiting user write command and tag tap. */
  IDLE = 'IDLE',
  /** Tag entered antenna RF field. */
  TAG_DETECTED = 'TAG_DETECTED',
  /** Tag capacity validated against plaintext length + 54B overhead. */
  CAPACITY_CHECKED = 'CAPACITY_CHECKED',
  /** AES-256-GCM encryption performed; binary envelope constructed. */
  ENVELOPE_PREPARED = 'ENVELOPE_PREPARED',
  /** Transmitting 4-byte page writes over NFC RF link. */
  WRITE_IN_PROGRESS = 'WRITE_IN_PROGRESS',
  /** All pages written to tag memory. */
  WRITE_COMPLETE = 'WRITE_COMPLETE',
  /** Reading back all pages from tag to verify against source buffer. */
  READ_BACK_IN_PROGRESS = 'READ_BACK_IN_PROGRESS',
  /** Read-back bytes match exactly; write confirmed and authenticated. */
  WRITE_VERIFIED = 'WRITE_VERIFIED',
  /** Low-level transmission error or RF tear during write. */
  WRITE_FAILED = 'WRITE_FAILED',
  /** Write finished but read-back comparison detected corrupted/mismatched bytes. */
  WRITE_UNVERIFIED = 'WRITE_UNVERIFIED',
}

/**
 * Operational context maintained across the write lifecycle.
 */
export interface WriteContext {
  /** Current state of the write state machine. */
  readonly state: WriteState;
  /** Target tag hardware metadata. */
  readonly tagInfo?: TagInfo;
  /** Target key identifier used for DEK encryption. */
  readonly targetKeyId?: string;
  /** Total byte count of the serialized envelope to be written. */
  readonly envelopeByteLength?: number;
  /** Current write progress percentage (0 - 100). */
  readonly progressPercent?: number;
  /** Error code if state transitioned to WRITE_FAILED or WRITE_UNVERIFIED. */
  readonly errorCode?: GhostTagErrorCode;
}

// ---------------------------------------------------------------------------
// Wipe State Machine
// ---------------------------------------------------------------------------

/**
 * Multi-pass secure erasure workflow states for sanitizing an NFC tag.
 *
 * Flow:
 * IDLE -> TAG_DETECTED -> AUTHENTICATING -> OVERWRITE_PASS1_ZEROS
 *      -> OVERWRITE_PASS2_RANDOM -> OVERWRITE_PASS3_NDEF_EMPTY -> READ_BACK_VERIFY
 *      -> [WIPE_COMPLETE | WIPE_PARTIAL | WIPE_FAILED]
 */
export enum WipeState {
  /** Ready to initiate wipe operation. */
  IDLE = 'IDLE',
  /** Tag detected for sanitization. */
  TAG_DETECTED = 'TAG_DETECTED',
  /** Unlocking tag password/auth sectors if applicable. */
  AUTHENTICATING = 'AUTHENTICATING',
  /** Overwrite Pass 1: Writing all user memory pages with 0x00 bytes. */
  OVERWRITE_PASS1_ZEROS = 'OVERWRITE_PASS1_ZEROS',
  /** Overwrite Pass 2: Writing all user memory pages with cryptographically random bytes. */
  OVERWRITE_PASS2_RANDOM = 'OVERWRITE_PASS2_RANDOM',
  /** Overwrite Pass 3: Formatting user pages with a blank, empty NDEF container. */
  OVERWRITE_PASS3_NDEF_EMPTY = 'OVERWRITE_PASS3_NDEF_EMPTY',
  /** Verification Pass: Reading back memory to confirm complete sanitization. */
  READ_BACK_VERIFY = 'READ_BACK_VERIFY',
  /** Sanitization successful: all passes verified. */
  WIPE_COMPLETE = 'WIPE_COMPLETE',
  /** Partial wipe: operation interrupted midway; tag in inconsistent state. */
  WIPE_PARTIAL = 'WIPE_PARTIAL',
  /** Sanitization failed: write rejected or locked tag. */
  WIPE_FAILED = 'WIPE_FAILED',
}

/**
 * Operational context maintained across the wipe lifecycle.
 */
export interface WipeContext {
  /** Current state of the wipe state machine. */
  readonly state: WipeState;
  /** Target tag metadata. */
  readonly tagInfo?: TagInfo;
  /** Currently executing sanitization pass (1, 2, or 3). */
  readonly currentPass?: number;
  /** Total user pages to sanitize. */
  readonly totalPages?: number;
  /** Pages completed in the current pass. */
  readonly pagesCompleted?: number;
  /** Error code if wipe failed or was partial. */
  readonly errorCode?: GhostTagErrorCode;
}

// ---------------------------------------------------------------------------
// State Machine Transition Contracts
// ---------------------------------------------------------------------------

/** Generic transition function signature for state machines. */
export type StateTransition<TState, TEvent, TContext> = (
  currentState: TState,
  event: TEvent,
  context: TContext
) => { nextState: TState; context: TContext };
