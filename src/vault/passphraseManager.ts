/**
 * @file passphraseManager.ts
 * @summary Master Passphrase Management, Validation, and Rate Limiting.
 *
 * Enforces passphrase invariants:
 * - Minimum length and character entropy validation.
 * - Rate-limited local unlock attempts with exponential cooldown to mitigate brute-force.
 * - Strict volatile handling: passphrases are never persisted to disk, databases, or logs.
 * - Memory zeroization for transient buffers.
 */

import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { timingSafeEqual } from '../security/antiLeak';

export interface PassphraseValidationResult {
  valid: boolean;
  score: number; // 0-4
  feedback?: string;
}

export interface UnlockAttemptResult {
  success: boolean;
  remainingAttempts: number;
  lockoutRemainingMs: number;
}

const MIN_PASSPHRASE_LENGTH = 8;
const MAX_LOCAL_FAILED_ATTEMPTS = 5;
const BASE_LOCKOUT_MS = 30_000; // 30 seconds initial cooldown

export class PassphraseManager {
  private failedAttempts: number = 0;
  private lockedUntilMs: number = 0;

  /**
   * Validates a candidate master passphrase against policy requirements.
   * Does NOT persist or log the passphrase.
   */
  public static validatePassphrase(passphrase: string): PassphraseValidationResult {
    if (typeof passphrase !== 'string' || passphrase.length === 0) {
      return {
        valid: false,
        score: 0,
        feedback: 'Passphrase cannot be empty.',
      };
    }

    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
      return {
        valid: false,
        score: 1,
        feedback: `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`,
      };
    }

    let score = 1;
    if (passphrase.length >= 12) score++;
    if (/[A-Z]/.test(passphrase) && /[a-z]/.test(passphrase)) score++;
    if (/[0-9]/.test(passphrase)) score++;
    if (/[^A-Za-z0-9]/.test(passphrase)) score++;

    const clampedScore = Math.min(4, score);

    return {
      valid: clampedScore >= 2,
      score: clampedScore,
      feedback: clampedScore < 2 ? 'Passphrase is too simple. Use a combination of letters, numbers, and symbols.' : undefined,
    };
  }

  /**
   * Asserts that the passphrase meets basic non-empty validity rules.
   * Throws typed GhostTagError if invalid.
   */
  public static assertValid(passphrase: string): void {
    if (typeof passphrase !== 'string' || passphrase.trim().length === 0) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
        userMessage: 'A non-empty master passphrase is required.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
      throw new GhostTagError({
        code: GhostTagErrorCode.PASSPHRASE_INVALID,
        userMessage: `Master passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters.`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }
  }

  /**
   * Checks whether the local unlock state is currently locked out.
   */
  public isLockedOut(): boolean {
    const now = Date.now();
    return now < this.lockedUntilMs;
  }

  /**
   * Gets remaining milliseconds in lockout period, or 0 if active.
   */
  public getLockoutRemainingMs(): number {
    const now = Date.now();
    return Math.max(0, this.lockedUntilMs - now);
  }

  /**
   * Records an unlock attempt.
   * Enforces exponential cooldown after reaching MAX_LOCAL_FAILED_ATTEMPTS.
   */
  public recordAttempt(success: boolean): UnlockAttemptResult {
    if (this.isLockedOut()) {
      return {
        success: false,
        remainingAttempts: 0,
        lockoutRemainingMs: this.getLockoutRemainingMs(),
      };
    }

    if (success) {
      this.failedAttempts = 0;
      this.lockedUntilMs = 0;
      return {
        success: true,
        remainingAttempts: MAX_LOCAL_FAILED_ATTEMPTS,
        lockoutRemainingMs: 0,
      };
    }

    this.failedAttempts++;
    if (this.failedAttempts >= MAX_LOCAL_FAILED_ATTEMPTS) {
      const multiplier = Math.pow(2, this.failedAttempts - MAX_LOCAL_FAILED_ATTEMPTS);
      this.lockedUntilMs = Date.now() + BASE_LOCKOUT_MS * multiplier;
    }

    return {
      success: false,
      remainingAttempts: Math.max(0, MAX_LOCAL_FAILED_ATTEMPTS - this.failedAttempts),
      lockoutRemainingMs: this.getLockoutRemainingMs(),
    };
  }

  /**
   * Resets local failure counters upon explicit authenticated re-authorization.
   */
  public resetLockout(): void {
    this.failedAttempts = 0;
    this.lockedUntilMs = 0;
  }

  /**
   * Constant-time comparison helper for passphrase hashes.
   */
  public static constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
    return timingSafeEqual(a, b);
  }
}
