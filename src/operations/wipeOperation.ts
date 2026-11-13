/**
 * @file wipeOperation.ts
 * @summary Ghost-Tag Destructive Tag Sanitization and Overwrite Pipeline.
 *
 * Implements multi-pass sanitization:
 * IDLE -> TAG_DETECTED -> AUTHENTICATING -> OVERWRITE_PASS1_ZEROS
 *      -> OVERWRITE_PASS2_RANDOM -> OVERWRITE_PASS3_NDEF_EMPTY -> READ_BACK_VERIFY
 *      -> [WIPE_COMPLETE | WIPE_PARTIAL | WIPE_FAILED]
 *
 * Security Disclaimer:
 * "This operation overwrites writable user memory and verifies the result.
 * It does not guarantee recovery-proof erasure at the silicon level."
 */

import { WipeState, WipeContext } from '../contracts/states';
import { GhostTagErrorCode, GhostTagError, ErrorCategory, ErrorSeverity } from '../contracts/errors';
import { TagWiper } from '../nfc/tagWiper';
import { TagInfo } from '../nfc/tagInfo';
import { NfcTag } from '../nfc/nfcManager';

export type WipeStateCallback = (context: WipeContext) => void;

export interface WipeResult {
  readonly success: boolean;
  readonly context: WipeContext;
  readonly error?: GhostTagError;
}

export class WipeOperation {
  private readonly wiper: TagWiper;
  private readonly tagInfoHelper: TagInfo;

  constructor(wiper = new TagWiper(), tagInfoHelper = new TagInfo()) {
    this.wiper = wiper;
    this.tagInfoHelper = tagInfoHelper;
  }

  /**
   * Executes multi-pass destructive user-memory overwrite.
   */
  public async execute(
    tag: NfcTag,
    onStateChange?: WipeStateCallback
  ): Promise<WipeResult> {
    let currentContext: WipeContext = { state: WipeState.TAG_DETECTED };
    this.notify(currentContext, onStateChange);

    try {
      const contractTagInfo = this.tagInfoHelper.toContractTagInfo(tag);
      currentContext = {
        ...currentContext,
        tagInfo: contractTagInfo,
      };

      if (!this.tagInfoHelper.isTagSupported(tag)) {
        throw new GhostTagError({
          code: GhostTagErrorCode.TAG_UNSUPPORTED,
          userMessage: 'Target tag is not a supported Type 2 NFC tag.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        });
      }

      if (!this.tagInfoHelper.isTagWritable(tag)) {
        throw new GhostTagError({
          code: GhostTagErrorCode.TAG_READ_ONLY,
          userMessage: 'Tag is hardware locked or read-only; cannot sanitize user pages.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        });
      }

      // Execute Wiper
      const wiperResult = await this.wiper.wipeTag(tag);

      if (wiperResult.success && wiperResult.state === WipeState.WIPE_COMPLETE) {
        currentContext = {
          ...currentContext,
          state: WipeState.WIPE_COMPLETE,
        };
        this.notify(currentContext, onStateChange);

        return {
          success: true,
          context: currentContext,
        };
      } else if (wiperResult.state === WipeState.WIPE_PARTIAL) {
        throw new GhostTagError({
          code: GhostTagErrorCode.WIPE_PARTIAL,
          userMessage: 'Sanitization aborted prematurely! Tag was partially overwritten and may contain residue.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.CRITICAL,
        });
      } else {
        throw wiperResult.error || new GhostTagError({
          code: GhostTagErrorCode.TAG_WRITE_FAILED,
          userMessage: 'Wipe operation failed during user memory overwrite.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        });
      }
    } catch (err) {
      const gError =
        err instanceof GhostTagError
          ? err
          : new GhostTagError({
              code: GhostTagErrorCode.TAG_WRITE_FAILED,
              userMessage: err instanceof Error ? err.message : 'Wipe operation failed',
              category: ErrorCategory.OPERATION,
              severity: ErrorSeverity.ERROR,
              cause: err,
            });

      const terminalState =
        gError.code === GhostTagErrorCode.WIPE_PARTIAL
          ? WipeState.WIPE_PARTIAL
          : WipeState.WIPE_FAILED;

      currentContext = {
        ...currentContext,
        state: terminalState,
        errorCode: gError.code,
      };
      this.notify(currentContext, onStateChange);

      return {
        success: false,
        context: currentContext,
        error: gError,
      };
    }
  }

  private notify(context: WipeContext, cb?: WipeStateCallback): void {
    if (cb) {
      try {
        cb(context);
      } catch {
        // Suppress listener errors
      }
    }
  }
}
