/**
 * @file verifyOperation.ts
 * @summary Non-Destructive Ghost-Tag Integrity Verification.
 *
 * Validates envelope headers, MIME types, magic markers, and cryptographic
 * authentication without disclosing plaintext or requiring active master sessions.
 */

import { TagReader } from '../nfc/tagReader';
import { TagInfo } from '../nfc/tagInfo';
import { parseEnvelope } from '../crypto/envelope';
import { bytesToHex } from '../crypto/keyWrap';
import { VaultManager } from '../vault/vaultManager';
import { GhostTagEnvelope } from '../contracts/envelope';
import { GhostTagErrorCode, GhostTagError, ErrorCategory, ErrorSeverity } from '../contracts/errors';
import { NfcTag } from '../nfc/nfcManager';

export interface VerifyOperationResult {
  readonly isValidGhostTag: boolean;
  readonly isRecognizedKey: boolean;
  readonly keyIdHex?: string;
  readonly envelope?: GhostTagEnvelope;
  readonly error?: GhostTagError;
}

export class VerifyOperation {
  private readonly reader: TagReader;
  private readonly tagInfoHelper: TagInfo;
  private readonly vaultManager: VaultManager;

  constructor(vaultManager: VaultManager, reader = new TagReader(), tagInfoHelper = new TagInfo()) {
    this.vaultManager = vaultManager;
    this.reader = reader;
    this.tagInfoHelper = tagInfoHelper;
  }

  /**
   * Performs passive inspection and validation of a tag envelope.
   */
  public async execute(tag: NfcTag): Promise<VerifyOperationResult> {
    try {
      if (!this.tagInfoHelper.isTagSupported(tag)) {
        return {
          isValidGhostTag: false,
          isRecognizedKey: false,
          error: new GhostTagError({
            code: GhostTagErrorCode.TAG_UNSUPPORTED,
            userMessage: 'Tag hardware is not a supported Type 2 NFC tag.',
            category: ErrorCategory.NFC,
            severity: ErrorSeverity.WARNING,
          }),
        };
      }

      const readResult = await this.reader.readTag(tag);
      if (!readResult.success) {
        return {
          isValidGhostTag: false,
          isRecognizedKey: false,
          error: readResult.error,
        };
      }

      const envelope = parseEnvelope(readResult.envelopeBytes);
      const keyIdHex = bytesToHex(envelope.header.keyId);

      // Check if DEK exists in local vault without needing unlock
      const dekManager = this.vaultManager.getDEKManager();
      const recognizedKeyIds = await dekManager.listKeyIds();
      const isRecognized = recognizedKeyIds.some(
        (id) => bytesToHex(id) === keyIdHex
      );

      return {
        isValidGhostTag: true,
        isRecognizedKey: isRecognized,
        keyIdHex,
        envelope,
      };
    } catch (err) {
      return {
        isValidGhostTag: false,
        isRecognizedKey: false,
        error:
          err instanceof GhostTagError
            ? err
            : new GhostTagError({
                code: GhostTagErrorCode.INVALID_ENVELOPE,
                userMessage: err instanceof Error ? err.message : 'Envelope verification failed',
                category: ErrorCategory.ENVELOPE,
                severity: ErrorSeverity.WARNING,
                cause: err,
              }),
      };
    }
  }
}
