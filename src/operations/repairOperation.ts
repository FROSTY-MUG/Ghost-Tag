/**
 * @file repairOperation.ts
 * @summary Ghost-Tag Re-encryption and Tag Rewrite Workflow.
 *
 * Reads an existing valid tag envelope, decrypts it using the current key,
 * re-encrypts it under a refreshed nonce or new DEK, and writes back with
 * verified read-back comparison.
 */

import { ScanOperation } from './scanOperation';
import { WriteOperation } from './writeOperation';
import { GhostTagErrorCode, GhostTagError, ErrorCategory, ErrorSeverity } from '../contracts/errors';
import { VaultManager } from '../vault/vaultManager';
import { NfcTag } from '../nfc/nfcManager';

export interface RepairOperationResult {
  readonly success: boolean;
  readonly previousKeyId?: string;
  readonly newKeyId?: string;
  readonly error?: GhostTagError;
}

export class RepairOperation {
  private readonly scanOp: ScanOperation;
  private readonly writeOp: WriteOperation;
  private readonly vaultManager: VaultManager;

  constructor(vaultManager: VaultManager, scanOp?: ScanOperation, writeOp?: WriteOperation) {
    this.vaultManager = vaultManager;
    this.scanOp = scanOp ?? new ScanOperation(vaultManager);
    this.writeOp = writeOp ?? new WriteOperation(vaultManager);
  }

  /**
   * Reads, decrypts, re-encrypts, and rewrites a tag envelope.
   */
  public async execute(tag: NfcTag, rotateKey = false): Promise<RepairOperationResult> {
    const session = this.vaultManager.getActiveSession();
    if (!session || !session.isUnlocked) {
      return {
        success: false,
        error: new GhostTagError({
          code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
          userMessage: 'Vault must be unlocked to perform tag repair or re-encryption.',
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.WARNING,
        }),
      };
    }

    // 1. Scan and Decrypt Existing Tag
    const scanResult = await this.scanOp.execute(tag);
    if (!scanResult.success || !scanResult.rawPayload || !scanResult.envelope) {
      return {
        success: false,
        error: scanResult.error,
      };
    }

    const previousKeyId = scanResult.context.resolvedKeyId;

    // 2. Re-encrypt and Write Back
    const writeResult = await this.writeOp.execute(tag, {
      plaintext: scanResult.rawPayload,
      purpose: scanResult.envelope.header.purpose,
      keyId: rotateKey ? undefined : scanResult.envelope.header.keyId,
    });

    if (!writeResult.success) {
      return {
        success: false,
        previousKeyId,
        error: writeResult.error,
      };
    }

    return {
      success: true,
      previousKeyId,
      newKeyId: writeResult.keyId,
    };
  }
}
