/**
 * @file scanOperation.ts
 * @summary Ghost-Tag Scan and Decryption Workflow.
 *
 * Implements the full scan state machine:
 * IDLE -> TAG_DETECTED -> TECHNOLOGY_IDENTIFIED -> NDEF_READING -> NDEF_READ_COMPLETE
 *      -> ENVELOPE_PARSING -> KEY_RESOLVING -> DECRYPTING -> VERIFIED -> DISPLAYING
 */

import { ScanState, ScanContext } from '../contracts/states';
import { GhostTagErrorCode, GhostTagError, ErrorCategory, ErrorSeverity } from '../contracts/errors';
import { GhostTagEnvelope } from '../contracts/envelope';
import { parseEnvelope } from '../crypto/envelope';
import { decrypt } from '../crypto/aesGcm';
import { constructAAD } from '../crypto/envelope';
import { bytesToHex } from '../crypto/keyWrap';
import { zeroize } from '../crypto/secureMemory';
import { TagReader, GhostTagRecord } from '../nfc/tagReader';
import { TagInfo, TagIdentification } from '../nfc/tagInfo';
import { VaultManager } from '../vault/vaultManager';
import { NfcTag } from '../nfc/nfcManager';

export type ScanStateCallback = (context: ScanContext) => void;

export interface ScanResult {
  readonly success: boolean;
  readonly context: ScanContext;
  readonly plaintext?: string;
  readonly rawPayload?: Uint8Array;
  readonly envelope?: GhostTagEnvelope;
  readonly error?: GhostTagError;
}

export class ScanOperation {
  private readonly reader: TagReader;
  private readonly tagInfoHelper: TagInfo;
  private readonly vaultManager: VaultManager;

  constructor(vaultManager: VaultManager, reader = new TagReader(), tagInfoHelper = new TagInfo()) {
    this.vaultManager = vaultManager;
    this.reader = reader;
    this.tagInfoHelper = tagInfoHelper;
  }

  /**
   * Executes the full scan and decryption pipeline on a detected tag.
   */
  public async execute(
    tag: NfcTag,
    onStateChange?: ScanStateCallback
  ): Promise<ScanResult> {
    let currentContext: ScanContext = { state: ScanState.TAG_DETECTED };
    this.notify(currentContext, onStateChange);

    try {
      // 1. Identify Technology & Tag Matrix
      const identification = this.tagInfoHelper.identifyTag(tag);
      const contractTagInfo = this.tagInfoHelper.toContractTagInfo(tag);

      currentContext = {
        state: ScanState.TECHNOLOGY_IDENTIFIED,
        tagInfo: contractTagInfo,
      };
      this.notify(currentContext, onStateChange);

      if (!identification.isSupported) {
        throw new GhostTagError({
          code: GhostTagErrorCode.TAG_UNSUPPORTED,
          userMessage: `Unsupported tag architecture: ${identification.details}. Ghost-Tag only supports NTAG21x and MIFARE Ultralight Type 2 tags.`,
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        });
      }

      // 2. Read NDEF Message
      currentContext = { ...currentContext, state: ScanState.NDEF_READING };
      this.notify(currentContext, onStateChange);

      const readResult = await this.reader.readTag(tag);
      if (!readResult.success) {
        throw readResult.error;
      }

      currentContext = {
        ...currentContext,
        state: ScanState.NDEF_READ_COMPLETE,
        rawNdefBytes: readResult.envelopeBytes,
      };
      this.notify(currentContext, onStateChange);

      // 3. Parse Envelope
      currentContext = { ...currentContext, state: ScanState.ENVELOPE_PARSING };
      this.notify(currentContext, onStateChange);

      const envelope = parseEnvelope(readResult.envelopeBytes);
      const keyIdHex = bytesToHex(envelope.header.keyId);

      currentContext = {
        ...currentContext,
        envelope,
        resolvedKeyId: keyIdHex,
      };

      // 4. Resolve Key from Vault
      currentContext = { ...currentContext, state: ScanState.KEY_RESOLVING };
      this.notify(currentContext, onStateChange);

      const session = this.vaultManager.getActiveSession();
      if (!session || !session.isUnlocked) {
        throw new GhostTagError({
          code: GhostTagErrorCode.KEY_UNAVAILABLE,
          userMessage: 'Vault is currently locked. Master passphrase is required to unwrap key.',
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.WARNING,
        });
      }

      const kek = session.getKEK();
      if (!kek) {
        throw new GhostTagError({
          code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
          userMessage: 'Active cryptographic session expired. Please re-enter passphrase.',
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.WARNING,
        });
      }

      const dekManager = this.vaultManager.getDEKManager();
      let dek: Uint8Array;
      try {
        dek = await dekManager.getDEK(envelope.header.keyId, kek);
      } catch (err) {
        throw new GhostTagError({
          code: GhostTagErrorCode.KEY_NOT_FOUND,
          userMessage: `No matching Data Encryption Key (DEK) found for key ID: ${keyIdHex}. Tag was encrypted with another vault.`,
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.ERROR,
          cause: err,
        });
      }

      // 5. Decrypt and Authenticate via AES-256-GCM
      currentContext = { ...currentContext, state: ScanState.DECRYPTING };
      this.notify(currentContext, onStateChange);

      const aad = constructAAD(
        envelope.header.formatVersion,
        envelope.header.purpose,
        envelope.header.keyId,
        envelope.header.ciphertextLength
      );

      let plaintextBytes: Uint8Array;
      try {
        plaintextBytes = decrypt(
          dek,
          envelope.ciphertext,
          envelope.header.nonce,
          envelope.gcmTag,
          aad
        );
      } catch (decryptErr) {
        throw new GhostTagError({
          code: GhostTagErrorCode.GCM_AUTH_FAILED,
          userMessage: 'AES-256-GCM authentication failed! Tag payload or metadata has been tampered with or corrupted.',
          category: ErrorCategory.CRYPTO,
          severity: ErrorSeverity.CRITICAL,
          cause: decryptErr,
        });
      } finally {
        // Zeroize raw ephemeral DEK
        zeroize(dek);
      }

      // 6. Verified
      currentContext = {
        ...currentContext,
        state: ScanState.VERIFIED,
        decryptedPayload: plaintextBytes,
      };
      this.notify(currentContext, onStateChange);

      // 7. Decode Display Plaintext
      const decoder = new TextDecoder('utf-8');
      const plaintextString = decoder.decode(plaintextBytes);

      currentContext = {
        ...currentContext,
        state: ScanState.DISPLAYING,
      };
      this.notify(currentContext, onStateChange);

      return {
        success: true,
        context: currentContext,
        plaintext: plaintextString,
        rawPayload: plaintextBytes,
        envelope,
      };
    } catch (error) {
      const gError =
        error instanceof GhostTagError || (error as any)?.name === 'GhostTagError'
          ? (error as GhostTagError)
          : new GhostTagError({
              code: GhostTagErrorCode.INVALID_ENVELOPE,
              userMessage: error instanceof Error ? error.message : 'Scan operation failed',
              category: ErrorCategory.OPERATION,
              severity: ErrorSeverity.ERROR,
              cause: error,
            });

      currentContext = {
        ...currentContext,
        state: ScanState.ERROR,
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

  private notify(context: ScanContext, cb?: ScanStateCallback): void {
    if (cb) {
      try {
        cb(context);
      } catch {
        // Suppress listener errors
      }
    }
  }
}
