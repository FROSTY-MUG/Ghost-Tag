/**
 * @file writeOperation.ts
 * @summary Ghost-Tag Tag Write and Verification Pipeline.
 *
 * Implements the atomic write and read-back state machine:
 * IDLE -> TAG_DETECTED -> CAPACITY_CHECKED -> ENVELOPE_PREPARED -> WRITE_IN_PROGRESS
 *      -> WRITE_COMPLETE -> READ_BACK_IN_PROGRESS -> [WRITE_VERIFIED | WRITE_FAILED | WRITE_UNVERIFIED]
 */

import { WriteState, WriteContext } from '../contracts/states';
import { EnvelopePurpose, GhostTagEnvelope, ENVELOPE_FORMAT_VERSION_V1, ENVELOPE_MAGIC } from '../contracts/envelope';
import { GhostTagErrorCode, GhostTagError, ErrorCategory, ErrorSeverity } from '../contracts/errors';
import { encrypt } from '../crypto/aesGcm';
import { constructAAD, serializeEnvelope } from '../crypto/envelope';
import { generateNonce } from '../crypto/random';
import { bytesToHex, hexToBytes } from '../crypto/keyWrap';
import { zeroize } from '../crypto/secureMemory';
import { TagWriter } from '../nfc/tagWriter';
import { TagInfo } from '../nfc/tagInfo';
import { VaultManager } from '../vault/vaultManager';
import { NfcTag } from '../nfc/nfcManager';

export type WriteStateCallback = (context: WriteContext) => void;

export interface WritePayloadOptions {
  readonly plaintext: string | Uint8Array;
  readonly purpose?: EnvelopePurpose;
  readonly keyId?: Uint8Array; // Optional specific DEK to use, or fresh DEK created
}

export interface WriteResult {
  readonly success: boolean;
  readonly context: WriteContext;
  readonly keyId?: string;
  readonly envelopeByteLength?: number;
  readonly error?: GhostTagError;
}

export class WriteOperation {
  private readonly writer: TagWriter;
  private readonly tagInfoHelper: TagInfo;
  private readonly vaultManager: VaultManager;

  constructor(vaultManager: VaultManager, writer = new TagWriter(), tagInfoHelper = new TagInfo()) {
    this.vaultManager = vaultManager;
    this.writer = writer;
    this.tagInfoHelper = tagInfoHelper;
  }

  /**
   * Executes atomic write + independent read-back verification.
   */
  public async execute(
    tag: NfcTag,
    options: WritePayloadOptions,
    onStateChange?: WriteStateCallback
  ): Promise<WriteResult> {
    let currentContext: WriteContext = { state: WriteState.TAG_DETECTED };
    this.notify(currentContext, onStateChange);

    let plaintextBytes: Uint8Array | null = null;
    let dek: Uint8Array | null = null;

    try {
      // 1. Convert plaintext input
      if (typeof options.plaintext === 'string') {
        const encoder = new TextEncoder();
        plaintextBytes = encoder.encode(options.plaintext);
      } else {
        plaintextBytes = new Uint8Array(options.plaintext);
      }

      // 2. Validate Tag Technology & Capacity
      const contractTagInfo = this.tagInfoHelper.toContractTagInfo(tag);
      const availableSpace = this.tagInfoHelper.calculateAvailableSpace(tag);

      currentContext = {
        ...currentContext,
        tagInfo: contractTagInfo,
      };

      if (!this.tagInfoHelper.isTagSupported(tag)) {
        throw new GhostTagError({
          code: GhostTagErrorCode.TAG_UNSUPPORTED,
          userMessage: 'Target tag is not a supported Type 2 (NTAG21x / MIFARE Ultralight) tag.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        });
      }

      if (!this.tagInfoHelper.isTagWritable(tag)) {
        throw new GhostTagError({
          code: GhostTagErrorCode.TAG_READ_ONLY,
          userMessage: 'Tag is hardware locked or marked read-only. Cannot write.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        });
      }

      if (plaintextBytes.length > availableSpace) {
        throw new GhostTagError({
          code: GhostTagErrorCode.PAYLOAD_TOO_LARGE,
          userMessage: `Payload size (${plaintextBytes.length} bytes) exceeds available tag capacity (${availableSpace} bytes).`,
          category: ErrorCategory.ENVELOPE,
          severity: ErrorSeverity.ERROR,
        });
      }

      currentContext = {
        ...currentContext,
        state: WriteState.CAPACITY_CHECKED,
      };
      this.notify(currentContext, onStateChange);

      // 3. Ensure Vault Session is Active
      const session = this.vaultManager.getActiveSession();
      if (!session || !session.isUnlocked) {
        throw new GhostTagError({
          code: GhostTagErrorCode.PASSPHRASE_REQUIRED,
          userMessage: 'Vault must be unlocked before encrypting and writing tags.',
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.WARNING,
        });
      }

      const kek = session.getKEK();
      if (!kek) {
        throw new GhostTagError({
          code: GhostTagErrorCode.KEY_UNAVAILABLE,
          userMessage: 'Cryptographic session key unavailable. Please re-authenticate.',
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.WARNING,
        });
      }

      // 4. Resolve or Generate DEK
      const dekManager = this.vaultManager.getDEKManager();
      let targetKeyIdBytes: Uint8Array;
      if (options.keyId) {
        targetKeyIdBytes =
          typeof options.keyId === 'string'
            ? hexToBytes(options.keyId)
            : options.keyId;
        dek = await dekManager.getDEK(targetKeyIdBytes, kek);
      } else {
        const wrappedDek = await dekManager.createDEK(kek);
        targetKeyIdBytes = hexToBytes(wrappedDek.keyId);
        dek = await dekManager.getDEK(targetKeyIdBytes, kek);
      }

      const keyIdHex = bytesToHex(targetKeyIdBytes);
      currentContext = {
        ...currentContext,
        targetKeyId: keyIdHex,
      };

      // 5. Encrypt with AES-256-GCM & Construct Envelope
      const nonce = generateNonce();
      const purpose = options.purpose ?? EnvelopePurpose.NOTE;
      const aad = constructAAD(
        ENVELOPE_FORMAT_VERSION_V1,
        purpose,
        targetKeyIdBytes,
        plaintextBytes.length
      );

      const { ciphertext, tag: gcmTag } = encrypt(dek, plaintextBytes, aad);

      const envelope: GhostTagEnvelope = {
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose,
          keyId: targetKeyIdBytes,
          nonce,
          ciphertextLength: ciphertext.length,
        },
        ciphertext,
        gcmTag,
      };

      const serialized = serializeEnvelope(envelope);

      currentContext = {
        ...currentContext,
        state: WriteState.ENVELOPE_PREPARED,
        envelopeByteLength: serialized.length,
      };
      this.notify(currentContext, onStateChange);

      // 6. Execute Atomic Write and Read-Back Verification
      currentContext = {
        ...currentContext,
        state: WriteState.WRITE_IN_PROGRESS,
        progressPercent: 30,
      };
      this.notify(currentContext, onStateChange);

      const writeResult = await this.writer.writeAndVerify(tag, serialized);

      if (writeResult.state === WriteState.WRITE_VERIFIED) {
        currentContext = {
          ...currentContext,
          state: WriteState.WRITE_VERIFIED,
          progressPercent: 100,
        };
        this.notify(currentContext, onStateChange);

        return {
          success: true,
          context: currentContext,
          keyId: keyIdHex,
          envelopeByteLength: serialized.length,
        };
      } else if (writeResult.state === WriteState.WRITE_UNVERIFIED) {
        throw new GhostTagError({
          code: GhostTagErrorCode.WRITE_UNVERIFIED,
          userMessage: 'Write completed on tag, but read-back verification failed! Tag contents may be corrupted.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.CRITICAL,
        });
      } else {
        throw writeResult.error || new GhostTagError({
          code: GhostTagErrorCode.WRITE_FAILED,
          userMessage: 'NFC transmission failed during tag write.',
          category: ErrorCategory.NFC,
          severity: ErrorSeverity.ERROR,
        });
      }
    } catch (err) {
      const gError =
        err instanceof GhostTagError || (err as any)?.name === 'GhostTagError'
          ? (err as GhostTagError)
          : new GhostTagError({
              code: GhostTagErrorCode.WRITE_FAILED,
              userMessage: err instanceof Error ? err.message : 'Write operation failed',
              category: ErrorCategory.OPERATION,
              severity: ErrorSeverity.ERROR,
              cause: err,
            });

      const failedState =
        gError.code === GhostTagErrorCode.WRITE_UNVERIFIED
          ? WriteState.WRITE_UNVERIFIED
          : WriteState.WRITE_FAILED;

      currentContext = {
        ...currentContext,
        state: failedState,
        errorCode: gError.code,
      };
      this.notify(currentContext, onStateChange);

      return {
        success: false,
        context: currentContext,
        error: gError,
      };
    } finally {
      // Discard and zeroize all volatile sensitive plaintext and DEK material
      if (plaintextBytes) {
        zeroize(plaintextBytes);
      }
      if (dek) {
        zeroize(dek);
      }
    }
  }

  private notify(context: WriteContext, cb?: WriteStateCallback): void {
    if (cb) {
      try {
        cb(context);
      } catch {
        // Suppress listener errors
      }
    }
  }
}
