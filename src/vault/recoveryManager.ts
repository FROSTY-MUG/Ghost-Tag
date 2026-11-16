/**
 * @file recoveryManager.ts
 * @summary Emergency Out-of-Band Vault Recovery Management.
 *
 * Implements 24-word BIP39-style mnemonic recovery phrase generation, verification,
 * recovery KEK derivation via Argon2id with isolated salts, and recovery-wrapped DEK containers.
 */

import QuickCrypto from 'react-native-quick-crypto';
import { Buffer } from 'buffer';
import {
  RECOVERY_KEY_WRAP_PURPOSE_BYTE,
  RECOVERY_PHRASE_WORD_COUNT,
  RECOVERY_PHRASE_12_WORD_COUNT,
  RECOVERY_PHRASE_24_WORD_COUNT,
  RECOVERY_SECRET_BYTE_LENGTH,
  RECOVERY_12_WORD_SECRET_BYTE_LENGTH,
  RecoveryEnvelope,
  RecoveryWrappedDEK,
} from '../contracts/recovery';
import {
  WrappedDEK,
  RecoveryKdfParameters,
  DEFAULT_RECOVERY_KDF_CONFIG,
  RECOVERY_KDF_SALT_BYTE_LENGTH,
  KEY_ID_BYTE_LENGTH,
  DEK_BYTE_LENGTH,
} from '../contracts/keyHierarchy';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { generateSecureRandom } from '../crypto/random';
import { deriveKEK } from '../crypto/argon2';
import { encrypt, decrypt } from '../crypto/aesGcm';
import { unwrapDEK, bytesToHex, hexToBytes } from '../crypto/keyWrap';
import { zeroize, zeroizeAll } from '../crypto/secureMemory';
import { timingSafeEqual } from '../security/antiLeak';
import { getWord, getWordIndex, isValidWord } from './wordlist';
import { VaultDatabase } from './database';

/** Persistent database key for storing the recovery envelope. */
export const RECOVERY_ENVELOPE_STORAGE_KEY = 'recovery_envelope';

/**
 * Result returned upon generating a new mnemonic recovery phrase.
 */
export interface RecoveryPhraseResult {
  /** Complete 24-word recovery phrase separated by spaces. */
  readonly phrase: string;
  /** Array of individual 24 recovery words. */
  readonly words: readonly string[];
}

/**
 * Unwrapped Data Encryption Key recovered during emergency restoration.
 */
export interface RecoveredDEK {
  /** 16-byte hex identifier matching the original DEK. */
  readonly keyId: string;
  /** Unwrapped 32-byte raw DEK (MUST be zeroized by caller after re-wrapping). */
  readonly dek: Uint8Array;
  /** Original key version number. */
  readonly keyVersion: number;
}

/**
 * Result of executing an emergency vault recovery workflow.
 */
export interface RecoveryResult {
  /** Indicates whether all managed DEKs were successfully decrypted and restored. */
  readonly success: boolean;
  /** Total count of restored DEKs. */
  readonly recoveredDekCount: number;
  /** Array of unwrapped DEKs ready for re-wrapping under a new master passphrase. */
  readonly recoveredDeks: readonly RecoveredDEK[];
}

/** Serialized JSON schema for persisting RecoveryEnvelope in VaultDatabase. */
interface SerializedRecoveryEnvelope {
  readonly recoveryId: string;
  readonly salt: string; // hex
  readonly params: {
    readonly memoryCost: number;
    readonly timeCost: number;
    readonly parallelism: number;
    readonly version: number;
  };
  readonly wrappedDEKs: readonly {
    readonly keyId: string;
    readonly wrappedDEK: string; // hex
    readonly nonce: string; // hex
    readonly tag: string; // hex
    readonly keyVersion: number;
  }[];
  readonly checksum: string; // hex
  readonly createdAt: number;
}

/**
 * Manages the emergency recovery lifecycle and out-of-band vault restoration.
 */
export class RecoveryManager {
  private readonly database: VaultDatabase;

  /**
   * Constructs a new RecoveryManager.
   *
   * @param database Initialized VaultDatabase instance for persistent storage.
   */
  constructor(database: VaultDatabase) {
    this.database = database;
  }

  /**
   * Generates a standard BIP-39 mnemonic recovery phrase.
   * Defaults to 12 words (128-bit entropy, standard Ghost-Tag v2.0.5 profile) or 24 words.
   *
   * Security Properties:
   * - Ephemeral secret buffers are zeroized immediately after phrase encoding.
   * - The generated phrase is NEVER stored on disk by the recovery system.
   *
   * @param wordCount Number of mnemonic words (12 or 24, defaults to 24 for backward compatibility).
   * @returns Generated recovery phrase and word array.
   */
  public generateRecoveryPhrase(wordCount: 12 | 24 = 24): RecoveryPhraseResult {
    const byteLength =
      wordCount === 12
        ? RECOVERY_12_WORD_SECRET_BYTE_LENGTH
        : RECOVERY_SECRET_BYTE_LENGTH;
    const rawEntropy = generateSecureRandom(byteLength);

    try {
      const phrase = this.entropyToMnemonic(rawEntropy);
      const words = phrase.split(' ');
      return { phrase, words };
    } finally {
      zeroize(rawEntropy);
    }
  }

  /**
   * Generates a standard 12-word BIP-39 English recovery phrase (Ghost-Tag v2.0.5 primary standard).
   */
  public generate12WordPhrase(): RecoveryPhraseResult {
    return this.generateRecoveryPhrase(12);
  }

  /**
   * Generates a high-entropy 24-word BIP-39 English recovery phrase.
   */
  public generate24WordPhrase(): RecoveryPhraseResult {
    return this.generateRecoveryPhrase(24);
  }

  /**
   * Validates standard 12-word confirmation indices (words 4, 8, 11 - 1-based per v2.0.5 spec).
   *
   * @param originalWords Array of 12 words generated during account creation.
   * @param word4 User input for word 4.
   * @param word8 User input for word 8.
   * @param word11 User input for word 11.
   * @returns True if all 3 entered words exactly match the offline words.
   */
  public verifyConfirmationWords(
    originalWords: readonly string[],
    word4: string,
    word8: string,
    word11: string
  ): boolean {
    if (!originalWords || originalWords.length < 12) return false;
    const clean = (w: string) => (w || '').trim().toLowerCase();
    return (
      clean(originalWords[3]) === clean(word4) &&
      clean(originalWords[7]) === clean(word8) &&
      clean(originalWords[10]) === clean(word11)
    );
  }

  /**
   * Configures vault emergency recovery by wrapping copies of all DEKs under a Recovery KEK.
   *
   * Security Directives:
   * - Uses a dedicated 32-byte salt completely isolated from the primary master passphrase salt.
   * - Derives Recovery KEK via Argon2id.
   * - Recovery KEK and unwrapped intermediate DEKs are zeroized immediately after wrapping.
   * - Recovery phrase itself is NEVER stored.
   *
   * @param recoveryPhrase 24-word mnemonic phrase confirmed by the user.
   * @param kek Active 32-byte primary Key Encryption Key.
   * @param deks Array of current active/rotated WrappedDEK containers from the vault.
   * @throws {GhostTagError} If recovery phrase is invalid or key unwrapping/wrapping fails.
   */
  public async setupRecovery(
    recoveryPhrase: string,
    kek: Uint8Array,
    deks: WrappedDEK[]
  ): Promise<void> {
    const isValid = await this.verifyRecoveryPhrase(recoveryPhrase);
    if (!isValid) {
      throw new GhostTagError({
        code: GhostTagErrorCode.RECOVERY_INVALID,
        userMessage: 'Recovery setup failed: invalid recovery phrase or checksum mismatch.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    const recoverySalt = generateSecureRandom(RECOVERY_KDF_SALT_BYTE_LENGTH);
    const recoveryParams: RecoveryKdfParameters = {
      salt: recoverySalt,
      memoryCost: DEFAULT_RECOVERY_KDF_CONFIG.memoryCost,
      timeCost: DEFAULT_RECOVERY_KDF_CONFIG.timeCost,
      parallelism: DEFAULT_RECOVERY_KDF_CONFIG.parallelism,
      version: DEFAULT_RECOVERY_KDF_CONFIG.version,
    };

    let recoveryKek: Uint8Array | null = null;
    const recoveryWrappedDeks: RecoveryWrappedDEK[] = [];

    try {
      // Derive dedicated recovery KEK
      recoveryKek = await deriveKEK(recoveryPhrase, recoverySalt, recoveryParams);

      for (const wrappedDek of deks) {
        let rawDek: Uint8Array | null = null;
        try {
          // 1. Unwrap DEK with active primary KEK
          rawDek = unwrapDEK(kek, wrappedDek);

          // 2. Wrap copy under recovery KEK
          const keyIdBytes = hexToBytes(wrappedDek.keyId);
          const recoveryAad = this.buildRecoveryKeyWrapAad(keyIdBytes, wrappedDek.keyVersion);
          const encrypted = encrypt(recoveryKek, rawDek, recoveryAad);

          recoveryWrappedDeks.push({
            keyId: wrappedDek.keyId,
            wrappedDEK: encrypted.ciphertext,
            nonce: encrypted.nonce,
            tag: encrypted.tag,
            keyVersion: wrappedDek.keyVersion,
          });
        } finally {
          if (rawDek) {
            zeroize(rawDek);
          }
        }
      }

      // Compute authentication checksum protecting recovery envelope metadata
      const recoveryId = bytesToHex(generateSecureRandom(16));
      const checksum = this.computeEnvelopeChecksum(recoveryKek, recoveryId, recoverySalt, recoveryWrappedDeks);

      const envelope: RecoveryEnvelope = {
        recoveryId,
        salt: recoverySalt,
        params: recoveryParams,
        wrappedDEKs: recoveryWrappedDeks,
        checksum,
        createdAt: Date.now(),
      };

      await this.saveRecoveryEnvelope(envelope);
    } finally {
      if (recoveryKek) {
        zeroize(recoveryKek);
      }
    }
  }

  /**
   * Verifies the grammatical validity and checksum of a 12-word or 24-word BIP-39 recovery phrase.
   *
   * @param phrase Candidate 12-word or 24-word recovery phrase string.
   * @returns True if the phrase adheres to BIP39 English dictionary and checksum validates.
   */
  public async verifyRecoveryPhrase(phrase: string): Promise<boolean> {
    if (typeof phrase !== 'string') {
      return false;
    }

    const words = phrase.trim().toLowerCase().split(/\s+/);
    if (words.length !== 12 && words.length !== 24) {
      return false;
    }

    // Verify every word exists in BIP39 dictionary
    for (const word of words) {
      if (!isValidWord(word)) {
        return false;
      }
    }

    // Validate checksum against entropy
    const decoded = this.mnemonicToEntropy(phrase);
    if (!decoded.valid || !decoded.entropy) {
      return false;
    }

    zeroize(decoded.entropy);
    return true;
  }

  /**
   * Recovers all managed Data Encryption Keys using the 24-word recovery phrase.
   *
   * Flow:
   * 1. Validate recovery phrase.
   * 2. Load recovery envelope from persistent storage.
   * 3. Derive Recovery KEK via Argon2id using stored recovery salt and params.
   * 4. Verify envelope checksum.
   * 5. Unwrap all DEKs under Recovery KEK.
   * 6. Zeroize Recovery KEK.
   * 7. Return unwrapped DEKs so user can configure a new master passphrase and re-wrap.
   *
   * @param recoveryPhrase 24-word recovery phrase.
   * @returns Restored DEK material.
   * @throws {GhostTagError} If recovery is not configured, phrase is invalid, or decryption fails.
   */
  public async recoverVault(recoveryPhrase: string): Promise<RecoveryResult> {
    const envelope = await this.loadRecoveryEnvelope();
    if (!envelope) {
      throw new GhostTagError({
        code: GhostTagErrorCode.RECOVERY_INVALID,
        userMessage: 'Vault restoration failed: emergency recovery envelope is not configured.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }

    const isValid = await this.verifyRecoveryPhrase(recoveryPhrase);
    if (!isValid) {
      throw new GhostTagError({
        code: GhostTagErrorCode.RECOVERY_INVALID,
        userMessage: 'Vault restoration failed: invalid recovery phrase or checksum.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }

    let recoveryKek: Uint8Array | null = null;
    const restoredDeks: RecoveredDEK[] = [];

    try {
      recoveryKek = await deriveKEK(recoveryPhrase, envelope.salt, envelope.params);

      // Verify envelope integrity checksum
      const expectedChecksum = this.computeEnvelopeChecksum(
        recoveryKek,
        envelope.recoveryId,
        envelope.salt,
        envelope.wrappedDEKs
      );

      if (!this.timingSafeEqual(envelope.checksum, expectedChecksum)) {
        throw new GhostTagError({
          code: GhostTagErrorCode.RECOVERY_INVALID,
          userMessage: 'Recovery envelope checksum verification failed: potential tampering.',
          category: ErrorCategory.VAULT,
          severity: ErrorSeverity.FATAL,
        });
      }

      // Unwrap all recovery DEKs
      for (const recWrapped of envelope.wrappedDEKs) {
        const keyIdBytes = hexToBytes(recWrapped.keyId);
        const recoveryAad = this.buildRecoveryKeyWrapAad(keyIdBytes, recWrapped.keyVersion);

        const unwrapped = decrypt(
          recoveryKek,
          recWrapped.wrappedDEK,
          recWrapped.nonce,
          recWrapped.tag,
          recoveryAad
        );

        if (unwrapped.length !== DEK_BYTE_LENGTH) {
          throw new GhostTagError({
            code: GhostTagErrorCode.RECOVERY_INVALID,
            userMessage: `Decrypted DEK length mismatch for key ${recWrapped.keyId}.`,
            category: ErrorCategory.VAULT,
            severity: ErrorSeverity.FATAL,
          });
        }

        restoredDeks.push({
          keyId: recWrapped.keyId,
          dek: unwrapped,
          keyVersion: recWrapped.keyVersion,
        });
      }

      return {
        success: true,
        recoveredDekCount: restoredDeks.length,
        recoveredDeks: restoredDeks,
      };
    } catch (err) {
      // In case of error, zeroize any partially restored DEK buffers
      for (const item of restoredDeks) {
        zeroize(item.dek);
      }
      if (err instanceof GhostTagError) {
        throw err;
      }
      throw new GhostTagError({
        code: GhostTagErrorCode.RECOVERY_INVALID,
        userMessage: 'Emergency vault recovery failed.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
        cause: err,
      });
    } finally {
      if (recoveryKek) {
        zeroize(recoveryKek);
      }
    }
  }

  /**
   * Checks whether emergency recovery is currently configured in persistent storage.
   *
   * @returns True if a valid recovery envelope is present, false otherwise.
   */
  public async isRecoveryConfigured(): Promise<boolean> {
    return this.database.exists(RECOVERY_ENVELOPE_STORAGE_KEY);
  }

  /**
   * Constructs the canonical 19-byte AAD for recovery key wrapping.
   *
   * Layout:
   * RECOVERY_KEY_WRAP_PURPOSE_BYTE (1B: 0x52) || KEY_ID (16B) || KEY_VERSION (2B LE)
   */
  private buildRecoveryKeyWrapAad(keyId: Uint8Array, keyVersion: number): Uint8Array {
    if (!keyId || keyId.length !== KEY_ID_BYTE_LENGTH) {
      throw new GhostTagError({
        code: GhostTagErrorCode.ARGON2ID_FAILED,
        userMessage: `Recovery key wrap AAD requires 16-byte keyId, got: ${keyId?.length ?? 0}`,
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.ERROR,
      });
    }

    const aad = new Uint8Array(19);
    aad[0] = RECOVERY_KEY_WRAP_PURPOSE_BYTE;
    aad.set(keyId, 1);

    const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
    view.setUint16(17, keyVersion & 0xffff, true); // Little-Endian unsigned 16-bit
    return aad;
  }

  /**
   * Computes an HMAC-SHA-256 authentication tag over recovery envelope metadata.
   */
  private computeEnvelopeChecksum(
    recoveryKek: Uint8Array,
    recoveryId: string,
    salt: Uint8Array,
    wrappedDeks: readonly RecoveryWrappedDEK[]
  ): Uint8Array {
    const sortedKeyIds = wrappedDeks.map((d) => d.keyId).sort().join(',');
    const canonical = `${recoveryId}:${bytesToHex(salt)}:${wrappedDeks.length}:${sortedKeyIds}`;

    const hmac = QuickCrypto.createHmac('sha256', recoveryKek);
    hmac.update(canonical);
    const digest = hmac.digest();

    // 16-byte authentication tag
    const result = new Uint8Array(16);
    result.set(digest.slice(0, 16));
    return result;
  }

  /**
   * Encodes 128-bit (16B) or 256-bit (32B) entropy into a 12-word or 24-word BIP39 mnemonic phrase.
   */
  private entropyToMnemonic(entropy: Uint8Array): string {
    const is12 = entropy.length === 16;
    const wordCount = is12 ? 12 : 24;
    const hash = this.sha256(entropy);

    let bitString = '';
    for (let i = 0; i < entropy.length; i++) {
      bitString += entropy[i].toString(2).padStart(8, '0');
    }
    const checksumBits = is12
      ? hash[0].toString(2).padStart(8, '0').slice(0, 4)
      : hash[0].toString(2).padStart(8, '0');
    bitString += checksumBits;

    const words: string[] = [];
    for (let i = 0; i < wordCount; i++) {
      const chunk = bitString.slice(i * 11, (i + 1) * 11);
      const index = parseInt(chunk, 2);
      words.push(getWord(index));
    }

    return words.join(' ');
  }

  /**
   * Decodes a 12-word or 24-word BIP39 mnemonic phrase into entropy and validates checksum.
   */
  private mnemonicToEntropy(phrase: string): { valid: boolean; entropy: Uint8Array | null } {
    const words = phrase.trim().toLowerCase().split(/\s+/);
    if (words.length !== 12 && words.length !== 24) {
      return { valid: false, entropy: null };
    }

    const is12 = words.length === 12;
    const entropyBitsCount = is12 ? 128 : 256;

    let totalBits = '';
    for (let i = 0; i < words.length; i++) {
      const wordIndex = getWordIndex(words[i]);
      if (wordIndex < 0 || wordIndex >= 2048) {
        return { valid: false, entropy: null };
      }
      totalBits += wordIndex.toString(2).padStart(11, '0');
    }

    const entropyBits = totalBits.slice(0, entropyBitsCount);
    const checksumBits = totalBits.slice(entropyBitsCount);

    const entropyBytesCount = entropyBitsCount / 8;
    const entropy = new Uint8Array(entropyBytesCount);
    for (let i = 0; i < entropyBytesCount; i++) {
      entropy[i] = parseInt(entropyBits.slice(i * 8, (i + 1) * 8), 2);
    }

    const hash = this.sha256(entropy);
    const expectedChecksumBits = is12
      ? hash[0].toString(2).padStart(8, '0').slice(0, 4)
      : hash[0].toString(2).padStart(8, '0');

    if (checksumBits !== expectedChecksumBits) {
      zeroize(entropy);
      return { valid: false, entropy: null };
    }

    return { valid: true, entropy };
  }

  /**
   * Helper to compute SHA-256 digest.
   */
  private sha256(data: Uint8Array): Uint8Array {
    const hash = QuickCrypto.createHash('sha256');
    hash.update(data);
    const buf = hash.digest();
    const result = new Uint8Array(buf.length);
    result.set(buf);
    return result;
  }

  /**
   * Constant-time equality comparison between two byte buffers using maintained crypto.
   */
  private timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
    return timingSafeEqual(a, b);
  }

  /**
   * Persists a RecoveryEnvelope to the database.
   */
  private async saveRecoveryEnvelope(envelope: RecoveryEnvelope): Promise<void> {
    const serialized: SerializedRecoveryEnvelope = {
      recoveryId: envelope.recoveryId,
      salt: bytesToHex(envelope.salt),
      params: {
        memoryCost: envelope.params.memoryCost,
        timeCost: envelope.params.timeCost,
        parallelism: envelope.params.parallelism,
        version: envelope.params.version,
      },
      wrappedDEKs: envelope.wrappedDEKs.map((d) => ({
        keyId: d.keyId,
        wrappedDEK: bytesToHex(d.wrappedDEK),
        nonce: bytesToHex(d.nonce),
        tag: bytesToHex(d.tag),
        keyVersion: d.keyVersion,
      })),
      checksum: bytesToHex(envelope.checksum),
      createdAt: envelope.createdAt,
    };

    const json = JSON.stringify(serialized);
    const buf = Buffer.from(json, 'utf8');
    const bytes = new Uint8Array(buf.length);
    bytes.set(buf);
    await this.database.store(RECOVERY_ENVELOPE_STORAGE_KEY, bytes);
  }

  /**
   * Loads and deserializes a RecoveryEnvelope from the database.
   */
  private async loadRecoveryEnvelope(): Promise<RecoveryEnvelope | null> {
    const rawBytes = await this.database.retrieve(RECOVERY_ENVELOPE_STORAGE_KEY);
    if (!rawBytes) {
      return null;
    }

    try {
      const json = Buffer.from(rawBytes).toString('utf8');
      const parsed: SerializedRecoveryEnvelope = JSON.parse(json);

      const salt = hexToBytes(parsed.salt);
      const params: RecoveryKdfParameters = {
        salt,
        memoryCost: parsed.params.memoryCost,
        timeCost: parsed.params.timeCost,
        parallelism: parsed.params.parallelism,
        version: parsed.params.version,
      };

      const wrappedDEKs: RecoveryWrappedDEK[] = parsed.wrappedDEKs.map((d) => ({
        keyId: d.keyId,
        wrappedDEK: hexToBytes(d.wrappedDEK),
        nonce: hexToBytes(d.nonce),
        tag: hexToBytes(d.tag),
        keyVersion: d.keyVersion,
      }));

      return {
        recoveryId: parsed.recoveryId,
        salt,
        params,
        wrappedDEKs,
        checksum: hexToBytes(parsed.checksum),
        createdAt: parsed.createdAt,
      };
    } catch {
      throw new GhostTagError({
        code: GhostTagErrorCode.VAULT_CORRUPT,
        userMessage: 'Corrupted recovery envelope record stored in vault database.',
        category: ErrorCategory.VAULT,
        severity: ErrorSeverity.CRITICAL,
      });
    }
  }
}
