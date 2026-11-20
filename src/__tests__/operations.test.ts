/**
 * @file operations.test.ts
 * @summary Unit and Integration Tests for Ghost-Tag Tag Operations Engine.
 */

import { ScanOperation } from '../operations/scanOperation';
import { WriteOperation } from '../operations/writeOperation';
import { WipeOperation } from '../operations/wipeOperation';
import { VerifyOperation } from '../operations/verifyOperation';
import { DiagnosticsExporter } from '../operations/diagnosticsExporter';
import { OperationCoordinator } from '../operations/operationCoordinator';

import { VaultManager } from '../vault/vaultManager';
import { TagReader } from '../nfc/tagReader';
import { TagWriter } from '../nfc/tagWriter';
import { TagWiper } from '../nfc/tagWiper';
import { TagInfo } from '../nfc/tagInfo';
import { GhostNfcManager } from '../nfc/nfcManager';

import { ScanState, WriteState, WipeState } from '../contracts/states';
import { EnvelopePurpose, ENVELOPE_FORMAT_VERSION_V1, ENVELOPE_MAGIC } from '../contracts/envelope';
import { GhostTagErrorCode } from '../contracts/errors';
import { SupportedTagFamily } from '../contracts/tags';

import { encrypt } from '../crypto/aesGcm';
import { constructAAD, serializeEnvelope } from '../crypto/envelope';
import { generateKeyId, generateNonce } from '../crypto/random';
import { hexToBytes } from '../crypto/keyWrap';

// Mock dependencies
jest.mock('react-native-mmkv');
jest.mock('react-native-nfc-manager');
jest.mock('react-native-keychain');

describe('Ghost-Tag Tag Operations Engine Suite', () => {
  let vaultManager: VaultManager;
  let mockReader: jest.Mocked<TagReader>;
  let mockWriter: jest.Mocked<TagWriter>;
  let mockWiper: jest.Mocked<TagWiper>;
  let tagInfo: TagInfo;
  let mockNfcManager: jest.Mocked<GhostNfcManager>;

  const testPassphrase = 'correct-horse-battery-staple-ghost-tag-2026';

  const sampleTag: any = {
    id: '04A1B2C3D4E5F6',
    techList: ['android.nfc.tech.NfcA', 'android.nfc.tech.Ndef'],
    maxSize: 504, // NTAG215
    isWritable: true,
  };

  beforeEach(async () => {
    vaultManager = new VaultManager();
    await vaultManager.createVault(testPassphrase);

    mockReader = {
      readTag: jest.fn(),
      readNdefMessage: jest.fn(),
      findGhostTagRecord: jest.fn(),
    } as unknown as jest.Mocked<TagReader>;

    mockWriter = {
      writeEnvelope: jest.fn(),
      verifyWrite: jest.fn(),
      writeAndVerify: jest.fn(),
    } as unknown as jest.Mocked<TagWriter>;

    mockWiper = {
      wipeTag: jest.fn(),
      verifyWipe: jest.fn(),
    } as unknown as jest.Mocked<TagWiper>;

    mockNfcManager = {
      initialize: jest.fn().mockResolvedValue(undefined),
      isNfcSupported: jest.fn().mockResolvedValue(true),
      isNfcEnabled: jest.fn().mockResolvedValue(true),
      startListening: jest.fn().mockResolvedValue(undefined),
      stopListening: jest.fn().mockResolvedValue(undefined),
      dispose: jest.fn(),
    } as unknown as jest.Mocked<GhostNfcManager>;

    tagInfo = new TagInfo();
  });

  afterEach(() => {
    vaultManager.lockVault();
  });

  describe('ScanOperation', () => {
    it('executes full scan and decrypts envelope successfully', async () => {
      const session = await vaultManager.openVault(testPassphrase);
      const kek = session.getKEK()!;
      const dekManager = vaultManager.getDEKManager();
      const wrappedDek = await dekManager.createDEK(kek);
      const keyIdBytes = hexToBytes(wrappedDek.keyId);
      const dek = await dekManager.getDEK(keyIdBytes, kek);

      const plaintext = 'Secret recovery payload 2026';
      const plaintextBytes = new TextEncoder().encode(plaintext);

      const aad = constructAAD(
        ENVELOPE_FORMAT_VERSION_V1,
        EnvelopePurpose.NOTE,
        keyIdBytes,
        plaintextBytes.length
      );
      const { ciphertext, nonce, tag: gcmTag } = encrypt(dek, plaintextBytes, aad);

      const envelopeBytes = serializeEnvelope({
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose: EnvelopePurpose.NOTE,
          keyId: keyIdBytes,
          nonce,
          ciphertextLength: ciphertext.length,
        },
        ciphertext,
        gcmTag,
      });

      mockReader.readTag.mockResolvedValueOnce({
        success: true,
        envelopeBytes,
        rawEnvelope: envelopeBytes,
        isGhostTag: true,
      } as any);

      const scanOp = new ScanOperation(vaultManager, mockReader, tagInfo);
      const stateHistory: ScanState[] = [];
      const result = await scanOp.execute(sampleTag, (ctx) => {
        stateHistory.push(ctx.state);
      });

      expect(result.success).toBe(true);
      expect(result.plaintext).toBe(plaintext);
      expect(stateHistory).toContain(ScanState.TAG_DETECTED);
      expect(stateHistory).toContain(ScanState.TECHNOLOGY_IDENTIFIED);
      expect(stateHistory).toContain(ScanState.NDEF_READING);
      expect(stateHistory).toContain(ScanState.ENVELOPE_PARSING);
      expect(stateHistory).toContain(ScanState.KEY_RESOLVING);
      expect(stateHistory).toContain(ScanState.DECRYPTING);
      expect(stateHistory).toContain(ScanState.VERIFIED);
      expect(stateHistory).toContain(ScanState.DISPLAYING);
    });

    it('rejects unsupported tag technology', async () => {
      const unsupportedTag: any = {
        id: '01020304',
        techList: ['android.nfc.tech.MifareClassic'],
      };

      const scanOp = new ScanOperation(vaultManager, mockReader, tagInfo);
      const result = await scanOp.execute(unsupportedTag);

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(GhostTagErrorCode.TAG_UNSUPPORTED);
    });

    it('fails gracefully when vault is locked and key cannot be unwrapped', async () => {
      vaultManager.lockVault(); // Ensure locked

      const keyId = generateKeyId();
      const nonce = generateNonce();
      const fakeEnvelopeBytes = serializeEnvelope({
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose: EnvelopePurpose.NOTE,
          keyId,
          nonce,
          ciphertextLength: 16,
        },
        ciphertext: new Uint8Array(16),
        gcmTag: new Uint8Array(16),
      });

      mockReader.readTag.mockResolvedValueOnce({
        success: true,
        envelopeBytes: fakeEnvelopeBytes,
        rawEnvelope: fakeEnvelopeBytes,
        isGhostTag: true,
      } as any);

      const scanOp = new ScanOperation(vaultManager, mockReader, tagInfo);
      const result = await scanOp.execute(sampleTag);

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(GhostTagErrorCode.KEY_UNAVAILABLE);
    });
  });

  describe('WriteOperation', () => {
    it('encrypts, writes, and verifies payload with read-back verification', async () => {
      await vaultManager.openVault(testPassphrase);

      mockWriter.writeAndVerify.mockResolvedValueOnce({
        success: true,
        state: WriteState.WRITE_VERIFIED,
      } as any);

      const writeOp = new WriteOperation(vaultManager, mockWriter, tagInfo);
      const stateHistory: WriteState[] = [];
      const result = await writeOp.execute(
        sampleTag,
        {
          plaintext: 'Encrypted token: 8f9b2c4e',
          purpose: EnvelopePurpose.CREDENTIAL,
        },
        (ctx) => stateHistory.push(ctx.state)
      );

      expect(result.success).toBe(true);
      expect(result.keyId).toBeDefined();
      expect(mockWriter.writeAndVerify).toHaveBeenCalledTimes(1);
      expect(stateHistory).toContain(WriteState.TAG_DETECTED);
      expect(stateHistory).toContain(WriteState.CAPACITY_CHECKED);
      expect(stateHistory).toContain(WriteState.ENVELOPE_PREPARED);
      expect(stateHistory).toContain(WriteState.WRITE_IN_PROGRESS);
      expect(stateHistory).toContain(WriteState.WRITE_VERIFIED);
    });

    it('rejects payload exceeding tag capacity', async () => {
      await vaultManager.openVault(testPassphrase);

      // Oversized payload for NTAG215 (usable space ~440 bytes)
      const hugePlaintext = 'A'.repeat(600);

      const writeOp = new WriteOperation(vaultManager, mockWriter, tagInfo);
      const result = await writeOp.execute(sampleTag, { plaintext: hugePlaintext });

      expect(result.success).toBe(false);
      expect(result.error?.code).toBe(GhostTagErrorCode.PAYLOAD_TOO_LARGE);
      expect(mockWriter.writeAndVerify).not.toHaveBeenCalled();
    });

    it('rejects empty plaintext string and empty Uint8Array', async () => {
      await vaultManager.openVault(testPassphrase);
      const writeOp = new WriteOperation(vaultManager, mockWriter, tagInfo);

      // Test empty string
      const emptyStrResult = await writeOp.execute(sampleTag, { plaintext: '' });
      expect(emptyStrResult.success).toBe(false);
      expect(emptyStrResult.error?.code).toBe(GhostTagErrorCode.PAYLOAD_TOO_LARGE);
      expect(emptyStrResult.error?.userMessage).toBe('Payload cannot be empty.');

      // Test empty byte array
      const emptyBytesResult = await writeOp.execute(sampleTag, { plaintext: new Uint8Array(0) });
      expect(emptyBytesResult.success).toBe(false);
      expect(emptyBytesResult.error?.code).toBe(GhostTagErrorCode.PAYLOAD_TOO_LARGE);
      expect(emptyBytesResult.error?.userMessage).toBe('Payload cannot be empty.');

      // Test non-string, non-Uint8Array input (rejected as an invalid envelope)
      const nullResult = await writeOp.execute(sampleTag, { plaintext: null as any });
      expect(nullResult.success).toBe(false);
      expect(nullResult.error?.code).toBe(GhostTagErrorCode.INVALID_ENVELOPE);
      expect(nullResult.error?.userMessage).toBe('Payload must be a string or a Uint8Array.');

      // None of the rejected inputs may reach the physical writer
      expect(mockWriter.writeAndVerify).not.toHaveBeenCalled();
    });

    it('accepts a non-empty Uint8Array payload exactly once into the write pipeline', async () => {
      await vaultManager.openVault(testPassphrase);

      mockWriter.writeAndVerify.mockResolvedValueOnce({
        success: true,
        state: WriteState.WRITE_VERIFIED,
      } as any);

      const writeOp = new WriteOperation(vaultManager, mockWriter, tagInfo);
      const result = await writeOp.execute(sampleTag, {
        plaintext: new Uint8Array([0x67, 0x68, 0x6f, 0x73, 0x74]),
      });

      expect(result.success).toBe(true);
      expect(result.context.state).toBe(WriteState.WRITE_VERIFIED);
      expect(mockWriter.writeAndVerify).toHaveBeenCalledTimes(1);
    });

    it('handles WRITE_UNVERIFIED terminal state when read-back fails', async () => {
      await vaultManager.openVault(testPassphrase);

      mockWriter.writeAndVerify.mockResolvedValueOnce({
        success: false,
        state: WriteState.WRITE_UNVERIFIED,
      } as any);

      const writeOp = new WriteOperation(vaultManager, mockWriter, tagInfo);
      const result = await writeOp.execute(sampleTag, { plaintext: 'Important data' });

      expect(result.success).toBe(false);
      expect(result.context.state).toBe(WriteState.WRITE_UNVERIFIED);
      expect(result.error?.code).toBe(GhostTagErrorCode.WRITE_UNVERIFIED);
    });
  });

  describe('WipeOperation', () => {
    it('executes complete multi-pass wipe and verifies', async () => {
      mockWiper.wipeTag.mockResolvedValueOnce({
        success: true,
        state: WipeState.WIPE_COMPLETE,
      } as any);

      const wipeOp = new WipeOperation(mockWiper, tagInfo);
      const stateHistory: WipeState[] = [];
      const result = await wipeOp.execute(sampleTag, (ctx) => {
        stateHistory.push(ctx.state);
      });

      expect(result.success).toBe(true);
      expect(result.context.state).toBe(WipeState.WIPE_COMPLETE);
      expect(mockWiper.wipeTag).toHaveBeenCalledWith(sampleTag);
    });

    it('detects and flags WIPE_PARTIAL if interrupted', async () => {
      mockWiper.wipeTag.mockResolvedValueOnce({
        success: false,
        state: WipeState.WIPE_PARTIAL,
      } as any);

      const wipeOp = new WipeOperation(mockWiper, tagInfo);
      const result = await wipeOp.execute(sampleTag);

      expect(result.success).toBe(false);
      expect(result.context.state).toBe(WipeState.WIPE_PARTIAL);
      expect(result.error?.code).toBe(GhostTagErrorCode.WIPE_PARTIAL);
    });
  });

  describe('VerifyOperation', () => {
    it('validates a recognized envelope passively', async () => {
      const session = await vaultManager.openVault(testPassphrase);
      const kek = session.getKEK()!;
      const dekManager = vaultManager.getDEKManager();
      const wrappedDek = await dekManager.createDEK(kek);
      const keyIdBytes = hexToBytes(wrappedDek.keyId);

      const fakeEnvelopeBytes = serializeEnvelope({
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose: EnvelopePurpose.NOTE,
          keyId: keyIdBytes,
          nonce: generateNonce(),
          ciphertextLength: 16,
        },
        ciphertext: new Uint8Array(16),
        gcmTag: new Uint8Array(16),
      });

      mockReader.readTag.mockResolvedValueOnce({
        success: true,
        envelopeBytes: fakeEnvelopeBytes,
        rawEnvelope: fakeEnvelopeBytes,
        isGhostTag: true,
      } as any);

      const verifyOp = new VerifyOperation(vaultManager, mockReader, tagInfo);
      const result = await verifyOp.execute(sampleTag);

      expect(result.isValidGhostTag).toBe(true);
      expect(result.isRecognizedKey).toBe(true);
      expect(result.keyIdHex).toBe(wrappedDek.keyId);
    });
  });

  describe('DiagnosticsExporter', () => {
    it('exports sanitized report with strict zero-secrets enforcement', async () => {
      await vaultManager.openVault(testPassphrase);

      const exporter = new DiagnosticsExporter(vaultManager, mockNfcManager, tagInfo);
      const report = await exporter.generateReport(sampleTag);

      expect(report.platform).toBe('android');
      expect(report.nfcStatus.isSupported).toBe(true);
      expect(report.vaultStatus.isInitialized).toBe(true);
      expect(report.vaultStatus.isUnlocked).toBe(true);
      expect(report.inspectedTag?.family).toBe(SupportedTagFamily.NTAG215);

      // Verify ZERO sensitive fields
      const reportJson = JSON.stringify(report);
      expect(reportJson).not.toContain(testPassphrase);
      expect(reportJson).not.toContain('plaintext');
      expect(reportJson).not.toContain('recovery_phrase');
      expect(reportJson).not.toContain('kek');
      expect(reportJson).not.toContain('dek');
    });
  });

  describe('OperationCoordinator', () => {
    it('initializes and manages scanning lifecycle', async () => {
      const coordinator = new OperationCoordinator(
        vaultManager,
        mockNfcManager,
        mockReader,
        mockWriter,
        mockWiper,
        tagInfo
      );

      const tagCallback = jest.fn();
      await coordinator.startListening(tagCallback);
      expect(mockNfcManager.startListening).toHaveBeenCalledWith(tagCallback);

      await coordinator.stopListening();
      expect(mockNfcManager.stopListening).toHaveBeenCalled();
    });
  });
});
