/**
 * @file nfc.test.ts
 * @summary Unit tests for Ghost-Tag Phase 4 NFC Hardware Abstraction Layer.
 */

import {
  GhostNfcManager,
  TagReader,
  TagWriter,
  TagInfo,
  TagWiper,
  START_USER_PAGE,
  PAGE_SIZE_BYTES,
  buildGhostTagNdefRecord,
  buildGhostTagNdefMessage,
  extractGhostTagPayload,
  mapNfcError,
  NfcTag,
} from '../nfc';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import {
  SupportedTagFamily,
  UnsupportedTagFamily,
} from '../contracts/tags';
import {
  ENVELOPE_MIME_TYPE,
  ENVELOPE_FIXED_OVERHEAD_BYTES,
} from '../contracts/envelope';
import { ScanState, WriteState, WipeState } from '../contracts/states';
import NfcManager, { NfcError, Ndef } from 'react-native-nfc-manager';

jest.mock('react-native-nfc-manager', () => {
  class NfcErrorBase extends Error {}
  class RadioDisabled extends NfcErrorBase {}
  class UnsupportedFeature extends NfcErrorBase {}
  class TagConnectionLost extends NfcErrorBase {}
  class TagNotConnected extends NfcErrorBase {}
  class TagNotWritable extends NfcErrorBase {}
  class TagSizeTooSmall extends NfcErrorBase {}
  class TagUpdateFailure extends NfcErrorBase {}
  class FirstNdefInvalid extends NfcErrorBase {}
  class UserCancel extends NfcErrorBase {}
  class Timeout extends NfcErrorBase {}

  const mockNfcError = {
    NfcErrorBase,
    RadioDisabled,
    UnsupportedFeature,
    TagConnectionLost,
    TagNotConnected,
    TagNotWritable,
    TagSizeTooSmall,
    TagUpdateFailure,
    FirstNdefInvalid,
    UserCancel,
    Timeout,
  };

  const mockNdef = {
    TNF_EMPTY: 0x0,
    TNF_WELL_KNOWN: 0x01,
    TNF_MIME_MEDIA: 0x02,
    TNF_ABSOLUTE_URI: 0x03,
    TNF_EXTERNAL_TYPE: 0x04,
    TNF_UNKNOWN: 0x05,
    TNF_UNCHANGED: 0x06,
    TNF_RESERVED: 0x07,
    util: {
      stringToBytes: (str: string) => Array.from(str).map((c) => c.charCodeAt(0)),
      bytesToString: (bytes: number[]) => String.fromCharCode(...bytes),
    },
    record: (tnf: number, type: string | number[], id: number[] | string, payload: number[] | Uint8Array) => ({
      tnf,
      type: typeof type === 'string' ? type : String.fromCharCode(...type),
      id: Array.isArray(id) ? id : Array.from(id).map((c) => c.charCodeAt(0)),
      payload: Array.isArray(payload) ? payload : Array.from(payload),
    }),
    textRecord: (text: string) => ({
      tnf: 0x01,
      type: 'T',
      id: [],
      payload: Array.from(text).map((c) => c.charCodeAt(0)),
    }),
    encodeMessage: (records: any[]) => {
      let out: number[] = [];
      for (const r of records) {
        out = out.concat(r.payload);
      }
      return out;
    },
  };

  const pageStore = new Map<number, number[]>();

  return {
    __esModule: true,
    default: {
      start: jest.fn().mockResolvedValue(undefined),
      isSupported: jest.fn().mockResolvedValue(true),
      isEnabled: jest.fn().mockResolvedValue(true),
      registerTagEvent: jest.fn().mockResolvedValue(undefined),
      unregisterTagEvent: jest.fn().mockResolvedValue(undefined),
      setEventListener: jest.fn(),
      requestTechnology: jest.fn().mockResolvedValue(null),
      cancelTechnologyRequest: jest.fn().mockResolvedValue(undefined),
      getNdefMessage: jest.fn(),
      writeNdefMessage: jest.fn().mockResolvedValue(undefined),
      goToNfcSetting: jest.fn().mockResolvedValue(true),
      transceive: jest.fn().mockResolvedValue([0, 0, 0, 0]),
      mifareUltralightHandlerAndroid: {
        mifareUltralightWritePage: jest.fn().mockImplementation(async (page: number, data: number[]) => {
          pageStore.set(page, data.slice());
        }),
        mifareUltralightReadPages: jest.fn().mockImplementation(async (page: number) => {
          const p0 = pageStore.get(page) ?? [0, 0, 0, 0];
          const p1 = pageStore.get(page + 1) ?? [0, 0, 0, 0];
          const p2 = pageStore.get(page + 2) ?? [0, 0, 0, 0];
          const p3 = pageStore.get(page + 3) ?? [0, 0, 0, 0];
          return [...p0, ...p1, ...p2, ...p3];
        }),
      },
      ndefHandler: {
        getNdefMessage: jest.fn(),
        writeNdefMessage: jest.fn().mockResolvedValue(undefined),
      },
    },
    NfcEvents: {
      DiscoverTag: 'NfcManagerDiscoverTag',
      DiscoverBackgroundTag: 'NfcManagerDiscoverBackgroundTag',
      SessionClosed: 'NfcManagerSessionClosed',
      StateChanged: 'NfcManagerStateChanged',
    },
    NfcTech: {
      Ndef: 'Ndef',
      NfcA: 'NfcA',
      MifareUltralight: 'MifareUltralight',
      MifareClassic: 'MifareClassic',
      IsoDep: 'IsoDep',
    },
    Ndef: mockNdef,
    NfcError: mockNfcError,
  };
});

describe('Ghost-Tag Phase 4: NFC Hardware Abstraction Layer', () => {
  /**
   * Helper to construct a mock valid Ghost-Tag binary envelope buffer.
   * Total length = 54 + plaintextLen.
   */
  function createMockEnvelope(plaintextLen: number = 10): Uint8Array {
    const totalLen = ENVELOPE_FIXED_OVERHEAD_BYTES + plaintextLen;
    const buf = new Uint8Array(totalLen);

    // Magic: "GTAG" (0x47, 0x54, 0x41, 0x47)
    buf[0] = 0x47;
    buf[1] = 0x54;
    buf[2] = 0x41;
    buf[3] = 0x47;

    // Version = 1
    buf[4] = 0x01;
    // Purpose = 1 (NOTE)
    buf[5] = 0x01;

    // Key ID (16 bytes: bytes 6..21)
    for (let i = 0; i < 16; i++) {
      buf[6 + i] = 0x10 + i;
    }

    // Nonce (12 bytes: bytes 22..33)
    for (let i = 0; i < 12; i++) {
      buf[22 + i] = 0xa0 + i;
    }

    // Ciphertext length: uint32 LE at bytes 34..37
    buf[34] = plaintextLen & 0xff;
    buf[35] = (plaintextLen >> 8) & 0xff;
    buf[36] = (plaintextLen >> 16) & 0xff;
    buf[37] = (plaintextLen >> 24) & 0xff;

    // Ciphertext payload (bytes 38 .. 38 + plaintextLen - 1)
    for (let i = 0; i < plaintextLen; i++) {
      buf[38 + i] = 0x77;
    }

    // GCM Tag (16 bytes: last 16 bytes)
    const gcmOffset = totalLen - 16;
    for (let i = 0; i < 16; i++) {
      buf[gcmOffset + i] = 0xfe - i;
    }

    return buf;
  }

  // -------------------------------------------------------------------------
  // 1. Error Mapping Tests (errors.ts)
  // -------------------------------------------------------------------------
  describe('errors.ts - Error Mapping', () => {
    it('returns existing GhostTagError without modification', () => {
      const orig = new GhostTagError({
        code: GhostTagErrorCode.TAG_LOST,
        userMessage: 'Test lost',
        category: ErrorCategory.NFC,
        severity: ErrorSeverity.WARNING,
      });
      const mapped = mapNfcError(orig);
      expect(mapped).toBe(orig);
      expect(mapped.code).toBe(GhostTagErrorCode.TAG_LOST);
    });

    it('maps NfcError.RadioDisabled to NFC_DISABLED', () => {
      const err = new NfcError.RadioDisabled();
      const mapped = mapNfcError(err);
      expect(mapped.code).toBe(GhostTagErrorCode.NFC_DISABLED);
      expect(mapped.category).toBe(ErrorCategory.NFC);
    });

    it('maps NfcError.UnsupportedFeature to NFC_UNSUPPORTED', () => {
      const err = new NfcError.UnsupportedFeature();
      const mapped = mapNfcError(err);
      expect(mapped.code).toBe(GhostTagErrorCode.NFC_UNSUPPORTED);
    });

    it('maps NfcError.TagConnectionLost to TAG_LOST', () => {
      const err = new NfcError.TagConnectionLost();
      const mapped = mapNfcError(err);
      expect(mapped.code).toBe(GhostTagErrorCode.TAG_LOST);
    });

    it('maps NfcError.TagNotWritable to TAG_READ_ONLY', () => {
      const err = new NfcError.TagNotWritable();
      const mapped = mapNfcError(err);
      expect(mapped.code).toBe(GhostTagErrorCode.TAG_READ_ONLY);
    });

    it('maps NfcError.TagSizeTooSmall to TAG_CAPACITY_INSUFFICIENT', () => {
      const err = new NfcError.TagSizeTooSmall();
      const mapped = mapNfcError(err);
      expect(mapped.code).toBe(GhostTagErrorCode.TAG_CAPACITY_INSUFFICIENT);
    });

    it('maps string messages from Android native exceptions', () => {
      expect(mapNfcError('NFC is not enabled').code).toBe(GhostTagErrorCode.NFC_DISABLED);
      expect(mapNfcError('Tag was lost').code).toBe(GhostTagErrorCode.TAG_LOST);
      expect(mapNfcError('transceive fail').code).toBe(GhostTagErrorCode.TAG_LOST);
      expect(mapNfcError('Tag is read only').code).toBe(GhostTagErrorCode.TAG_READ_ONLY);
      expect(mapNfcError('out of memory').code).toBe(GhostTagErrorCode.TAG_CAPACITY_INSUFFICIENT);
      expect(mapNfcError('Tag is not ndef').code).toBe(GhostTagErrorCode.TAG_NOT_NDEF);
      expect(mapNfcError('write unverified mismatch').code).toBe(GhostTagErrorCode.TAG_WRITE_UNVERIFIED);
    });
  });

  // -------------------------------------------------------------------------
  // 2. NDEF Record & Message Construction (ndefBuilder.ts)
  // -------------------------------------------------------------------------
  describe('ndefBuilder.ts - NDEF Record Construction', () => {
    it('constructs NDEF MIME record with application/vnd.ghost.secure', () => {
      const envelope = createMockEnvelope(10);
      const record = buildGhostTagNdefRecord(envelope);

      expect(record.tnf).toBe(Ndef.TNF_MIME_MEDIA);
      expect(record.type).toBe(ENVELOPE_MIME_TYPE);
      expect(Array.isArray(record.payload)).toBe(true);
      expect(record.payload.length).toBe(envelope.length);

      // Verify payload bytes match raw binary envelope
      expect(new Uint8Array(record.payload)).toEqual(envelope);
    });

    it('rejects envelope smaller than fixed overhead', () => {
      const truncated = new Uint8Array(20);
      expect(() => buildGhostTagNdefRecord(truncated)).toThrow(GhostTagError);
    });

    it('rejects envelope with invalid magic bytes', () => {
      const badMagic = createMockEnvelope(10);
      badMagic[0] = 0x00; // Corrupt magic
      expect(() => buildGhostTagNdefRecord(badMagic)).toThrow(GhostTagError);
    });

    it('builds NDEF message with single record', () => {
      const envelope = createMockEnvelope(10);
      const message = buildGhostTagNdefMessage(envelope);
      expect(message.length).toBe(1);
      expect(message[0].type).toBe(ENVELOPE_MIME_TYPE);
    });

    it('extracts raw binary payload from valid GhostTag record', () => {
      const envelope = createMockEnvelope(10);
      const record = buildGhostTagNdefRecord(envelope);
      const extracted = extractGhostTagPayload(record);

      expect(extracted).not.toBeNull();
      expect(extracted).toEqual(envelope);
    });

    it('returns null when extracting payload from non-MIME record', () => {
      const nonMimeRecord = Ndef.textRecord('Hello');
      expect(extractGhostTagPayload(nonMimeRecord)).toBeNull();
    });
  });

  // -------------------------------------------------------------------------
  // 3. Tag Identification and Capacity (tagInfo.ts)
  // -------------------------------------------------------------------------
  describe('tagInfo.ts - Tag Information and Capacity', () => {
    const service = new TagInfo();

    it('identifies NTAG213 tag by maxSize', () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA', 'android.nfc.tech.MifareUltralight'],
        maxSize: 137,
        isWritable: true,
      };

      const ident = service.identifyTag(tag);
      expect(ident.family).toBe(SupportedTagFamily.NTAG213);
      expect(ident.isSupported).toBe(true);
      expect(ident.rawUserMemoryBytes).toBe(144);
      expect(ident.userPages).toBe(36);
    });

    it('identifies NTAG215 tag by maxSize', () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 492,
        isWritable: true,
      };

      const ident = service.identifyTag(tag);
      expect(ident.family).toBe(SupportedTagFamily.NTAG215);
      expect(ident.userPages).toBe(126);
    });

    it('identifies NTAG216 tag by maxSize', () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 872,
        isWritable: true,
      };

      const ident = service.identifyTag(tag);
      expect(ident.family).toBe(SupportedTagFamily.NTAG216);
      expect(ident.userPages).toBe(222);
    });

    it('identifies unsupported MIFARE Classic tags', () => {
      const tag: NfcTag = {
        id: '04A1B2C3',
        techTypes: ['android.nfc.tech.MifareClassic'],
        sak: 0x08,
      };

      const ident = service.identifyTag(tag);
      expect(ident.family).toBe(UnsupportedTagFamily.MIFARE_CLASSIC_1K);
      expect(ident.isSupported).toBe(false);
      expect(service.isTagSupported(tag)).toBe(false);
    });

    it('identifies unsupported MIFARE DESFire tags', () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.IsoDep'],
        sak: 0x20,
      };

      const ident = service.identifyTag(tag);
      expect(ident.family).toBe(UnsupportedTagFamily.MIFARE_DESFIRE);
      expect(ident.isSupported).toBe(false);
    });

    it('calculates available space correctly including TLV and MIME overhead', () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
      };

      const cap = service.getCapacity(tag);
      expect(cap.rawUserMemoryBytes).toBe(144);
      expect(cap.usableNdefBytes).toBe(137);
      expect(cap.ndefTlvOverheadBytes).toBe(7); // 144 - 137 = 7
      expect(cap.mimeRecordOverheadBytes).toBe(31); // short record MIME overhead
      expect(cap.envelopeOverheadBytes).toBe(54); // ENVELOPE_FIXED_OVERHEAD_BYTES
      expect(cap.totalOverheadBytes).toBe(7 + 31 + 54); // 92
      expect(cap.maxPlaintextBytes).toBe(144 - 92); // 52 bytes
      expect(cap.availablePlaintextBytes).toBe(52);
      expect(service.calculateAvailableSpace(tag)).toBe(52);
    });

    it('handles MIFARE Ultralight where envelope cannot fit', () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.MifareUltralight'],
        maxSize: 46,
      };

      const cap = service.getCapacity(tag);
      expect(cap.family).toBe(SupportedTagFamily.MIFARE_ULTRALIGHT);
      expect(cap.availablePlaintextBytes).toBe(0); // Clamped to 0
    });

    it('verifies tag writability', () => {
      const writableTag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        isWritable: true,
      };
      expect(service.isTagWritable(writableTag)).toBe(true);

      const readOnlyTag: NfcTag = {
        ...writableTag,
        isWritable: false,
      };
      expect(service.isTagWritable(readOnlyTag)).toBe(false);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Tag Reading (tagReader.ts)
  // -------------------------------------------------------------------------
  describe('tagReader.ts - Tag Reading', () => {
    const reader = new TagReader();

    it('reads tag and extracts Ghost-Tag envelope successfully', async () => {
      const envelope = createMockEnvelope(16);
      const record = buildGhostTagNdefRecord(envelope);

      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        ndefMessage: [record],
      };

      const result = await reader.readTag(tag);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.state).toBe(ScanState.NDEF_READ_COMPLETE);
        expect(result.rawEnvelope).toEqual(envelope);
        expect(result.ghostTagRecord.mimeType).toBe(ENVELOPE_MIME_TYPE);
      }
    });

    it('returns failure when tag is unsupported', async () => {
      const tag: NfcTag = {
        id: '04A1B2C3',
        techTypes: ['android.nfc.tech.MifareClassic'],
        sak: 0x08,
      };

      const result = await reader.readTag(tag);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(GhostTagErrorCode.TAG_UNSUPPORTED);
        expect(result.state).toBe(ScanState.ERROR);
      }
    });

    it('returns failure when tag contains no NDEF records', async () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        ndefMessage: [],
      };

      (NfcManager.getNdefMessage as jest.Mock).mockResolvedValueOnce(null);

      const result = await reader.readTag(tag);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(GhostTagErrorCode.TAG_NOT_NDEF);
      }
    });

    it('returns failure when NDEF message has no Ghost-Tag MIME record', async () => {
      const textRec = Ndef.textRecord('Random text');
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        ndefMessage: [textRec],
      };

      const result = await reader.readTag(tag);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(GhostTagErrorCode.INVALID_ENVELOPE);
      }
    });

    it('returns failure when envelope has corrupted magic marker', async () => {
      const corruptedEnv = createMockEnvelope(10);
      corruptedEnv[0] = 0x58; // Not 'G'

      const record = Ndef.record(
        Ndef.TNF_MIME_MEDIA,
        ENVELOPE_MIME_TYPE,
        [],
        Array.from(corruptedEnv)
      );

      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        ndefMessage: [record],
      };

      const result = await reader.readTag(tag);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(GhostTagErrorCode.INVALID_ENVELOPE);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 5. Tag Writing and Verification (tagWriter.ts)
  // -------------------------------------------------------------------------
  describe('tagWriter.ts - Tag Writing and Verification', () => {
    const writer = new TagWriter();

    it('rejects write if tag is read-only', async () => {
      const envelope = createMockEnvelope(10);
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        isWritable: false,
      };

      const result = await writer.writeEnvelope(tag, envelope);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.code).toBe(GhostTagErrorCode.TAG_READ_ONLY);
        expect(result.state).toBe(WriteState.WRITE_FAILED);
      }
    });

    it('writes envelope successfully', async () => {
      const envelope = createMockEnvelope(10);
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        isWritable: true,
      };

      (NfcManager.writeNdefMessage as jest.Mock).mockResolvedValueOnce(undefined);

      const result = await writer.writeEnvelope(tag, envelope);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.bytesWritten).toBe(envelope.length);
        expect(result.state).toBe(WriteState.WRITE_COMPLETE);
      }
    });

    it('verifies write when read-back matches source exactly', async () => {
      const envelope = createMockEnvelope(10);
      const record = buildGhostTagNdefRecord(envelope);

      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        ndefMessage: [record],
      };

      const verifyResult = await writer.verifyWrite(tag, envelope);
      expect(verifyResult.verified).toBe(true);
      if (verifyResult.verified) {
        expect(verifyResult.state).toBe(WriteState.WRITE_VERIFIED);
        expect(verifyResult.matchedBytes).toBe(envelope.length);
      }
    });

    it('fails verification when read-back GCM tag does not match', async () => {
      const envelope = createMockEnvelope(10);
      const corruptedReadBack = new Uint8Array(envelope);
      // Corrupt GCM tag (last byte)
      corruptedReadBack[corruptedReadBack.length - 1] ^= 0xff;

      const record = Ndef.record(
        Ndef.TNF_MIME_MEDIA,
        ENVELOPE_MIME_TYPE,
        [],
        Array.from(corruptedReadBack)
      );

      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        ndefMessage: [record],
      };

      const verifyResult = await writer.verifyWrite(tag, envelope);
      expect(verifyResult.verified).toBe(false);
      if (!verifyResult.verified) {
        expect(verifyResult.error.code).toBe(GhostTagErrorCode.TAG_WRITE_UNVERIFIED);
        expect(verifyResult.mismatchedField).toBe('GCM_TAG');
      }
    });

    it('executes atomic writeAndVerify successfully', async () => {
      const envelope = createMockEnvelope(10);
      const record = buildGhostTagNdefRecord(envelope);

      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.NfcA'],
        maxSize: 137,
        isWritable: true,
        ndefMessage: [record],
      };

      (NfcManager.writeNdefMessage as jest.Mock).mockResolvedValueOnce(undefined);

      const result = await writer.writeAndVerify(tag, envelope);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.state).toBe(WriteState.WRITE_VERIFIED);
        expect(result.envelope).toEqual(envelope);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 6. Destructive Tag Sanitization (tagWiper.ts)
  // -------------------------------------------------------------------------
  describe('tagWiper.ts - Destructive Wipe', () => {
    const wiper = new TagWiper();

    it('starts user memory at page 4 and preserves CC (page 3)', () => {
      expect(START_USER_PAGE).toBe(4);
      expect(PAGE_SIZE_BYTES).toBe(4);
    });

    it('executes multi-pass wipe across all user pages', async () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.MifareUltralight'],
        maxSize: 137, // NTAG213: 36 pages
        isWritable: true,
      };

      const result = await wiper.wipeTag(tag);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.state).toBe(WipeState.WIPE_COMPLETE);
        expect(result.pagesWiped).toBe(36);
        expect(result.totalPages).toBe(36);
        expect(result.verified).toBe(true);
      }
    });

    it('reports WIPE_PARTIAL if communication is severed midway', async () => {
      const tag: NfcTag = {
        id: '04A1B2C3D4E5F6',
        techTypes: ['android.nfc.tech.Ndef', 'android.nfc.tech.MifareUltralight'],
        maxSize: 137,
        isWritable: true,
      };

      let writeCount = 0;
      (NfcManager.mifareUltralightHandlerAndroid.mifareUltralightWritePage as jest.Mock).mockImplementation(
        async () => {
          writeCount++;
          if (writeCount > 10) {
            throw new Error('Tag was lost');
          }
        }
      );

      const result = await wiper.wipeTag(tag);
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.state).toBe(WipeState.WIPE_PARTIAL);
        expect(result.error.code).toBe(GhostTagErrorCode.WIPE_PARTIAL);
      }
    });
  });

  // -------------------------------------------------------------------------
  // 7. NFC Manager Lifecycle (nfcManager.ts)
  // -------------------------------------------------------------------------
  describe('nfcManager.ts - GhostNfcManager', () => {
    const manager = new GhostNfcManager();

    afterEach(() => {
      manager.dispose();
    });

    it('initializes and checks NFC availability', async () => {
      await manager.initialize();
      const supported = await manager.isNfcSupported();
      const enabled = await manager.isNfcEnabled();

      expect(supported).toBe(true);
      expect(enabled).toBe(true);
      expect(NfcManager.start).toHaveBeenCalled();
    });

    it('starts listening and registers Android foreground dispatch', async () => {
      const callback = jest.fn();
      await manager.startListening(callback);

      expect(NfcManager.registerTagEvent).toHaveBeenCalled();
      expect(NfcManager.setEventListener).toHaveBeenCalled();

      await manager.stopListening();
      expect(NfcManager.unregisterTagEvent).toHaveBeenCalled();
    });

    it('handles operation timeouts via withTimeout', async () => {
      const hangingOp = new Promise((resolve) => setTimeout(() => resolve('done'), 500));
      await expect(
        manager.withTimeout(hangingOp, 20, 'Test Scan')
      ).rejects.toThrow(GhostTagError);
    });
  });
});
