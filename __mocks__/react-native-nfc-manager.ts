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

export const NfcError = {
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

export const Ndef = {
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
  record: (
    tnf: number,
    type: string | number[],
    id: number[] | string,
    payload: number[] | Uint8Array
  ) => ({
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
  encodeMessage: (records: any[]) => records,
};

export const NfcTech = {
  NfcA: 'NfcA',
  NfcB: 'NfcB',
  NfcF: 'NfcF',
  NfcV: 'NfcV',
  IsoDep: 'IsoDep',
  Ndef: 'Ndef',
  MifareClassic: 'MifareClassic',
  MifareUltralight: 'MifareUltralight',
  NdefFormatable: 'NdefFormatable',
};

export const NfcEvents = {
  DiscoverTag: 'DiscoverTag',
  SessionClosed: 'SessionClosed',
  StateChanged: 'StateChanged',
};

const mockNfcManager = {
  start: jest.fn().mockResolvedValue(undefined),
  isSupported: jest.fn().mockResolvedValue(true),
  isEnabled: jest.fn().mockResolvedValue(true),
  registerTagEvent: jest.fn().mockResolvedValue(undefined),
  unregisterTagEvent: jest.fn().mockResolvedValue(undefined),
  setEventListener: jest.fn(),
  goToNfcSetting: jest.fn().mockResolvedValue(true),
  cancelTechnologyRequest: jest.fn().mockResolvedValue(undefined),
  requestTechnology: jest.fn().mockResolvedValue(undefined),
  ndefHandler: {
    getNdefMessage: jest.fn().mockResolvedValue(null),
    writeNdefMessage: jest.fn().mockResolvedValue(undefined),
    makeReadOnly: jest.fn().mockResolvedValue(undefined),
  },
  mifareUltralightHandlerAndroid: {
    readPages: jest.fn().mockResolvedValue([0, 0, 0, 0]),
    writePage: jest.fn().mockResolvedValue(undefined),
  },
};

export default mockNfcManager;
