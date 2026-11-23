/**
 * @file apdu.js
 * @description Real PC/SC APDU Command Handlers for ACR122U and NFC Forum Type 2 Tags (NTAG213/215/216)
 */

const crypto = require('crypto');

// ACR122U Direct APDU Commands
const APDU = {
  // Get Card UID (returns UID + SW1 SW2 [90 00])
  GET_UID: Buffer.from([0xFF, 0xCA, 0x00, 0x00, 0x00]),

  // Read 4 bytes from specified block on NTAG / Ultralight: [FF, B0, 00, block, 04]
  readBlock(block) {
    return Buffer.from([0xFF, 0xB0, 0x00, block & 0xFF, 0x04]);
  },

  // Write 4 bytes to specified block on NTAG / Ultralight: [FF, D6, 00, block, 04, b0, b1, b2, b3]
  writeBlock(block, fourBytes) {
    if (fourBytes.length !== 4) {
      throw new Error(`NTAG block write requires exactly 4 bytes, got ${fourBytes.length}`);
    }
    return Buffer.concat([
      Buffer.from([0xFF, 0xD6, 0x00, block & 0xFF, 0x04]),
      Buffer.from(fourBytes)
    ]);
  }
};

/**
 * Transmits an APDU command to a smartcard via PC/SC reader protocol.
 * @param {object} reader - Connected PC/SC reader instance
 * @param {Buffer} apdu - APDU command bytes
 * @returns {Promise<Buffer>} Response buffer including SW1 SW2 status words
 */
function transmitApdu(reader, apdu) {
  return new Promise((resolve, reject) => {
    reader.transmit(apdu, 256, 2, (err, response) => {
      if (err) return reject(err);
      if (response.length < 2) return reject(new Error('Truncated APDU response received'));
      const sw1 = response[response.length - 2];
      const sw2 = response[response.length - 1];
      if (sw1 !== 0x90 || sw2 !== 0x00) {
        return reject(new Error(`APDU returned error status words: 0x${sw1.toString(16).padStart(2, '0')} 0x${sw2.toString(16).padStart(2, '0')}`));
      }
      resolve(response.slice(0, response.length - 2));
    });
  });
}

/**
 * Reads the hardware UID of the card on the ACR122U reader.
 */
async function getCardUid(reader) {
  const uidData = await transmitApdu(reader, APDU.GET_UID);
  return uidData.toString('hex').toUpperCase();
}

/**
 * Reads the Capability Container (CC) at block 3 to determine real capacity, model, and writable status.
 * Standard NFC Forum Type 2 Tag Layout:
 * Block 3: [CC0 (Magic 0xE1), CC1 (Version), CC2 (Size = UserMemory / 8), CC3 (Access / R/W)]
 */
async function readTagCapability(reader) {
  try {
    const cc = await transmitApdu(reader, APDU.readBlock(3));
    if (cc.length < 4 || cc[0] !== 0xE1) {
      return {
        isType2: false,
        model: 'Unsupported Tag',
        manufacturer: 'Unknown',
        totalBytes: 0,
        writableBytes: 0,
        ndefStatus: 'Unsupported Tag Format'
      };
    }

    const sizeByte = cc[2];
    const accessByte = cc[3];
    const isReadOnly = (accessByte & 0x0F) !== 0x00;

    let model = 'NFC Forum Type 2 Tag';
    let userMemoryBytes = sizeByte * 8;
    let totalBytes = userMemoryBytes + 36;
    let manufacturer = 'NXP Semiconductors';

    if (sizeByte === 0x12) {
      model = 'NXP NTAG213';
      totalBytes = 180;
      userMemoryBytes = 144; // Canonical NTAG213 user memory
    } else if (sizeByte === 0x3E) {
      model = 'NXP NTAG215';
      totalBytes = 540;
      userMemoryBytes = 504; // Canonical NTAG215 user memory (126 pages x 4B)
    } else if (sizeByte === 0x6D) {
      model = 'NXP NTAG216';
      totalBytes = 924;
      userMemoryBytes = 888; // Canonical NTAG216 user memory (222 pages x 4B)
    } else if (sizeByte === 0x06) {
      model = 'NXP Mifare Ultralight';
      totalBytes = 64;
      userMemoryBytes = 48;
    } else if (sizeByte === 0x1E) {
      model = 'NXP Mifare Ultralight C';
      totalBytes = 192;
      userMemoryBytes = 144;
    } else {
      manufacturer = 'Generic NFC Forum Type 2';
    }

    return {
      isType2: true,
      model,
      manufacturer,
      totalBytes,
      writableBytes: isReadOnly ? 0 : userMemoryBytes,
      ndefStatus: isReadOnly ? 'Read-Only' : 'Read/Write'
    };
  } catch (_err) {
    return {
      isType2: false,
      model: 'Unsupported Tag',
      manufacturer: 'Unknown',
      totalBytes: 0,
      writableBytes: 0,
      ndefStatus: 'Unsupported Tag Format'
    };
  }
}

/**
 * Reads NDEF user memory from an NFC Forum Type 2 tag (NTAG213/215/216).
 * Reads blocks sequentially from block 4 until the terminator TLV (0xFE) is encountered.
 */
async function readTagNdef(reader) {
  const blocks = [];
  const maxBlocksToRead = 230; // covers up to NTAG216 user memory (888 bytes = 222 blocks)

  for (let b = 4; b < maxBlocksToRead + 4; b++) {
    try {
      const blockData = await transmitApdu(reader, APDU.readBlock(b));
      blocks.push(blockData);
      // Fast check: if block contains 0xFE (terminator), we may have reached the end of TLV
      if (blockData.includes(0xFE)) {
        // Read one more block to be certain and stop
        break;
      }
    } catch {
      // Reached boundary of readable user memory for this chip
      break;
    }
  }

  if (blocks.length === 0) {
    throw new Error('Unable to read user memory from tag');
  }

  const userMemory = Buffer.concat(blocks);
  return parseNdefFromUserMemory(userMemory);
}

/**
 * Parses NDEF Message TLV from raw NTAG user memory.
 */
function parseNdefFromUserMemory(userMemory) {
  let offset = 0;
  let ndefBuffer = null;

  while (offset < userMemory.length) {
    const tagType = userMemory[offset++];
    if (tagType === 0x00) continue; // NULL TLV
    if (tagType === 0xFE) break;   // Terminator TLV

    if (offset >= userMemory.length) break;
    let length = userMemory[offset++];
    if (length === 0xFF) {
      if (offset + 2 > userMemory.length) break;
      length = (userMemory[offset] << 8) | userMemory[offset + 1];
      offset += 2;
    }

    if (tagType === 0x03) { // NDEF Message TLV
      if (offset + length <= userMemory.length) {
        ndefBuffer = userMemory.slice(offset, offset + length);
      }
      break;
    } else {
      offset += length; // Skip other TLVs (Lock, Memory control, proprietary)
    }
  }

  if (!ndefBuffer || ndefBuffer.length === 0) {
    return { records: [], rawBytes: [] };
  }

  const records = parseNdefRecords(ndefBuffer);
  return {
    records,
    rawBytes: Array.from(ndefBuffer)
  };
}

/**
 * Parses raw NDEF records into structured objects.
 */
function parseNdefRecords(buffer) {
  const records = [];
  let offset = 0;

  while (offset < buffer.length) {
    const header = buffer[offset++];
    // Bit 7: Message Begin (MB), Bit 5: Chunk Flag (CF)
    const me = (header & 0x40) !== 0; // Message End
    const sr = (header & 0x10) !== 0; // Short Record
    const il = (header & 0x08) !== 0; // ID Length Present
    const tnf = header & 0x07;       // Type Name Format

    if (offset >= buffer.length) break;
    const typeLength = buffer[offset++];

    let payloadLength = 0;
    if (sr) {
      if (offset >= buffer.length) break;
      payloadLength = buffer[offset++];
    } else {
      if (offset + 4 > buffer.length) break;
      payloadLength = buffer.readUInt32BE(offset);
      offset += 4;
    }

    let idLength = 0;
    if (il) {
      if (offset >= buffer.length) break;
      idLength = buffer[offset++];
    }

    if (offset + typeLength > buffer.length) break;
    const typeBytes = buffer.slice(offset, offset + typeLength);
    offset += typeLength;

    if (il && offset + idLength <= buffer.length) {
      offset += idLength;
    }

    if (offset + payloadLength > buffer.length) break;
    const payload = buffer.slice(offset, offset + payloadLength);
    offset += payloadLength;

    let mediaType = '';
    if (tnf === 0x02) { // MIME Media Type
      mediaType = typeBytes.toString('utf-8');
    }

    records.push({
      recordType: tnf === 0x02 ? 'mime' : 'well-known',
      mediaType,
      data: Array.from(payload)
    });

    if (me) break; // Message End flag set
  }

  return records;
}

/**
 * Builds an NDEF message buffer for a given MIME type and payload.
 */
function buildMimeNdefMessage(mediaType, payloadBuffer) {
  const typeBytes = Buffer.from(mediaType, 'utf-8');
  const isShortRecord = payloadBuffer.length <= 255;
  const header = 0xD2 | (isShortRecord ? 0x10 : 0x00); // MB=1, ME=1, SR, TNF=2 (MIME)

  const headerList = [Buffer.from([header, typeBytes.length])];
  if (isShortRecord) {
    headerList.push(Buffer.from([payloadBuffer.length]));
  } else {
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(payloadBuffer.length, 0);
    headerList.push(lenBuf);
  }
  headerList.push(typeBytes);
  headerList.push(payloadBuffer);

  return Buffer.concat(headerList);
}

/**
 * Writes an NDEF record to NTAG memory starting at block 4, then reads it back to verify.
 */
async function writeTagNdefAndVerify(reader, mediaType, payloadBuffer) {
  // Pre-flight hardware checks: verify Type 2 support, lock state, and real tag capacity
  const capability = await readTagCapability(reader);
  if (!capability.isType2) {
    throw new Error('Unsupported tag: write requires an NFC Forum Type 2 tag (NTAG213, NTAG215, or NTAG216).');
  }
  if (capability.writableBytes === 0) {
    throw new Error('Tag is read-only or locked: write prohibited.');
  }

  const ndefMessage = buildMimeNdefMessage(mediaType, payloadBuffer);

  // Wrap in NDEF Message TLV (0x03) + Terminator TLV (0xFE)
  let tlvHeader;
  if (ndefMessage.length < 0xFF) {
    tlvHeader = Buffer.from([0x03, ndefMessage.length]);
  } else {
    tlvHeader = Buffer.from([0x03, 0xFF, (ndefMessage.length >> 8) & 0xFF, ndefMessage.length & 0xFF]);
  }

  const rawUserMemory = Buffer.concat([tlvHeader, ndefMessage, Buffer.from([0xFE])]);
  // Pad to multiple of 4 bytes
  const remainder = rawUserMemory.length % 4;
  const paddingLength = remainder === 0 ? 0 : 4 - remainder;
  const fullPayload = Buffer.concat([rawUserMemory, Buffer.alloc(paddingLength, 0x00)]);

  if (fullPayload.length > capability.writableBytes) {
    throw new Error(`Tag capacity exceeded: payload requires ${fullPayload.length} bytes, but tag capacity is ${capability.writableBytes} bytes.`);
  }

  // Write block by block starting at block 4
  const numBlocks = fullPayload.length / 4;
  for (let i = 0; i < numBlocks; i++) {
    const blockNumber = 4 + i;
    const blockData = fullPayload.slice(i * 4, (i + 1) * 4);
    await transmitApdu(reader, APDU.writeBlock(blockNumber, blockData));
  }

  // --- Real Read-Back Verification Step ---
  const readBack = await readTagNdef(reader);
  if (!readBack.records || readBack.records.length === 0) {
    throw new Error('Read-back verification failed: no NDEF record found after write');
  }

  const writtenRecord = readBack.records[0];
  const writtenPayload = Buffer.from(writtenRecord.data);

  if (writtenPayload.length !== payloadBuffer.length) {
    throw new Error(`Read-back length mismatch: expected ${payloadBuffer.length} bytes, got ${writtenPayload.length} bytes`);
  }

  const originalHash = crypto.createHash('sha256').update(payloadBuffer).digest('hex');
  const readBackHash = crypto.createHash('sha256').update(writtenPayload).digest('hex');

  if (originalHash !== readBackHash) {
    throw new Error('Read-back cryptographic integrity failure: payload hash mismatch');
  }

  return {
    verified: true,
    sha256: readBackHash,
    bytesWritten: payloadBuffer.length
  };
}

/**
 * Calculates exact NDEF storage requirements and maximum envelope/payload sizes
 * for a given tag user memory capacity and MIME type.
 *
 * Accounts for:
 * - NDEF Record Header (MB, ME, CF, SR, IL, TNF=0x02 MIME)
 * - Type Length and Payload Length (1 byte for SR <= 255, 4 bytes for normal > 255)
 * - MIME Type string bytes (e.g. 'application/vnd.ghost.secure' [28B] or 'application/vnd.ghost.bulk' [26B])
 * - Type 2 NDEF Message TLV Header (0x03, 1 byte length if < 255, 3 bytes [0xFF, len_hi, len_lo] if >= 255)
 * - Terminator TLV (0xFE, 1 byte)
 * - 4-byte block/page alignment padding
 */
function calculateTagCapacity(userMemoryBytes, mimeType = 'application/vnd.ghost.secure') {
  function getRequiredStorage(envelopeSize) {
    const typeBytesLen = Buffer.byteLength(mimeType, 'utf-8');
    const isShortRecord = envelopeSize <= 255;
    const recordHeaderLen = 1 + 1 + (isShortRecord ? 1 : 4) + typeBytesLen;
    const ndefMessageLen = recordHeaderLen + envelopeSize;
    const tlvHeaderLen = ndefMessageLen < 255 ? 2 : 4;
    const rawStorage = tlvHeaderLen + ndefMessageLen + 1; // +1 for terminator TLV (0xFE)
    const remainder = rawStorage % 4;
    const paddedStorage = remainder === 0 ? rawStorage : rawStorage + (4 - remainder);
    return {
      envelopeSize,
      ndefMessageLen,
      rawStorage,
      paddedStorage,
      fits: paddedStorage <= userMemoryBytes
    };
  }

  let maxEnvelopeSize = 0;
  for (let s = 1; s <= userMemoryBytes; s++) {
    const res = getRequiredStorage(s);
    if (res.fits) {
      maxEnvelopeSize = s;
    } else {
      break;
    }
  }

  const isBulk = mimeType.includes('bulk');
  const fixedOverhead = isBulk ? 134 : 54;
  const maxCiphertextPayload = maxEnvelopeSize >= fixedOverhead ? maxEnvelopeSize - fixedOverhead : 0;

  return {
    userMemoryBytes,
    mimeType,
    maxEnvelopeSize,
    fixedEnvelopeOverhead: fixedOverhead,
    maxCiphertextPayload,
    fits: maxEnvelopeSize >= fixedOverhead,
    getRequiredStorage
  };
}

module.exports = {
  APDU,
  transmitApdu,
  getCardUid,
  readTagCapability,
  calculateTagCapacity,
  readTagNdef,
  parseNdefRecords,
  parseNdefFromUserMemory,
  writeTagNdefAndVerify,
  buildMimeNdefMessage
};
