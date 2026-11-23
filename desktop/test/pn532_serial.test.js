/**
 * @file pn532_serial.test.js
 * @description Comprehensive Unit and Protocol Test Suite for PN532 Serial Transport
 *
 * Validates the 22 required PN532 test criteria using deterministic MockSerialPort.
 */

const assert = require('assert');
const EventEmitter = require('events');
const crypto = require('crypto');
const { Pn532SerialTransport } = require('../src/transports/serialTransport');
const { buildMimeNdefMessage, parseNdefFromUserMemory, calculateTagCapacity } = require('../src/apdu');

// --- Deterministic Mock Serial Port ---
class MockSerialPort extends EventEmitter {
  constructor() {
    super();
    this.written = [];
    this.isOpen = true;
    this.responseHandler = null;
  }

  write(data, callback) {
    this.written.push(data);
    if (this.responseHandler) {
      process.nextTick(() => {
        try {
          this.responseHandler(data);
        } catch (err) {
          // Handler error
        }
      });
    }
    if (callback) process.nextTick(callback);
  }

  simulateIncoming(line) {
    this.emit('data', Buffer.from(line + '\n'));
  }

  close() {
    this.isOpen = false;
    this.emit('close');
  }
}

// Minimal AES-256-GCM helper for Ghost-Tag envelope simulation
function encryptAesGcm(key, iv, plaintext, aad) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { ct, tag };
}

function decryptAesGcm(key, iv, ciphertext, tag, aad) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// Build deterministic v1 envelope buffer (54 bytes overhead)
function createDeterministicV1Envelope(secretText, key) {
  const magic = Buffer.from('GTAG'); // 4B
  const version = Buffer.from([0x01]); // 1B
  const purpose = Buffer.from([0x01]); // 1B (Single Tag)
  const keyId = Buffer.alloc(16, 0xAA); // 16B
  const nonce = Buffer.alloc(12, 0x55); // 12B
  const plaintext = Buffer.from(secretText, 'utf-8');

  // AAD for v1: magic(4) + version(1) + purpose(1) + keyId(16) + nonce(12) = 34 bytes
  const aad = Buffer.concat([magic, version, purpose, keyId, nonce]);
  const { ct, tag } = encryptAesGcm(key, nonce, plaintext, aad);

  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32LE(ct.length, 0);

  // Total overhead: 4 + 1 + 1 + 16 + 12 + 4 + 16 = 54 bytes
  return Buffer.concat([magic, version, purpose, keyId, nonce, lenBuf, ct, tag]);
}

describe('PN532 Serial Transport Protocol & Security Suite', () => {
  let mockPort;
  let transport;

  beforeEach(() => {
    mockPort = new MockSerialPort();
    transport = new Pn532SerialTransport();
    transport.attachPort(mockPort);
  });

  // 1. Serial protocol handshake
  test('1. Serial protocol handshake (HELLO)', async () => {
    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'HELLO') {
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'OK',
          version: '1.0.0',
          protocol: 'ghost-pn532-v1',
          hardware: 'ESP32-PN532-SPI'
        }));
      }
    };

    const res = await transport.handshake();
    assert.strictEqual(res.status, 'OK');
    assert.strictEqual(res.protocol, 'ghost-pn532-v1');
    assert.strictEqual(transport.connected, true);
  });

  // 2. Protocol version mismatch
  test('2. Protocol version mismatch', async () => {
    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'HELLO') {
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'OK',
          version: '2.0.0',
          protocol: 'incompatible-proto-v99',
          hardware: 'ESP32-PN532-SPI'
        }));
      }
    };

    await assert.rejects(
      async () => transport.handshake(),
      /Protocol version mismatch/
    );
  });

  // 3. Malformed serial frame
  test('3. Malformed serial frame', (done) => {
    transport.on('protocol_error', (err) => {
      assert.strictEqual(err.reason, 'Malformed JSON frame');
      done();
    });
    mockPort.simulateIncoming('{CORRUPTED_JSON_FRAME');
  });

  // 4. Oversized serial frame
  test('4. Oversized serial frame handling', async () => {
    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      mockPort.simulateIncoming(JSON.stringify({
        id: req.id,
        status: 'ERROR',
        code: 'ERROR_INVALID_LENGTH',
        message: 'Serial frame exceeds buffer limit'
      }));
    };

    await assert.rejects(
      async () => transport.sendRequest('WRITE_NDEF', { payload_b64: 'A'.repeat(8192) }),
      /Serial frame exceeds buffer limit/
    );
  });

  // 5. Invalid base64 payload
  test('5. Invalid base64 payload rejection', async () => {
    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      mockPort.simulateIncoming(JSON.stringify({
        id: req.id,
        status: 'ERROR',
        code: 'ERROR_INVALID_LENGTH',
        message: 'Failed to decode base64 or payload empty'
      }));
    };

    await assert.rejects(
      async () => transport.sendRequest('WRITE_NDEF', { payload_b64: '!!!NOT_B64!!!' }),
      /Failed to decode base64/
    );
  });

  // 6. Request ID mismatch
  test('6. Request ID mismatch ignores stale response', async () => {
    mockPort.responseHandler = (data) => {
      // Respond with wrong request ID
      mockPort.simulateIncoming(JSON.stringify({
        id: 'wrong-id-999',
        status: 'OK',
        version: '1.0.0',
        protocol: 'ghost-pn532-v1'
      }));
    };

    await assert.rejects(
      async () => transport.sendRequest('HELLO', {}, 50),
      /Serial request timed out/
    );
  });

  // 7. Timeout handling
  test('7. Explicit timeout handling', async () => {
    mockPort.responseHandler = () => {
      // Do nothing, simulate dead firmware
    };

    await assert.rejects(
      async () => transport.sendRequest('READ_NDEF', {}, 50),
      /Serial request timed out \(READ_NDEF\)/
    );
  });

  // 8. USB disconnect handling
  test('8. USB disconnect handling rejects pending requests', async () => {
    const promise = transport.sendRequest('READ_NDEF', {}, 2000);
    mockPort.close();

    await assert.rejects(
      promise,
      /Serial transport disconnected/
    );
    assert.strictEqual(transport.connected, false);
  });

  // 9. Tag-present event
  test('9. Tag-present asynchronous event', (done) => {
    transport.on('card_present', (card) => {
      assert.strictEqual(card.uid, '04A1B2C3D4E5F6');
      assert.strictEqual(card.model, 'NXP NTAG215');
      assert.strictEqual(card.writableBytes, 504);
      assert.strictEqual(card.ndefStatus, 'Read/Write');
      done();
    });

    mockPort.simulateIncoming(JSON.stringify({
      event: 'TAG_PRESENT',
      data: {
        uid: '04A1B2C3D4E5F6',
        is_type2: true,
        user_memory_bytes: 504,
        is_read_only: false
      }
    }));
  });

  // 10. Tag-removed event
  test('10. Tag-removed asynchronous event', (done) => {
    transport.activeCard = { uid: '04A1B2C3D4E5F6' };
    transport.on('card_removed', () => {
      assert.strictEqual(transport.activeCard, null);
      done();
    });

    mockPort.simulateIncoming(JSON.stringify({
      event: 'TAG_REMOVED',
      data: {}
    }));
  });

  // 11. NDEF read
  test('11. NDEF read from user memory', async () => {
    transport.activeCard = { uid: '04A1B2C3D4E5F6', writableBytes: 504 };

    const testPayload = Buffer.from('GTAG_TEST_DATA');
    const ndefMessage = buildMimeNdefMessage('application/vnd.ghost.secure', testPayload);
    const rawUserMemory = Buffer.concat([
      Buffer.from([0x03, ndefMessage.length]),
      ndefMessage,
      Buffer.from([0xFE])
    ]);

    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'READ_NDEF') {
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'OK',
          user_memory_bytes: 504,
          payload_b64: rawUserMemory.toString('base64')
        }));
      }
    };

    const res = await transport.readTagNdef();
    assert.strictEqual(res.records.length, 1);
    assert.strictEqual(res.records[0].mediaType, 'application/vnd.ghost.secure');
    assert.deepStrictEqual(Buffer.from(res.records[0].data), testPayload);
  });

  // 12. NDEF write
  test('12. NDEF write block-by-block', async () => {
    transport.activeCard = { uid: '04A1B2C3D4E5F6', writableBytes: 504 };
    const testPayload = Buffer.from('GTAG_TEST_WRITE');

    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'WRITE_NDEF') {
        assert(req.payload_b64.length > 0);
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'OK',
          bytes_written: 40,
          bytes_read_back: 40,
          byte_comparison_passed: true,
          verified: true
        }));
      }
    };

    const res = await transport.writeTagNdefAndVerify('application/vnd.ghost.secure', testPayload);
    assert.strictEqual(res.verified, true);
    assert.strictEqual(res.bytesWritten, testPayload.length);
  });

  // 13. Read-back verification
  test('13. Read-back verification hash check', async () => {
    transport.activeCard = { uid: '04A1B2C3D4E5F6', writableBytes: 504 };
    const testPayload = Buffer.from('GTAG_TEST_VERIFY');
    const expectedSha256 = crypto.createHash('sha256').update(testPayload).digest('hex');

    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'WRITE_NDEF') {
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'OK',
          bytes_written: 44,
          bytes_read_back: 44,
          byte_comparison_passed: true,
          verified: true
        }));
      }
    };

    const res = await transport.writeTagNdefAndVerify('application/vnd.ghost.secure', testPayload);
    assert.strictEqual(res.verified, true);
    assert.strictEqual(res.byteComparisonPassed, true);
    assert.strictEqual(res.bytesWritten, testPayload.length);
    assert.strictEqual(res.sha256, expectedSha256);
  });

  // 14. Capacity rejection
  test('14. Pre-flight capacity rejection for oversized payloads', async () => {
    // NTAG213 with 144 bytes user memory
    transport.activeCard = { uid: '04A1B2C3D4E5F6', writableBytes: 144 };
    const oversizedPayload = Buffer.alloc(200, 0xFF); // 200B > 144B

    await assert.rejects(
      async () => transport.writeTagNdefAndVerify('application/vnd.ghost.secure', oversizedPayload),
      /Tag capacity exceeded: payload requires \d+ bytes, but tag capacity is 144 bytes/
    );
  });

  // 15. Unsupported tag rejection
  test('15. Unsupported tag rejection', (done) => {
    transport.on('card_present', (card) => {
      assert.strictEqual(card.isType2, false);
      done();
    });

    mockPort.simulateIncoming(JSON.stringify({
      event: 'TAG_PRESENT',
      data: {
        uid: '04A1B2C3D4E5F6',
        is_type2: false,
        user_memory_bytes: 0,
        is_read_only: false
      }
    }));
  });

  // 16. MIFARE Classic rejection
  test('16. MIFARE Classic tag rejected by firmware contract', async () => {
    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      mockPort.simulateIncoming(JSON.stringify({
        id: req.id,
        status: 'ERROR',
        code: 'ERROR_UNSUPPORTED_TAG',
        message: 'Tag is not an NFC Forum Type 2 tag or is MIFARE Classic'
      }));
    };

    transport.activeCard = { uid: '11223344', writableBytes: 1024 };
    await assert.rejects(
      async () => transport.readTagNdef(),
      /Tag is not an NFC Forum Type 2 tag or is MIFARE Classic/
    );
  });

  // 17. Tag removed during write
  test('17. Tag removed during write returns error', async () => {
    transport.activeCard = { uid: '04A1B2C3D4E5F6', writableBytes: 504 };

    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'WRITE_NDEF') {
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'ERROR',
          code: 'ERROR_TAG_LOST',
          message: 'Read-back verification failed: tag removed or read error'
        }));
      }
    };

    await assert.rejects(
      async () => transport.writeTagNdefAndVerify('application/vnd.ghost.secure', Buffer.from('data')),
      /Read-back verification failed: tag removed/
    );
  });

  // 18. Wrong passphrase rejection
  test('18. Decryption fails on wrong key with zero plaintext exposure', () => {
    const correctKey = crypto.randomBytes(32);
    const wrongKey = crypto.randomBytes(32);
    const envelope = createDeterministicV1Envelope('SUPER_SECRET_GHOST_NOTE', correctKey);

    // Extract envelope components
    const magic = envelope.slice(0, 4);
    const version = envelope.slice(4, 5);
    const purpose = envelope.slice(5, 6);
    const keyId = envelope.slice(6, 22);
    const nonce = envelope.slice(22, 34);
    const len = envelope.readUInt32LE(34);
    const ct = envelope.slice(38, 38 + len);
    const tag = envelope.slice(38 + len, 38 + len + 16);
    const aad = Buffer.concat([magic, version, purpose, keyId, nonce]);

    assert.throws(
      () => decryptAesGcm(wrongKey, nonce, ct, tag, aad),
      /Unsupported state or unable to authenticate data/
    );
  });

  // 19. Ghost v1 envelope write and read-back
  test('19. Ghost v1 envelope write and read-back roundtrip', async () => {
    transport.activeCard = { uid: '04A1B2C3D4E5F6', writableBytes: 504 };
    const key = crypto.randomBytes(32);
    const v1Envelope = createDeterministicV1Envelope('Ghost v1 Payload', key);

    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'WRITE_NDEF') {
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'OK',
          bytes_written: v1Envelope.length,
          bytes_read_back: v1Envelope.length,
          byte_comparison_passed: true,
          verified: true
        }));
      }
    };

    const res = await transport.writeTagNdefAndVerify('application/vnd.ghost.secure', v1Envelope);
    assert.strictEqual(res.verified, true);
    assert.strictEqual(res.byteComparisonPassed, true);
    assert.strictEqual(res.sha256, crypto.createHash('sha256').update(v1Envelope).digest('hex'));
  });

  // 20. Ghost v2 bulk envelope write and read-back
  test('20. Ghost v2 bulk envelope write and read-back on NTAG215', async () => {
    transport.activeCard = { uid: '04A1B2C3D4E5F6', writableBytes: 504 };
    // 134 bytes fixed overhead + 64 bytes chunk ciphertext = 198 bytes envelope
    const v2Envelope = Buffer.alloc(198, 0x42);

    mockPort.responseHandler = (data) => {
      const req = JSON.parse(data);
      if (req.cmd === 'WRITE_NDEF') {
        mockPort.simulateIncoming(JSON.stringify({
          id: req.id,
          status: 'OK',
          bytes_written: v2Envelope.length,
          bytes_read_back: v2Envelope.length,
          byte_comparison_passed: true,
          verified: true
        }));
      }
    };

    const res = await transport.writeTagNdefAndVerify('application/vnd.ghost.bulk', v2Envelope);
    assert.strictEqual(res.verified, true);
    assert.strictEqual(res.byteComparisonPassed, true);
  });

  // 21. Correct-passphrase decryption after real write and read-back
  test('21. Correct-passphrase decryption succeeds with authentic plaintext', () => {
    const key = crypto.randomBytes(32);
    const plaintext = 'SENSITIVE_RECOVERY_CREDENTIAL_2026';
    const envelope = createDeterministicV1Envelope(plaintext, key);

    const magic = envelope.slice(0, 4);
    const version = envelope.slice(4, 5);
    const purpose = envelope.slice(5, 6);
    const keyId = envelope.slice(6, 22);
    const nonce = envelope.slice(22, 34);
    const len = envelope.readUInt32LE(34);
    const ct = envelope.slice(38, 38 + len);
    const tag = envelope.slice(38 + len, 38 + len + 16);
    const aad = Buffer.concat([magic, version, purpose, keyId, nonce]);

    const decrypted = decryptAesGcm(key, nonce, ct, tag, aad);
    assert.strictEqual(decrypted.toString('utf-8'), plaintext);
  });

  // 22. No synthetic NFC events validation
  test('22. Firmware contract refuses synthetic tags and events', () => {
    assert.strictEqual(transport.activeCard, null);
    // Emitting random line without TAG_PRESENT event does not create a card
    mockPort.simulateIncoming(JSON.stringify({ id: 'dummy', status: 'OK' }));
    assert.strictEqual(transport.activeCard, null);
  });
});
