/**
 * @file bridge.test.js
 * @description Unit and Protocol Tests for Ghost Bridge Desktop Service
 */

const assert = require('assert');
const http = require('http');
const { GhostBridgeServer, HOST } = require('../src/server');
const { buildMimeNdefMessage, APDU, readTagCapability, calculateTagCapacity } = require('../src/apdu');

function testApdu() {
  assert.deepStrictEqual(APDU.GET_UID, Buffer.from([0xFF, 0xCA, 0x00, 0x00, 0x00]));
  const readBlock4 = APDU.readBlock(4);
  assert.deepStrictEqual(readBlock4, Buffer.from([0xFF, 0xB0, 0x00, 0x04, 0x04]));
  const writeBlock4 = APDU.writeBlock(4, Buffer.from([0x01, 0x02, 0x03, 0x04]));
  assert.deepStrictEqual(writeBlock4, Buffer.from([0xFF, 0xD6, 0x00, 0x04, 0x04, 0x01, 0x02, 0x03, 0x04]));
}

function testNdefBuilder() {
  const testPayload = Buffer.from('GTAG_TEST_PAYLOAD');
  const ndefMsg = buildMimeNdefMessage('application/vnd.ghost.bulk', testPayload);
  assert(ndefMsg.length > testPayload.length);
  assert(ndefMsg.includes(Buffer.from('application/vnd.ghost.bulk')));
  assert(ndefMsg.includes(testPayload));
}

async function testTagCapability() {
  function makeMockReader(ccBytes) {
    return {
      transmit: (apdu, maxLen, protocol, cb) => {
        if (apdu[3] === 3) {
          const resp = Buffer.concat([Buffer.from(ccBytes), Buffer.from([0x90, 0x00])]);
          return cb(null, resp);
        }
        cb(new Error('Unknown block'));
      }
    };
  }

  // NTAG213 (CC = E1 10 12 00)
  const ntag213 = await readTagCapability(makeMockReader([0xE1, 0x10, 0x12, 0x00]));
  assert.strictEqual(ntag213.isType2, true);
  assert.strictEqual(ntag213.model, 'NXP NTAG213');
  assert.strictEqual(ntag213.totalBytes, 180);
  assert.strictEqual(ntag213.writableBytes, 144);
  assert.strictEqual(ntag213.ndefStatus, 'Read/Write');

  // NTAG215 (CC = E1 10 3E 00)
  const ntag215 = await readTagCapability(makeMockReader([0xE1, 0x10, 0x3E, 0x00]));
  assert.strictEqual(ntag215.isType2, true);
  assert.strictEqual(ntag215.model, 'NXP NTAG215');
  assert.strictEqual(ntag215.totalBytes, 540);
  assert.strictEqual(ntag215.writableBytes, 504);
  assert.strictEqual(ntag215.ndefStatus, 'Read/Write');

  // NTAG216 (CC = E1 10 6D 00)
  const ntag216 = await readTagCapability(makeMockReader([0xE1, 0x10, 0x6D, 0x00]));
  assert.strictEqual(ntag216.isType2, true);
  assert.strictEqual(ntag216.model, 'NXP NTAG216');
  assert.strictEqual(ntag216.totalBytes, 924);
  assert.strictEqual(ntag216.writableBytes, 888);
  assert.strictEqual(ntag216.ndefStatus, 'Read/Write');

  // Read-only tag (CC = E1 10 3E 0F)
  const roTag = await readTagCapability(makeMockReader([0xE1, 0x10, 0x3E, 0x0F]));
  assert.strictEqual(roTag.isType2, true);
  assert.strictEqual(roTag.writableBytes, 0);
  assert.strictEqual(roTag.ndefStatus, 'Read-Only');

  // MIFARE Classic (Sector trailer at block 3, key bytes != 0xE1)
  const mifareClassic = await readTagCapability(makeMockReader([0xFF, 0xFF, 0xFF, 0xFF]));
  assert.strictEqual(mifareClassic.isType2, false);
  assert.strictEqual(mifareClassic.ndefStatus, 'Unsupported Tag Format');

  // Unsupported non-Type 2 tag (CC = 00 00 00 00)
  const unsupported = await readTagCapability(makeMockReader([0x00, 0x00, 0x00, 0x00]));
  assert.strictEqual(unsupported.isType2, false);
  assert.strictEqual(unsupported.ndefStatus, 'Unsupported Tag Format');
}

function testCapacityCalculations() {
  const MIME_V1 = 'application/vnd.ghost.secure';
  const MIME_V2 = 'application/vnd.ghost.bulk';

  // --- NTAG213 (144 bytes user memory) ---
  const ntag213_v1 = calculateTagCapacity(144, MIME_V1);
  assert.strictEqual(ntag213_v1.fits, true);
  assert.strictEqual(ntag213_v1.maxEnvelopeSize, 110);
  assert.strictEqual(ntag213_v1.maxCiphertextPayload, 56); // 110 - 54

  const ntag213_v2 = calculateTagCapacity(144, MIME_V2);
  assert.strictEqual(ntag213_v2.fits, false, 'v2 bulk envelope must NOT fit on NTAG213 (144 bytes)');
  assert.strictEqual(ntag213_v2.maxCiphertextPayload, 0);

  // --- NTAG215 (504 bytes user memory) ---
  const ntag215_v1 = calculateTagCapacity(504, MIME_V1);
  assert.strictEqual(ntag215_v1.fits, true);
  assert.strictEqual(ntag215_v1.maxEnvelopeSize, 465);
  assert.strictEqual(ntag215_v1.maxCiphertextPayload, 411); // 465 - 54

  const ntag215_v2 = calculateTagCapacity(504, MIME_V2);
  assert.strictEqual(ntag215_v2.fits, true);
  assert.strictEqual(ntag215_v2.maxEnvelopeSize, 467);
  assert.strictEqual(ntag215_v2.maxCiphertextPayload, 333); // 467 - 134

  // --- NTAG216 (888 bytes user memory) ---
  const ntag216_v1 = calculateTagCapacity(888, MIME_V1);
  assert.strictEqual(ntag216_v1.fits, true);
  assert.strictEqual(ntag216_v1.maxEnvelopeSize, 849);
  assert.strictEqual(ntag216_v1.maxCiphertextPayload, 795); // 849 - 54

  const ntag216_v2 = calculateTagCapacity(888, MIME_V2);
  assert.strictEqual(ntag216_v2.fits, true);
  assert.strictEqual(ntag216_v2.maxEnvelopeSize, 851);
  assert.strictEqual(ntag216_v2.maxCiphertextPayload, 717); // 851 - 134
}

async function testHttpStatus() {
  const bridge = new GhostBridgeServer();
  bridge.initHttpServer(0);

  try {
    await new Promise((resolve) => bridge.server.once('listening', resolve));
    const port = bridge.server.address().port;
    await new Promise((resolve, reject) => {
      http.get(`http://${HOST}:${port}/status`, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            assert.strictEqual(res.statusCode, 200);
            const data = JSON.parse(body);
            assert.strictEqual(data.bridge, 'Ghost Bridge');
            assert.strictEqual(data.version, '2.1.0');
            assert.strictEqual(data.status, 'ready');
            assert(Array.isArray(data.readers));
            assert(Array.isArray(data.supportedReaders));
            resolve();
          } catch (err) {
            reject(err);
          }
        });
      }).on('error', reject);
    });

    await new Promise((resolve, reject) => {
      http.get(`http://${HOST}:${port}/status`, { headers: { Origin: 'https://evil.example' } }, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            assert.strictEqual(res.statusCode, 403);
            const data = JSON.parse(body);
            assert.strictEqual(data.error, 'FORBIDDEN_ORIGIN');
            resolve();
          } catch (err) {
            reject(err);
          }
        });
      }).on('error', reject);
    });
  } finally {
    bridge.stop();
  }
}

async function testWebSocketSessionAndOriginGuards() {
  const WebSocket = require('ws');
  const bridge = new GhostBridgeServer();
  bridge.initHttpServer(0);
  bridge.initWebSocketServer();

  try {
    await new Promise((resolve) => bridge.server.once('listening', resolve));
    const port = bridge.server.address().port;

    // 1. Forbidden cross-origin WebSocket must be rejected during handshake
    await new Promise((resolve, reject) => {
      const badWs = new WebSocket(`ws://${HOST}:${port}`, {
        headers: { Origin: 'https://evil.example' },
      });
      badWs.on('error', () => {
        // Expected handshake abort after 403 Forbidden Origin
      });
      badWs.on('unexpected-response', (_req, res) => {
        try {
          assert.strictEqual(res.statusCode, 403);
          res.resume();
          resolve();
        } catch (err) {
          reject(err);
        }
      });
      badWs.on('open', () => {
        badWs.close();
        reject(new Error('Expected unauthorized Origin WebSocket to be rejected'));
      });
    });

    // 2. Approved WebSocket receives sessionToken and enforces it on tag commands
    await new Promise((resolve, reject) => {
      const ws = new WebSocket(`ws://${HOST}:${port}`, {
        headers: { Origin: 'https://frosty-mug.github.io' },
      });
      const responses = [];
      let sessionToken = null;

      ws.on('error', reject);
      ws.on('message', (raw) => {
        const msg = JSON.parse(raw.toString());
        responses.push(msg);

        if (responses.length === 1) {
          assert.strictEqual(msg.type, 'bridge_status');
          assert.strictEqual(typeof msg.sessionToken, 'string');
          assert(msg.sessionToken.length >= 32);
          sessionToken = msg.sessionToken;

          // Missing sessionToken must be rejected before any hardware call
          ws.send(JSON.stringify({ action: 'read_tag' }));
        } else if (responses.length === 2) {
          assert.strictEqual(msg.type, 'error');
          assert(msg.message.includes('session token'));

          // Wrong sessionToken must be rejected
          ws.send(JSON.stringify({
            action: 'write_tag',
            sessionToken: 'deadbeef',
            envelopeBytes: [0x47, 0x54, 0x41, 0x47],
            mimeType: 'application/vnd.ghost.bulk',
          }));
        } else if (responses.length === 3) {
          assert.strictEqual(msg.type, 'error');
          assert(msg.message.includes('session token'));

          // Unsupported MIME type with valid sessionToken must be rejected
          ws.send(JSON.stringify({
            action: 'write_tag',
            sessionToken,
            envelopeBytes: [0x47, 0x54, 0x41, 0x47],
            mimeType: 'text/plain',
          }));
        } else if (responses.length === 4) {
          assert.strictEqual(msg.type, 'error');
          assert(msg.message.includes('MIME type'));

          // Simulated NFC action must always be rejected
          ws.send(JSON.stringify({ action: 'simulate_tag', sessionToken }));
        } else if (responses.length === 5) {
          assert.strictEqual(msg.type, 'error');
          assert(msg.message.includes('prohibited'));
          ws.close();
          resolve();
        }
      });
    });
  } finally {
    bridge.stop();
  }
}

if (typeof describe === 'function') {
  describe('Ghost Bridge Desktop Daemon', () => {
    test('APDU command generators', () => {
      testApdu();
    });

    test('NDEF MIME Message serialization', () => {
      testNdefBuilder();
    });

    test('Real Tag Capability & Model Identification', async () => {
      await testTagCapability();
    });

    test('Tag Capacity & Envelope Boundary Calculations', () => {
      testCapacityCalculations();
    });

    test('HTTP /status endpoint schema and origin guard', async () => {
      await testHttpStatus();
    });

    test('WebSocket session token and origin enforcement', async () => {
      await testWebSocketSessionAndOriginGuards();
    });
  });
} else {
  (async () => {
    testApdu();
    testNdefBuilder();
    await testTagCapability();
    testCapacityCalculations();
    await testHttpStatus();
    await testWebSocketSessionAndOriginGuards();
    console.log('[PASS] All Ghost Bridge standalone tests passed.');
  })().catch(err => {
    console.error('[FAIL] Standalone test failed:', err);
    process.exit(1);
  });
}
