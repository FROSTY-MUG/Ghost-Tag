/**
 * @file bridge.test.js
 * @description Unit and Protocol Tests for Ghost Bridge Desktop Service
 */

const assert = require('assert');
const http = require('http');
const { GhostBridgeServer, PORT, HOST } = require('../src/server');
const { buildMimeNdefMessage, APDU } = require('../src/apdu');

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

async function testHttpStatus() {
  const bridge = new GhostBridgeServer();
  bridge.initHttpServer();

  try {
    await new Promise((resolve, reject) => {
      http.get(`http://${HOST}:${PORT}/status`, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            assert.strictEqual(res.statusCode, 200);
            const data = JSON.parse(body);
            assert.strictEqual(data.bridge, 'Ghost Bridge');
            assert.strictEqual(data.version, '2.0.5');
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

    test('HTTP /status endpoint schema', async () => {
      await testHttpStatus();
    });
  });
} else {
  (async () => {
    testApdu();
    testNdefBuilder();
    await testHttpStatus();
    console.log('[PASS] All Ghost Bridge standalone tests passed.');
  })().catch(err => {
    console.error('[FAIL] Standalone test failed:', err);
    process.exit(1);
  });
}
