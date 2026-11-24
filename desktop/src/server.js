/**
 * @file server.js
 * @description Native Desktop PC/SC USB NFC Bridge Server for Ghost-Tag
 * Binds strictly to 127.0.0.1:41789. Communicates with ACR122U USB reader and provides
 * real tag events and write-verification over WebSockets to the web app.
 */

const crypto = require('crypto');
const http = require('http');
const wsModule = require('ws');
const WebSocketServer = wsModule.WebSocketServer || wsModule.Server;
const { getCardUid, readTagCapability, readTagNdef, writeTagNdefAndVerify } = require('./apdu');

const PORT = 41789;
const HOST = '127.0.0.1';
const ALLOWED_GHOST_MIME_TYPES = new Set([
  'application/vnd.ghost.secure',
  'application/vnd.ghost.bulk',
]);
const MAX_ENVELOPE_BYTES = 8192;

const { isValidLoopbackOrigin, parseApprovedOrigins, isBridgeOriginAllowed } = (() => {
  function isValidLoopback(origin) {
    if (!origin || typeof origin !== 'string') return false;
    try {
      const parsed = new URL(origin);
      if (
        parsed.protocol !== 'http:' ||
        parsed.username ||
        parsed.password ||
        (parsed.pathname !== '' && parsed.pathname !== '/') ||
        parsed.search ||
        parsed.hash ||
        parsed.origin !== origin
      ) {
        return false;
      }
      if (parsed.hostname !== 'localhost' && parsed.hostname !== '127.0.0.1') {
        return false;
      }
      if (!parsed.port) return false;
      const port = Number(parsed.port);
      return Number.isInteger(port) && port >= 1 && port <= 65535;
    } catch {
      return false;
    }
  }

  function parseApproved(extra) {
    const allowed = new Set(['https://frosty-mug.github.io']);
    if (!extra) return allowed;
    for (const raw of String(extra).split(',')) {
      const trimmed = raw.trim();
      if (!trimmed || trimmed === '*' || trimmed.includes('*')) continue;
      try {
        const parsed = new URL(trimmed);
        if (
          parsed.protocol === 'https:' &&
          !parsed.username &&
          !parsed.password &&
          (parsed.pathname === '' || parsed.pathname === '/') &&
          !parsed.search &&
          !parsed.hash &&
          parsed.origin === trimmed
        ) {
          allowed.add(parsed.origin);
        }
      } catch {
        // Ignore malformed origins
      }
    }
    return allowed;
  }

  function isAllowed(origin, opts = {}) {
    if (!origin || typeof origin !== 'string') return false;
    const trimmed = origin.trim();
    if (!trimmed || trimmed === '*' || trimmed === 'null') return false;
    const approved = parseApproved(
      opts.approvedOrigins !== undefined ? opts.approvedOrigins : process.env.GHOST_APPROVED_ORIGINS
    );
    if (approved.has(trimmed)) return true;
    const isDev =
      opts.allowLocalhost === true ||
      (opts.environment !== undefined ? opts.environment : process.env.GHOST_ENV) !== 'production';
    return isDev && isValidLoopback(trimmed);
  }

  return {
    isValidLoopbackOrigin: isValidLoopback,
    parseApprovedOrigins: parseApproved,
    isBridgeOriginAllowed: isAllowed,
  };
})();

class GhostBridgeServer {
  constructor() {
    this.connectedReaders = new Map();
    this.clientSessions = new WeakMap();
    this.activeCard = null;
    this.activeReader = null;
    this.wss = null;
    this.server = null;
    this.pcsc = null;
    this.actionHandlers = new Map([
      ['get_status', (ws, _msg, session) => this.handleGetStatus(ws, session)],
      ['read_tag', (ws, msg, session) => this.handleReadTag(ws, msg, session)],
      ['write_tag', (ws, msg, session) => this.handleWriteTag(ws, msg, session)],
      ['simulate_tag', (ws) => this.handleSimulateTag(ws)],
    ]);
  }

  start() {
    this.initHttpServer();
    this.initWebSocketServer();
    this.initPcsc();
    console.log(`[Ghost Bridge] Running at ws://${HOST}:${PORT} and http://${HOST}:${PORT}/status`);
  }

  initHttpServer(listenPort = PORT) {
    this.server = http.createServer((req, res) => {
      const origin = req.headers['origin'];

      // Reject unauthorized cross-origin requests with HTTP 403 (never emit *)
      if (origin !== undefined && !isBridgeOriginAllowed(origin)) {
        res.writeHead(403, { 'Content-Type': 'application/json', Vary: 'Origin' });
        res.end(JSON.stringify({ error: 'FORBIDDEN_ORIGIN' }));
        return;
      }

      if (origin && isBridgeOriginAllowed(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
      }
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
      res.setHeader('Vary', 'Origin');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.url === '/status') {
        const readerNames = Array.from(this.connectedReaders.keys());
        const hasAcr122u = readerNames.some(name => name.toUpperCase().includes('ACR122') || name.toUpperCase().includes('NFC'));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          bridge: 'Ghost Bridge',
          version: '2.1.0',
          status: 'ready',
          readers: readerNames,
          hasAcr122u,
          cardPresent: this.activeCard !== null,
          activeCardUid: this.activeCard ? this.activeCard.uid : null,
          supportedReaders: ['ACS ACR122U USB NFC Reader']
        }));
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Ghost Bridge 2.1.0');
    });

    this.server.listen(listenPort, HOST);
  }

  initWebSocketServer() {
    this.wss = new WebSocketServer({
      server: this.server,
      verifyClient: (info, callback) => {
        const origin = info.origin || info.req.headers['origin'];
        if (origin !== undefined && !isBridgeOriginAllowed(origin)) {
          callback(false, 403, 'Forbidden Origin');
          return;
        }
        callback(true);
      },
    });

    this.wss.on('connection', (ws, req) => {
      const origin = req.headers['origin'];
      if (origin !== undefined && !isBridgeOriginAllowed(origin)) {
        ws.close(1008, 'Forbidden Origin');
        return;
      }

      const sessionToken = crypto.randomBytes(24).toString('hex');
      const session = {
        sessionToken,
        origin: origin || null,
        connectedAt: Date.now(),
      };
      this.clientSessions.set(ws, session);
      console.log(`[Ghost Bridge] Web client connected from ${req.socket.remoteAddress}`);

      // Send initial status and per-connection session token
      this.sendBridgeStatus(ws, sessionToken);

      ws.on('message', async (data) => {
        try {
          const msg = JSON.parse(data.toString());
          await this.handleClientMessage(ws, msg);
        } catch (err) {
          ws.send(JSON.stringify({ type: 'error', message: err.message }));
        }
      });
    });
  }

  sendBridgeStatus(ws, sessionToken) {
    const readerNames = Array.from(this.connectedReaders.keys());
    const payload = {
      type: 'bridge_status',
      version: '2.1.0',
      readers: readerNames,
      readerConnected: readerNames.length > 0,
      cardPresent: this.activeCard !== null,
      activeCard: this.activeCard,
    };
    if (sessionToken) {
      payload.sessionToken = sessionToken;
    }
    ws.send(JSON.stringify(payload));
  }

  hasValidSessionToken(session, presentedToken) {
    if (!session || typeof session.sessionToken !== 'string' || typeof presentedToken !== 'string') {
      return false;
    }
    const expectedBuf = Buffer.from(session.sessionToken, 'utf8');
    const presentedBuf = Buffer.from(presentedToken, 'utf8');
    if (expectedBuf.length !== presentedBuf.length) {
      return false;
    }
    return crypto.timingSafeEqual(expectedBuf, presentedBuf);
  }

  async handleClientMessage(ws, msg) {
    if (!msg || typeof msg !== 'object' || typeof msg.action !== 'string') {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid Ghost Bridge message envelope.' }));
      return;
    }

    const session = this.clientSessions.get(ws);
    if (!session) {
      ws.send(JSON.stringify({ type: 'error', message: 'Unauthenticated WebSocket session.' }));
      return;
    }

    if (!this.actionHandlers.has(msg.action)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Unsupported Ghost Bridge action.' }));
      return;
    }

    const handler = this.actionHandlers.get(msg.action);
    if (typeof handler !== 'function') {
      ws.send(JSON.stringify({ type: 'error', message: 'Unsupported Ghost Bridge action.' }));
      return;
    }

    await handler(ws, msg, session);
  }

  handleGetStatus(ws, session) {
    this.sendBridgeStatus(ws, session.sessionToken);
  }

  async handleReadTag(ws, msg, session) {
    if (!this.hasValidSessionToken(session, msg.sessionToken)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid or missing bridge session token.' }));
      return;
    }

    if (!this.activeReader || !this.activeCard) {
      ws.send(JSON.stringify({ type: 'error', message: 'No card present on USB NFC reader.' }));
      return;
    }

    try {
      const ndefResult = await readTagNdef(this.activeReader);
      ws.send(JSON.stringify({
        type: 'tag_read_result',
        uid: this.activeCard.uid,
        records: ndefResult.records,
        rawBytes: ndefResult.rawBytes,
        timestamp: Date.now(),
      }));
    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', message: `Tag read failed: ${err.message}` }));
    }
  }

  async handleWriteTag(ws, msg, session) {
    if (!this.hasValidSessionToken(session, msg.sessionToken)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid or missing bridge session token.' }));
      return;
    }

    if (
      !Array.isArray(msg.envelopeBytes) ||
      msg.envelopeBytes.length === 0 ||
      msg.envelopeBytes.length > MAX_ENVELOPE_BYTES ||
      !msg.envelopeBytes.every((b) => Number.isInteger(b) && b >= 0 && b <= 255)
    ) {
      ws.send(JSON.stringify({ type: 'error', message: 'Invalid or out-of-bounds envelopeBytes payload.' }));
      return;
    }

    const mediaType = typeof msg.mimeType === 'string' && msg.mimeType.length > 0
      ? msg.mimeType
      : 'application/vnd.ghost.bulk';
    if (!ALLOWED_GHOST_MIME_TYPES.has(mediaType)) {
      ws.send(JSON.stringify({ type: 'error', message: 'Unsupported Ghost-Tag NDEF MIME type.' }));
      return;
    }

    if (!this.activeReader || !this.activeCard) {
      ws.send(JSON.stringify({ type: 'error', message: 'No card present on USB NFC reader to write.' }));
      return;
    }

    try {
      const payloadBuffer = Buffer.from(msg.envelopeBytes);
      const verifyResult = await writeTagNdefAndVerify(this.activeReader, mediaType, payloadBuffer);

      ws.send(JSON.stringify({
        type: 'tag_write_verified',
        uid: this.activeCard.uid,
        verified: true,
        sha256: verifyResult.sha256,
        bytesWritten: verifyResult.bytesWritten,
        timestamp: Date.now(),
      }));
    } catch (err) {
      ws.send(JSON.stringify({ type: 'error', message: `Write verification failed: ${err.message}` }));
    }
  }

  handleSimulateTag(ws) {
    // Invariant: Refuse simulated data
    ws.send(JSON.stringify({
      type: 'error',
      message: 'Non-negotiable product rule: Synthetic or simulated NFC data is strictly prohibited.',
    }));
  }

  broadcast(obj) {
    if (!this.wss) return;
    const payload = JSON.stringify(obj);
    for (const client of this.wss.clients) {
      if (client.readyState === 1) { // OPEN
        client.send(payload);
      }
    }
  }

  initPcsc() {
    let pcsclite;
    try {
      pcsclite = require('@pokusew/pcsclite');
    } catch {
      try {
        pcsclite = require('pcsclite');
      } catch {
        console.warn('[Ghost Bridge] PC/SC library not compiled or not installed in environment.');
        console.warn('[Ghost Bridge] Real USB reader detection requires @pokusew/pcsclite and PC/SC drivers.');
        return;
      }
    }

    this.pcsc = pcsclite();

    this.pcsc.on('reader', (reader) => {
      console.log(`[Ghost Bridge] USB Reader detected: ${reader.name}`);
      this.connectedReaders.set(reader.name, reader);
      this.activeReader = reader;

      this.broadcast({
        type: 'reader_connected',
        reader: reader.name,
        readers: Array.from(this.connectedReaders.keys())
      });

      reader.on('status', async (status) => {
        const changes = reader.state ^ status.state;
        if (!changes) return;

        // Card removed
        if ((changes & reader.SCARD_STATE_EMPTY) && (status.state & reader.SCARD_STATE_EMPTY)) {
          console.log(`[Ghost Bridge] Card removed from ${reader.name}`);
          this.activeCard = null;
          reader.disconnect(reader.SCARD_LEAVE_CARD, () => {});
          this.broadcast({
            type: 'card_removed',
            reader: reader.name
          });
        }
        // Card present
        else if ((changes & reader.SCARD_STATE_PRESENT) && (status.state & reader.SCARD_STATE_PRESENT)) {
          console.log(`[Ghost Bridge] Card detected on ${reader.name}`);
          reader.connect({ share_mode: reader.SCARD_SHARE_SHARED }, async (err, protocol) => {
            if (err) {
              console.error('[Ghost Bridge] Error connecting to tag:', err);
              return;
            }

            try {
              const uid = await getCardUid(reader);
              const atr = status.atr ? status.atr.toString('hex').toUpperCase() : 'Not available on this device';
              
              // Read real tag capability from CC block 3
              const capability = await readTagCapability(reader);
              if (!capability.isType2) {
                console.warn(`[Ghost Bridge] Unsupported tag detected on ${reader.name} (UID: ${uid})`);
                this.broadcast({
                  type: 'error',
                  message: `Unsupported tag detected (UID: ${uid}). Ghost-Tag requires an NFC Forum Type 2 tag (NTAG213, NTAG215, or NTAG216).`
                });
                return;
              }

              // Attempt reading existing NDEF
              let existingData = null;
              let rawBytes = [];
              try {
                const ndef = await readTagNdef(reader);
                if (ndef && ndef.records && ndef.records.length > 0) {
                  existingData = ndef.records[0].data;
                  rawBytes = ndef.rawBytes;
                }
              } catch {
                // Fresh or unformatted tag
              }

              this.activeCard = {
                uid,
                atr,
                reader: reader.name,
                technology: `ISO 14443-3A / ${capability.model}`,
                model: capability.model,
                manufacturer: capability.manufacturer,
                ndefStatus: capability.ndefStatus,
                totalBytes: capability.totalBytes,
                writableBytes: capability.writableBytes,
                existingData,
                rawBytes,
                timestamp: Date.now()
              };

              console.log(`[Ghost Bridge] Tag detected: ${capability.model} (UID: ${uid}, ${capability.writableBytes}B writable)`);
              this.broadcast({
                type: 'card_present',
                tag: this.activeCard,
                card: this.activeCard
              });
            } catch (cardErr) {
              console.error('[Ghost Bridge] Failed to read tag info:', cardErr);
            }
          });
        }
      });

      reader.on('end', () => {
        console.log(`[Ghost Bridge] Reader disconnected: ${reader.name}`);
        this.connectedReaders.delete(reader.name);
        if (this.activeReader === reader) {
          this.activeReader = null;
          this.activeCard = null;
        }
        this.broadcast({
          type: 'reader_disconnected',
          reader: reader.name,
          readers: Array.from(this.connectedReaders.keys())
        });
      });

      reader.on('error', (err) => {
        console.error(`[Ghost Bridge] Reader error (${reader.name}):`, err);
      });
    });

    this.pcsc.on('error', (err) => {
      console.error('[Ghost Bridge] PC/SC System error:', err);
    });
  }

  stop() {
    if (this.pcsc) {
      try { this.pcsc.close(); } catch {}
    }
    if (this.wss) {
      this.wss.close();
    }
    if (this.server) {
      this.server.close();
    }
    console.log('[Ghost Bridge] Stopped.');
  }
}

module.exports = {
  GhostBridgeServer,
  PORT,
  HOST,
  isBridgeOriginAllowed,
  isValidLoopbackOrigin,
  parseApprovedOrigins,
};
