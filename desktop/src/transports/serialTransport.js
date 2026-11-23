/**
 * @file serialTransport.js
 * @description Ghost Bridge Serial Transport Adapter for ESP32 + PN532
 *
 * Implements a versioned, bounded JSON serial protocol between Ghost Bridge
 * and the microcontroller over USB virtual COM port.
 */

const EventEmitter = require('events');
const crypto = require('crypto');
const {
  parseNdefFromUserMemory,
  buildMimeNdefMessage
} = require('../apdu');

class Pn532SerialTransport extends EventEmitter {
  constructor(portAdapter = null) {
    super();
    this.port = portAdapter;
    this.connected = false;
    this.activeCard = null;
    this.reqCounter = 0;
    this.pendingRequests = new Map();
    this.lineBuffer = '';
    this.protocolVersion = 'ghost-pn532-v1';
  }

  /**
   * Generates a monotonically increasing request ID.
   */
  nextRequestId() {
    this.reqCounter++;
    return `req-${this.reqCounter}-${Date.now()}`;
  }

  /**
   * Attaches a serial stream/port interface and binds listeners.
   */
  attachPort(port) {
    this.port = port;

    port.on('data', (chunk) => {
      this.handleIncomingChunk(chunk);
    });

    port.on('close', () => {
      this.handleDisconnect('Serial port closed');
    });

    port.on('error', (err) => {
      this.handleDisconnect(`Serial port error: ${err.message}`);
    });
  }

  /**
   * Buffers incoming chunks and processes line-delimited JSON.
   */
  handleIncomingChunk(chunk) {
    this.lineBuffer += chunk.toString('utf-8');
    const lines = this.lineBuffer.split('\n');
    this.lineBuffer = lines.pop(); // Keep incomplete line in buffer

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (line.length === 0) continue;
      this.handleIncomingLine(line);
    }
  }

  /**
   * Parses and dispatches a single line from the serial port.
   */
  handleIncomingLine(line) {
    let msg;
    try {
      msg = JSON.parse(line);
    } catch {
      this.emit('protocol_error', { reason: 'Malformed JSON frame', line });
      return;
    }

    // Handle asynchronous firmware push events
    if (msg.event) {
      this.handleFirmwareEvent(msg.event, msg.data);
      return;
    }

    // Handle synchronous command responses
    if (msg.id && this.pendingRequests.has(msg.id)) {
      const pending = this.pendingRequests.get(msg.id);
      this.pendingRequests.delete(msg.id);
      clearTimeout(pending.timer);

      if (msg.status === 'OK') {
        pending.resolve(msg);
      } else {
        const error = new Error(msg.message || msg.code || 'Command failed on serial transport');
        error.code = msg.code || 'ERROR_UNKNOWN';
        pending.reject(error);
      }
    }
  }

  /**
   * Handles unsolicited tag presence/removal events.
   */
  handleFirmwareEvent(event, data) {
    if (event === 'TAG_PRESENT') {
      let model = 'NFC Forum Type 2 Tag';
      let totalBytes = (data.user_memory_bytes || 0) + 36;
      if (data.user_memory_bytes === 144) {
        model = 'NXP NTAG213';
        totalBytes = 180;
      } else if (data.user_memory_bytes === 504) {
        model = 'NXP NTAG215';
        totalBytes = 540;
      } else if (data.user_memory_bytes === 888) {
        model = 'NXP NTAG216';
        totalBytes = 924;
      }

      this.activeCard = {
        uid: data.uid,
        technology: `ISO 14443-3A / ${model}`,
        model,
        manufacturer: 'NXP Semiconductors',
        ndefStatus: data.is_read_only ? 'Read-Only' : 'Read/Write',
        totalBytes,
        writableBytes: data.is_read_only ? 0 : (data.user_memory_bytes || 0),
        isType2: data.is_type2 !== false,
        timestamp: Date.now()
      };

      this.emit('card_present', this.activeCard);
    } else if (event === 'TAG_REMOVED') {
      this.activeCard = null;
      this.emit('card_removed');
    }
  }

  /**
   * Sends a structured JSON request over serial and awaits response.
   */
  sendRequest(cmd, params = {}, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      if (!this.port) {
        return reject(new Error('Serial transport not connected'));
      }

      const id = this.nextRequestId();
      const payload = JSON.stringify({ id, cmd, ...params }) + '\n';

      const timer = setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error(`Serial request timed out (${cmd})`));
        }
      }, timeoutMs);

      this.pendingRequests.set(id, { resolve, reject, timer });

      try {
        this.port.write(payload, (err) => {
          if (err) {
            clearTimeout(timer);
            this.pendingRequests.delete(id);
            reject(err);
          }
        });
      } catch (err) {
        clearTimeout(timer);
        this.pendingRequests.delete(id);
        reject(err);
      }
    });
  }

  /**
   * Executes the HELLO protocol handshake with firmware.
   */
  async handshake() {
    const res = await this.sendRequest('HELLO', {}, 3000);
    if (res.protocol !== this.protocolVersion) {
      throw new Error(`Protocol version mismatch: firmware reported ${res.protocol}, expected ${this.protocolVersion}`);
    }
    this.connected = true;
    this.emit('ready', {
      version: res.version,
      hardware: res.hardware,
      protocol: res.protocol
    });
    return res;
  }

  /**
   * Reads NDEF user memory from the tag.
   */
  async readTagNdef() {
    if (!this.activeCard) {
      throw new Error('No tag present on reader');
    }

    const res = await this.sendRequest('READ_NDEF', {}, 6000);
    if (!res.payload_b64) {
      throw new Error('Firmware returned empty payload');
    }

    const rawUserMemory = Buffer.from(res.payload_b64, 'base64');
    return parseNdefFromUserMemory(rawUserMemory);
  }

  /**
   * Writes an NDEF record to the tag and verifies via physical read-back.
   */
  async writeTagNdefAndVerify(mediaType, payloadBuffer) {
    if (!this.activeCard) {
      throw new Error('No tag present on reader');
    }

    if (this.activeCard.writableBytes === 0) {
      throw new Error('Tag is read-only or locked: write prohibited.');
    }

    const ndefMessage = buildMimeNdefMessage(mediaType, payloadBuffer);

    // Wrap in NDEF Message TLV (0x03) + Terminator TLV (0xFE)
    const tlvParts = [Buffer.from([0x03])];
    if (ndefMessage.length < 0xFF) {
      tlvParts.push(Buffer.from([ndefMessage.length]));
    } else {
      tlvParts.push(Buffer.from([0xFF, (ndefMessage.length >> 8) & 0xFF, ndefMessage.length & 0xFF]));
    }
    tlvParts.push(ndefMessage);
    tlvParts.push(Buffer.from([0xFE]));

    const rawUserMemory = Buffer.concat(tlvParts);
    const remainder = rawUserMemory.length % 4;
    const paddingLength = remainder === 0 ? 0 : 4 - remainder;
    const fullPayload = Buffer.concat([rawUserMemory, Buffer.alloc(paddingLength, 0x00)]);

    if (fullPayload.length > this.activeCard.writableBytes) {
      throw new Error(`Tag capacity exceeded: payload requires ${fullPayload.length} bytes, but tag capacity is ${this.activeCard.writableBytes} bytes.`);
    }

    const payloadB64 = fullPayload.toString('base64');
    const res = await this.sendRequest('WRITE_NDEF', { payload_b64: payloadB64 }, 10000);

    if (!res.verified || !res.byte_comparison_passed) {
      throw new Error('Firmware write verification failed: byte-for-byte read-back check failed');
    }

    const sha256 = crypto.createHash('sha256').update(payloadBuffer).digest('hex');
    return {
      verified: true,
      byteComparisonPassed: true,
      bytesWritten: payloadBuffer.length,
      bytesReadBack: payloadBuffer.length,
      totalNdefBytesWritten: res.bytes_written,
      sha256
    };
  }

  /**
   * Handles unexpected USB/serial disconnects.
   */
  handleDisconnect(reason) {
    this.connected = false;
    this.activeCard = null;

    for (const pending of this.pendingRequests.values()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`Serial transport disconnected: ${reason}`));
    }
    this.pendingRequests.clear();
    this.emit('disconnected', { reason });
  }
}

module.exports = {
  Pn532SerialTransport
};
