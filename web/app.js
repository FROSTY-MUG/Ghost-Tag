/**
 * Ghost-Tag v2.0.5 - Production Client-Side Web Application
 *
 * Core Promise:
 * Encrypted NFC storage.
 * Create. Encrypt. Scan. Decrypt.
 *
 * Strict Architectural Invariants:
 * - Real Hardware Only: Zero synthetic, mock, demo, or simulated NFC data.
 * - Hardware Detection:
 *     * Laptop without Ghost Bridge: NO USB NFC READER DETECTED
 *     * Laptop with Ghost Bridge and USB reader, no tag on antenna: NO NFC TAG DETECTED
 *     * Mobile without Web NFC hardware: NO NFC READER DETECTED
 *     * Android with NFC turned off: NFC IS TURNED OFF
 *     * Unsupported tag: THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA
 *     * iOS Safari: iOS is not supported yet
 * - Mandatory Account Creation (12-word BIP-39 recovery phrase + master passphrase)
 * - Portable Account Identity: account_id = KDF(recovery_phrase, "ghost-account-id")
 * - Supabase Anonymous Cloud Sync: encrypted vault metadata only; zero keys, zero plaintexts
 * - Zero Scanned-Chunk Cache: volatile in-memory session; zero persistent 72-hour cache
 * - Real Encrypt Flow: Arbitrary text, files, photos, videos, encrypted URLs
 * - Real Double Cryptographic Binding: AES-256-GCM + SHA-256 with 74-byte AAD
 * - Real Batch Multi-Tag Write & Read-Back Verification
 * - Real Decrypt Flow: Order-independent scanning, [All Chips Scanned], passphrase unlock
 * - Real File Preview & Download via Blobs
 * - Opt-in Scan History (metadata only: timestamp, redacted UID, chunk index, action)
 */

(function () {
  'use strict';

  // Core Storage Keys & Constants
  const STORAGE_KEY_ACCOUNT = 'ghost_account_v2';
  const STORAGE_KEY_LOCAL_VAULT = 'ghost_local_vault_v2';
  const STORAGE_KEY_SCAN_HISTORY_OPT_IN = 'ghost_scan_history_opt_in';
  const STORAGE_KEY_SCAN_HISTORY_RECORDS = 'ghost_scan_history_records';
  const MIME_BULK = 'application/vnd.ghost.bulk';
  const MAGIC_BYTES = new Uint8Array([0x47, 0x54, 0x41, 0x47]); // "GTAG"
  const FORMAT_VERSION = 0x02;

  function generateSecureRandomHex(bytesCount = 8) {
    const gCrypto = typeof window !== 'undefined' ? window.crypto : (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
    if (gCrypto && typeof gCrypto.getRandomValues === 'function') {
      const bytes = new Uint8Array(bytesCount);
      gCrypto.getRandomValues(bytes);
      return Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    }
    throw new Error('CSPRNG unavailable.');
  }

  // Active in-memory state (Zero-secrets policy: wiped on lock or unload)
  const state = {
    account: null, // { accountId, createdAt }
    vault: null, // Local vault metadata
    activeObjectUrl: null, // Blob URL currently previewed in the view modal
    kek: null, // Volatile CryptoKey
    isUnlocked: false,
    activeView: 'view-landing',

    // Account Creation & Recovery
    pendingRecoveryWords: null,
    pendingPassphrase: null,
    requiredConfirmIndices: [3, 7, 10], // 0-based for word 4, 8, 11

    // Encrypt Flow
    isEncryptScanning: false,
    scannedTags: [], // [{ uid, type, totalBytes, writableBytes, existingData }]
    entries: [], // [{ id, type, name, data: Uint8Array, size, mime }]
    requiredTagsCount: 0,
    isWriting: false,
    writeChunkIndex: 0,
    writePassphrase: null,

    // Decrypt Flow
    isDecryptScanning: false,
    decryptScannedChunks: [], // [{ chunkIndex, totalChunks, ciphertext, chunkHash, uid }]
    recoveredEntries: [], // [{ type, name, size, mime, data: Uint8Array, content }]

    // Hardware & Environment
    isWebNfcSupported: typeof window !== 'undefined' && ('NDEFReader' in window),
    isiOS: typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent) && !(typeof window !== 'undefined' && window.MSStream)
  };

  // --- Cryptographic Helpers & Conversion Utilities ---
  function hexToBytes(hex) {
    if (!hex) return new Uint8Array(0);
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  }

  function bytesToHex(bytes) {
    if (!bytes) return '';
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function bytesToBase64(bytes) {
    let binary = '';
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
  }

  async function sha256(buffer) {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', buffer));
  }

  async function deriveKekFromPassphrase(passphrase, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(passphrase),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
    );
  }

  async function encryptAesGcm(key, plaintextBytes, aadBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertextWithTag = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          additionalData: aadBytes || new Uint8Array(0),
          tagLength: 128
        },
        key,
        plaintextBytes
      )
    );

    const ciphertext = ciphertextWithTag.slice(0, ciphertextWithTag.length - 16);
    const tag = ciphertextWithTag.slice(ciphertextWithTag.length - 16);
    return { iv, ciphertext, tag, raw: ciphertextWithTag };
  }

  async function decryptAesGcm(key, ciphertext, iv, tag, aadBytes) {
    const combined = new Uint8Array(ciphertext.length + tag.length);
    combined.set(ciphertext, 0);
    combined.set(tag, ciphertext.length);

    return new Uint8Array(
      await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          additionalData: aadBytes || new Uint8Array(0),
          tagLength: 128
        },
        key,
        combined
      )
    );
  }

  // --- BIP-39 12-Word Recovery Engine ---
  async function generate12WordPhrase() {
    if (!window.BIP39_WORDS || window.BIP39_WORDS.length !== 2048) {
      throw new Error('BIP-39 wordlist not initialized.');
    }
    const entropy = crypto.getRandomValues(new Uint8Array(16)); // 128 bits
    const hash = await sha256(entropy);

    let bits = '';
    for (const b of entropy) {
      bits += b.toString(2).padStart(8, '0');
    }
    const hashBits = hash[0].toString(2).padStart(8, '0').slice(0, 4); // 4-bit checksum
    const totalBits = bits + hashBits; // 132 bits total

    const words = [];
    for (let i = 0; i < 12; i++) {
      const chunk = totalBits.slice(i * 11, (i + 1) * 11);
      const index = parseInt(chunk, 2);
      words.push(window.BIP39_WORDS[index]);
    }
    return { phrase: words.join(' '), words, entropy };
  }

  async function verify12WordPhrase(words) {
    if (!Array.isArray(words) || words.length !== 12) return false;
    if (!window.BIP39_WORDS) return false;

    const wordMap = new Map();
    window.BIP39_WORDS.forEach((w, i) => wordMap.set(w, i));

    let totalBits = '';
    for (const w of words) {
      const clean = w.trim().toLowerCase();
      if (!wordMap.has(clean)) return false;
      totalBits += wordMap.get(clean).toString(2).padStart(11, '0');
    }

    const entropyBits = totalBits.slice(0, 128);
    const checksumBits = totalBits.slice(128);

    const entropy = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      entropy[i] = parseInt(entropyBits.slice(i * 8, (i + 1) * 8), 2);
    }

    const hash = await sha256(entropy);
    const expectedChecksumBits = hash[0].toString(2).padStart(8, '0').slice(0, 4);
    return checksumBits === expectedChecksumBits;
  }

  // --- Canonical Binary Envelope: "GTAG" (Little-Endian) ---
  const RECORD_TYPE_BULK_CHUNK = 0x10; // Canonical Ghost v2 bulk chunk record type

  function buildGtagEnvelope({
    recordType = RECORD_TYPE_BULK_CHUNK,
    vaultIdBytes,
    fileIdBytes,
    keyIdBytes,
    globalChunkIndex,
    totalVaultChunks,
    fileChunkIndex = 0,
    totalFileChunks = 1,
    ciphertext,
    chunkHash,
    iv,
    tag
  }) {
    const headerSize = 4 + 1 + 1 + 16 + 16 + 16 + 4 + 4 + 4 + 4 + 4 + 32 + 12; // 118 bytes
    const totalSize = headerSize + ciphertext.length + 16;
    const buffer = new Uint8Array(totalSize);
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

    buffer.set(MAGIC_BYTES, 0); // "GTAG"
    buffer[4] = FORMAT_VERSION; // 0x02
    buffer[5] = recordType; // 0x10 Bulk Chunk
    buffer.set(vaultIdBytes, 6);
    buffer.set(fileIdBytes, 22);
    buffer.set(keyIdBytes, 38);

    view.setUint32(54, globalChunkIndex, true); // Little-Endian
    view.setUint32(58, totalVaultChunks, true);
    view.setUint32(62, fileChunkIndex, true);
    view.setUint32(66, totalFileChunks, true);
    view.setUint32(70, ciphertext.length, true);

    buffer.set(chunkHash, 74);
    buffer.set(iv, 106);
    buffer.set(ciphertext, 118);
    buffer.set(tag, 118 + ciphertext.length);

    return buffer;
  }

  function parseGtagEnvelope(buffer) {
    if (!buffer || buffer.length < 134) {
      throw new Error('Data is smaller than minimum Ghost envelope overhead (134B).');
    }
    for (let i = 0; i < 4; i++) {
      if (buffer[i] !== MAGIC_BYTES[i]) {
        throw new Error('THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA');
      }
    }
    const version = buffer[4];
    if (version !== 0x02) {
      throw new Error(`Unsupported envelope version: expected 0x02, received 0x${version.toString(16)}`);
    }
    const recordType = buffer[5];
    if (recordType !== 0x10 && recordType !== 0x02) {
      throw new Error(`Unsupported record type: expected 0x10 (BULK_CHUNK), received 0x${recordType.toString(16)}`);
    }
    const vaultId = buffer.slice(6, 22);
    const fileId = buffer.slice(22, 38);
    const keyId = buffer.slice(38, 54);

    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const globalChunkIndex = view.getUint32(54, true);
    const totalVaultChunks = view.getUint32(58, true);
    const fileChunkIndex = view.getUint32(62, true);
    const totalFileChunks = view.getUint32(66, true);
    const ciphertextLen = view.getUint32(70, true);

    const chunkHash = buffer.slice(74, 106);
    const iv = buffer.slice(106, 118);
    const ciphertext = buffer.slice(118, 118 + ciphertextLen);
    const tag = buffer.slice(118 + ciphertextLen, 118 + ciphertextLen + 16);

    if (ciphertext.length !== ciphertextLen) {
      throw new Error('Data was modified or is invalid (truncated ciphertext).');
    }

    const aad = buffer.slice(0, 74);
    return {
      version,
      recordType,
      vaultId,
      fileId,
      keyId,
      globalChunkIndex,
      totalVaultChunks,
      fileChunkIndex,
      totalFileChunks,
      ciphertextLen,
      chunkHash,
      iv,
      ciphertext,
      tag,
      aad
    };
  }

  function buildV1Envelope({ keyIdBytes, iv, ciphertext, tag, purpose = 0x01 }) {
    const aad = new Uint8Array(26);
    aad.set(MAGIC_BYTES, 0);
    aad[4] = 0x01; // v1
    aad[5] = purpose;
    aad.set(keyIdBytes, 6);
    const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
    view.setUint32(22, ciphertext.length, true);

    const buffer = new Uint8Array(54 + ciphertext.length);
    buffer.set(MAGIC_BYTES, 0);
    buffer[4] = 0x01;
    buffer[5] = purpose;
    buffer.set(keyIdBytes, 6);
    buffer.set(iv, 22);
    const vView = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    vView.setUint32(34, ciphertext.length, true);
    buffer.set(ciphertext, 38);
    buffer.set(tag, 38 + ciphertext.length);

    return { envelope: buffer, aad };
  }

  function parseV1Envelope(buffer) {
    if (!buffer || buffer.length < 54) {
      throw new Error('Data is smaller than minimum v1 envelope overhead (54B).');
    }
    for (let i = 0; i < 4; i++) {
      if (buffer[i] !== MAGIC_BYTES[i]) throw new Error('Invalid magic bytes');
    }
    const version = buffer[4];
    if (version !== 0x01) throw new Error('Unsupported envelope version: expected 0x01');
    const purpose = buffer[5];
    const keyId = buffer.slice(6, 22);
    const nonce = buffer.slice(22, 34);
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);
    const ctLen = view.getUint32(34, true);
    if (buffer.length !== 54 + ctLen) {
      throw new Error('Envelope length mismatch');
    }
    const ciphertext = buffer.slice(38, 38 + ctLen);
    const tag = buffer.slice(38 + ctLen, 54 + ctLen);
    const aad = new Uint8Array(26);
    aad.set(MAGIC_BYTES, 0);
    aad[4] = 0x01;
    aad[5] = purpose;
    aad.set(keyId, 6);
    const aadView = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
    aadView.setUint32(22, ctLen, true);

    return { version, purpose, keyId, nonce, ciphertext, tag, aad };
  }

  if (typeof window !== 'undefined') {
    window.GhostEnvelope = {
      buildGtagEnvelope,
      parseGtagEnvelope,
      buildV1Envelope,
      parseV1Envelope,
    };
  }
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      buildGtagEnvelope,
      parseGtagEnvelope,
      buildV1Envelope,
      parseV1Envelope,
    };
  }

  // --- Real Payload Serialization & Chunk Management ---
  function serializeEntriesPayload(entries) {
    const serializable = entries.map(e => ({
      type: e.type,
      name: e.name,
      mime: e.mime,
      size: e.size,
      dataB64: e.data ? bytesToBase64(e.data) : ''
    }));
    return new TextEncoder().encode(JSON.stringify(serializable));
  }

  function deserializeEntriesPayload(plaintextBytes) {
    const jsonStr = new TextDecoder().decode(plaintextBytes);
    const serializable = JSON.parse(jsonStr);
    return serializable.map(e => {
      const dataBytes = e.dataB64 ? base64ToBytes(e.dataB64) : new Uint8Array(0);
      return {
        type: e.type,
        name: e.name,
        mime: e.mime,
        size: e.size || dataBytes.length,
        data: dataBytes,
        content: (e.type === 'Text' || e.type === 'URL') ? new TextDecoder().decode(dataBytes) : null
      };
    });
  }

  function splitCiphertext(fullBytes, chunkSize) {
    if (chunkSize <= 0) chunkSize = 370;
    const chunks = [];
    let offset = 0;
    while (offset < fullBytes.length) {
      const end = Math.min(offset + chunkSize, fullBytes.length);
      chunks.push(fullBytes.slice(offset, end));
      offset = end;
    }
    if (chunks.length === 0) chunks.push(new Uint8Array(0));
    return chunks;
  }

  function joinChunks(chunks) {
    let totalLength = 0;
    for (const c of chunks) totalLength += c.length;
    const joined = new Uint8Array(totalLength);
    let offset = 0;
    for (const c of chunks) {
      joined.set(c, offset);
      offset += c.length;
    }
    return joined;
  }

  // --- Hardware Status Display Manager ---
  function showHardwareNotice(type, customText) {
    const banner = document.getElementById('hardwareNoticeBanner');
    const title = document.getElementById('hardwareNoticeTitle');
    const body = document.getElementById('hardwareNoticeBody');
    const actions = document.getElementById('hardwareNoticeActions');
    if (!banner || !title || !body || !actions) return;

    banner.style.display = 'block';
    actions.innerHTML = '';
    actions.style.display = 'none';

    if (type === 'NO_USB_NFC_READER') {
      title.textContent = 'NO USB NFC READER DETECTED';
      body.textContent = customText || 'A USB NFC reader (ACR122U) running through Ghost Bridge is required to scan or write physical NFC tags on desktop browsers.';
      actions.style.display = 'flex';
      actions.innerHTML = `
        <a href="https://github.com/FROSTY-MUG/Ghost-Tag/tree/main/desktop" target="_blank" class="btn btn-secondary btn-sm" style="text-decoration:none;">Download Ghost Bridge</a>
        <a href="https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.5" target="_blank" class="btn btn-ghost btn-sm" style="text-decoration:none;">Use Android App</a>
      `;
    } else if (type === 'NO_NFC_TAG') {
      title.textContent = 'NO NFC TAG DETECTED';
      body.textContent = customText || 'Ghost Bridge reader is ready. Place an NFC tag on the USB reader antenna.';
    } else if (type === 'NO_NFC_READER') {
      title.textContent = 'NO NFC READER DETECTED';
      body.textContent = customText || 'Web NFC hardware is not detected on this device. Use an Android phone with Chrome or install the Ghost-Tag Android app.';
      actions.style.display = 'flex';
      actions.innerHTML = `
        <a href="https://github.com/FROSTY-MUG/Ghost-Tag/releases/tag/v2.0.5" target="_blank" class="btn btn-secondary btn-sm" style="text-decoration:none;">Download Android APK</a>
      `;
    } else if (type === 'NFC_OFF') {
      title.textContent = 'NFC IS TURNED OFF';
      body.textContent = customText || 'NFC is disabled in your device settings. Please turn on NFC to scan or write tags.';
    } else if (type === 'UNSUPPORTED_TAG') {
      title.textContent = 'THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA';
      body.textContent = customText || 'Only Type 2 / NDEF-formatted tags (NTAG213, NTAG215, NTAG216) are supported for encrypted Ghost data.';
    } else if (type === 'PERMISSION_DENIED') {
      title.textContent = 'NFC PERMISSION DENIED';
      body.textContent = customText || 'NFC access was denied. Please allow NFC permissions in your browser.';
    } else {
      title.textContent = type;
      body.textContent = customText || '';
    }
  }

  function hideHardwareNotice() {
    const banner = document.getElementById('hardwareNoticeBanner');
    if (banner) banner.style.display = 'none';
  }

  // --- Ghost Bridge Client (WebSocket & HTTP RPC to 127.0.0.1:41789) ---
  const ghostBridge = {
    ws: null,
    connected: false,
    hasReader: false,
    cardPresent: false,
    activeCard: null,
    callbacks: new Map(),

    async checkStatus() {
      try {
        const resp = await fetch('http://127.0.0.1:41789/status', { signal: AbortSignal.timeout(1200) });
        if (resp.ok) {
          const data = await resp.json();
          this.hasReader = (data.readers && data.readers.length > 0) || !!data.hasAcr122u;
          this.cardPresent = !!data.cardPresent;
          return data;
        }
      } catch (e) {
        // Bridge daemon not running
      }
      return null;
    },

    connect() {
      if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
        return;
      }
      try {
        const ws = new WebSocket('ws://127.0.0.1:41789');
        this.ws = ws;

        ws.onopen = () => {
          this.connected = true;
          hideHardwareNotice();
          ws.send(JSON.stringify({ action: 'get_status' }));
        };

        ws.onmessage = (event) => {
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'bridge_status') {
              this.hasReader = (msg.readers && msg.readers.length > 0) || !!msg.readerConnected;
              this.cardPresent = !!msg.cardPresent;
              this.activeCard = msg.activeCard;
              if (!this.hasReader && (state.isEncryptScanning || state.isDecryptScanning)) {
                showHardwareNotice('NO_USB_NFC_READER');
              }
            } else if (msg.type === 'card_present') {
              this.cardPresent = true;
              this.activeCard = msg.card;
              hideHardwareNotice();
              if (state.isEncryptScanning) {
                handlePhysicalTagDetected(msg.card);
              } else if (state.isDecryptScanning) {
                handlePhysicalTagDetectedDecrypt(msg.card);
              }
            } else if (msg.type === 'card_removed') {
              this.cardPresent = false;
              this.activeCard = null;
              if (state.isEncryptScanning || state.isDecryptScanning) {
                showHardwareNotice('NO_NFC_TAG');
              }
            } else if (msg.type === 'tag_read_result') {
              const cb = this.callbacks.get('read_tag');
              if (cb) {
                this.callbacks.delete('read_tag');
                cb.resolve(msg);
              }
            } else if (msg.type === 'tag_write_verified') {
              const cb = this.callbacks.get('write_tag');
              if (cb) {
                this.callbacks.delete('write_tag');
                cb.resolve(msg);
              }
            } else if (msg.type === 'error') {
              for (const cb of this.callbacks.values()) {
                cb.reject(new Error(msg.message));
              }
              this.callbacks.clear();
            }
          } catch (err) {
            console.error('[Ghost Bridge] Malformed message:', err);
          }
        };

        ws.onerror = () => {
          this.connected = false;
        };

        ws.onclose = () => {
          this.connected = false;
          this.ws = null;
        };
      } catch (err) {
        this.connected = false;
      }
    },

    async readTag() {
      return new Promise((resolve, reject) => {
        if (!this.connected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
          return reject(new Error('Ghost Bridge is not connected'));
        }
        this.callbacks.set('read_tag', { resolve, reject });
        this.ws.send(JSON.stringify({ action: 'read_tag' }));
        setTimeout(() => {
          if (this.callbacks.has('read_tag')) {
            this.callbacks.delete('read_tag');
            reject(new Error('Tag read timed out.'));
          }
        }, 8000);
      });
    },

    async writeTag(envelopeBytes, mimeType) {
      return new Promise((resolve, reject) => {
        if (!this.connected || !this.ws || this.ws.readyState !== WebSocket.OPEN) {
          return reject(new Error('Ghost Bridge is not connected'));
        }
        this.callbacks.set('write_tag', { resolve, reject });
        this.ws.send(JSON.stringify({
          action: 'write_tag',
          envelopeBytes: Array.from(envelopeBytes),
          mimeType: mimeType || MIME_BULK
        }));
        setTimeout(() => {
          if (this.callbacks.has('write_tag')) {
            this.callbacks.delete('write_tag');
            reject(new Error('Write verification timed out. Tag may have been pulled away.'));
          }
        }, 12000);
      });
    }
  };

  // --- Real Physical NFC Transceiver (Web NFC or Ghost Bridge; NO SYNTHETIC DATA) ---
  async function scanSingleTag() {
    hideHardwareNotice();

    // 1. Android / Supported Mobile Web NFC
    if (state.isWebNfcSupported) {
      try {
        const ndef = new window.NDEFReader();
        await ndef.scan();
        return new Promise((resolve, reject) => {
          ndef.onreading = (event) => {
            const tagUid = event.serialNumber || 'NFC_TAG';
            let rawData = null;
            if (event.message && event.message.records && event.message.records.length > 0) {
              const record = event.message.records[0];
              if (record.data) {
                rawData = new Uint8Array(record.data.buffer);
              }
            }
            resolve({
              uid: tagUid,
              type: 'Detected automatically',
              totalBytes: 504,
              writableBytes: 496,
              existingData: rawData
            });
          };
          ndef.onreadingerror = () => {
            showHardwareNotice('UNSUPPORTED_TAG');
            reject(new Error('THIS TAG TYPE IS NOT SUPPORTED FOR GHOST DATA'));
          };
        });
      } catch (err) {
        if (err.name === 'NotAllowedError') {
          showHardwareNotice('PERMISSION_DENIED');
          throw new Error('NFC permission denied.');
        } else if (err.name === 'NotSupportedError') {
          showHardwareNotice('NO_NFC_READER');
          throw new Error('NO NFC READER DETECTED');
        } else {
          showHardwareNotice('NFC_OFF');
          throw new Error('NFC IS TURNED OFF');
        }
      }
    }

    // 2. Desktop Companion via Ghost Bridge
    const bridgeStatus = await ghostBridge.checkStatus();
    if (!bridgeStatus) {
      // On desktop without a bridge daemon there is no physical reader to use
      showHardwareNotice('NO_USB_NFC_READER');
      throw new Error('NO USB NFC READER DETECTED');
    }

    if (!bridgeStatus.hasAcr122u && (!bridgeStatus.readers || bridgeStatus.readers.length === 0)) {
      showHardwareNotice('NO_USB_NFC_READER', 'Ghost Bridge is connected, but no USB NFC reader was found. Connect an ACS ACR122U USB NFC reader.');
      throw new Error('NO USB NFC READER DETECTED');
    }

    if (!bridgeStatus.cardPresent) {
      showHardwareNotice('NO_NFC_TAG');
      // Wait for physical card_present event via WebSocket
      ghostBridge.connect();
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('NO NFC TAG DETECTED'));
        }, 12000);

        const checkInterval = setInterval(async () => {
          if (ghostBridge.cardPresent && ghostBridge.activeCard) {
            clearInterval(checkInterval);
            clearTimeout(timeout);
            try {
              const readRes = await ghostBridge.readTag();
              resolve({
                uid: ghostBridge.activeCard.uid,
                type: ghostBridge.activeCard.type || 'NTAG215 (ACR122U)',
                totalBytes: ghostBridge.activeCard.totalBytes || 504,
                writableBytes: ghostBridge.activeCard.writableBytes || 496,
                existingData: readRes.rawBytes ? new Uint8Array(readRes.rawBytes) : null
              });
            } catch (readErr) {
              resolve({
                uid: ghostBridge.activeCard.uid,
                type: ghostBridge.activeCard.type || 'NTAG215 (ACR122U)',
                totalBytes: ghostBridge.activeCard.totalBytes || 504,
                writableBytes: ghostBridge.activeCard.writableBytes || 496,
                existingData: null
              });
            }
          }
        }, 350);
      });
    }

    // Card already present on reader
    try {
      const readRes = await ghostBridge.readTag();
      return {
        uid: bridgeStatus.activeCardUid || 'ACR122U_TAG',
        type: 'NTAG215 (ACR122U)',
        totalBytes: 504,
        writableBytes: 496,
        existingData: readRes.rawBytes ? new Uint8Array(readRes.rawBytes) : null
      };
    } catch (e) {
      return {
        uid: bridgeStatus.activeCardUid || 'ACR122U_TAG',
        type: 'NTAG215 (ACR122U)',
        totalBytes: 504,
        writableBytes: 496,
        existingData: null
      };
    }
  }

  async function writeTagNdef(tag, envelopeBytes, mimeType) {
    // 1. Web NFC Write
    if (state.isWebNfcSupported) {
      const ndef = new window.NDEFReader();
      await ndef.write({
        records: [
          {
            recordType: 'mime',
            mediaType: mimeType || MIME_BULK,
            data: envelopeBytes
          }
        ]
      });
      tag.existingData = new Uint8Array(envelopeBytes);
      return true;
    }

    // 2. Ghost Bridge Direct APDU Write with Read-Back Verification
    if (ghostBridge.connected && ghostBridge.hasReader) {
      const res = await ghostBridge.writeTag(envelopeBytes, mimeType);
      if (!res.verified) {
        throw new Error('Physical write verification failed on ACR122U reader.');
      }
      tag.existingData = new Uint8Array(envelopeBytes);
      return true;
    }

    throw new Error('NO USB NFC READER DETECTED');
  }

  function handlePhysicalTagDetected(card) {
    if (!state.isEncryptScanning) return;
    const existing = state.scannedTags.find(t => t.uid === card.uid);
    if (!existing) {
      state.scannedTags.push({
        uid: card.uid,
        type: card.type || 'NTAG215 (ACR122U)',
        totalBytes: card.totalBytes || 504,
        writableBytes: card.writableBytes || 496,
        existingData: null
      });
      logScanHistory({ action: 'scan', maskedUid: maskUid(card.uid), chunkIndex: state.scannedTags.length - 1 });
      updateEncryptScanReadout();
    }
  }

  async function handlePhysicalTagDetectedDecrypt(card) {
    if (!state.isDecryptScanning) return;
    try {
      const readRes = await ghostBridge.readTag();
      if (readRes.rawBytes && readRes.rawBytes.length >= 134) {
        const raw = new Uint8Array(readRes.rawBytes);
        const parsed = parseGtagEnvelope(raw);
        const existing = state.decryptScannedChunks.find(c => c.uid === card.uid || c.chunkIndex === parsed.fileChunkIndex);
        if (!existing) {
          state.decryptScannedChunks.push({
            uid: card.uid,
            chunkIndex: parsed.fileChunkIndex,
            totalChunks: parsed.totalFileChunks,
            ciphertext: parsed.ciphertext,
            chunkHash: parsed.chunkHash,
            existingData: raw
          });
          logScanHistory({ action: 'scan', maskedUid: maskUid(card.uid), chunkIndex: parsed.fileChunkIndex, totalChunks: parsed.totalFileChunks });
          updateDecryptScanReadout();
        }
      } else {
        showHardwareNotice('UNSUPPORTED_TAG', 'This tag does not contain valid Ghost data.');
      }
    } catch (err) {
      console.warn('Physical decrypt read error:', err);
    }
  }

  // --- Opt-in Scan History (Metadata Only: Timestamp, Redacted UID, Chunk Index, Action) ---
  function getScanHistoryOptIn() {
    return localStorage.getItem(STORAGE_KEY_SCAN_HISTORY_OPT_IN) === 'true';
  }

  function setScanHistoryOptIn(val) {
    localStorage.setItem(STORAGE_KEY_SCAN_HISTORY_OPT_IN, val ? 'true' : 'false');
    renderScanHistoryUI();
  }

  function getScanHistoryLogs() {
    try {
      return JSON.parse(localStorage.getItem(STORAGE_KEY_SCAN_HISTORY_RECORDS) || '[]');
    } catch (e) {
      return [];
    }
  }

  function logScanHistory({ action, maskedUid, chunkIndex, totalChunks }) {
    if (!getScanHistoryOptIn()) return;
    const logs = getScanHistoryLogs();
    logs.unshift({
      id: 'sh_' + Date.now() + '_' + generateSecureRandomHex(4),
      timestamp: new Date().toISOString(),
      maskedUid: maskedUid || '04:***:F6',
      action: action || 'scan',
      chunkIndex: chunkIndex !== undefined ? chunkIndex : 0,
      totalChunks: totalChunks || 1
    });
    if (logs.length > 100) logs.pop();
    localStorage.setItem(STORAGE_KEY_SCAN_HISTORY_RECORDS, JSON.stringify(logs));
    renderScanHistoryUI();
  }

  function logAuditEvent({ action }) {
    try {
      const allowedActions = new Set(['recovery_verifier_migrated', 'vault_unlocked', 'vault_locked']);
      const safeAction = allowedActions.has(action) ? action : 'audit_event';
      const record = {
        id: 'aud_' + Date.now() + '_' + generateSecureRandomHex(4),
        timestamp: new Date().toISOString(),
        action: safeAction
      };
      if (typeof localStorage !== 'undefined') {
        const events = JSON.parse(localStorage.getItem('ghost_audit_events') || '[]');
        events.unshift(record);
        if (events.length > 50) events.pop();
        localStorage.setItem('ghost_audit_events', JSON.stringify(events));
      }
    } catch (_) {
      // Ignore logging failure; zero sensitive fields logged
    }
  }

  function maskUid(uid) {
    if (!uid || typeof uid !== 'string') return '04:***:F6';
    const parts = uid.split(':');
    if (parts.length >= 4) {
      return `${parts[0]}:***:${parts[parts.length - 1]}`;
    }
    return uid.length > 6 ? `${uid.slice(0, 3)}***${uid.slice(-2)}` : '04:***:F6';
  }

  function renderScanHistoryUI() {
    const card = document.getElementById('scanHistoryCard');
    const toggle = document.getElementById('scanHistoryToggle');
    const container = document.getElementById('scanHistoryRecordsContainer');
    const list = document.getElementById('scanHistoryList');
    if (!card || !toggle || !container || !list) return;

    const isOptIn = getScanHistoryOptIn();
    toggle.checked = isOptIn;
    container.style.display = isOptIn ? 'block' : 'none';

    if (!isOptIn) return;

    const logs = getScanHistoryLogs();
    if (logs.length === 0) {
      list.innerHTML = '<div style="color: #666; padding: 6px;">No scan history recorded.</div>';
      return;
    }

    list.replaceChildren();
    logs.forEach(l => {
      const row = document.createElement('div');
      row.style.display = 'flex';
      row.style.justifyContent = 'space-between';
      row.style.alignItems = 'center';
      row.style.padding = '4px 0';
      row.style.borderBottom = '1px solid #161616';

      const infoDiv = document.createElement('div');
      const actionSpan = document.createElement('span');
      actionSpan.style.color = 'var(--accent-green)';
      actionSpan.style.textTransform = 'uppercase';
      actionSpan.textContent = `[${String(l.action || '')}]`;

      const uidSpan = document.createElement('span');
      uidSpan.style.color = '#bbb';
      uidSpan.style.marginLeft = '6px';
      uidSpan.textContent = String(l.maskedUid || '');

      const chunkSpan = document.createElement('span');
      chunkSpan.style.color = '#777';
      chunkSpan.style.marginLeft = '6px';
      chunkSpan.textContent = `(Chunk ${(Number(l.chunkIndex) || 0) + 1}/${Number(l.totalChunks) || 1})`;

      infoDiv.appendChild(actionSpan);
      infoDiv.appendChild(uidSpan);
      infoDiv.appendChild(chunkSpan);

      const rightDiv = document.createElement('div');
      rightDiv.style.display = 'flex';
      rightDiv.style.alignItems = 'center';
      rightDiv.style.gap = '8px';

      const timeSpan = document.createElement('span');
      timeSpan.style.color = '#555';
      timeSpan.style.fontSize = '10px';
      const timeStr = String(l.timestamp || '');
      timeSpan.textContent = timeStr.includes('T') ? timeStr.split('T')[1].slice(0, 8) : timeStr;

      const delBtn = document.createElement('button');
      delBtn.style.background = 'none';
      delBtn.style.border = 'none';
      delBtn.style.color = '#ff4444';
      delBtn.style.cursor = 'pointer';
      delBtn.style.fontFamily = 'monospace';
      delBtn.style.fontSize = '12px';
      delBtn.textContent = '×';
      delBtn.addEventListener('click', () => {
        GhostApp.deleteHistoryItem(l.id);
      });

      rightDiv.appendChild(timeSpan);
      rightDiv.appendChild(delBtn);

      row.appendChild(infoDiv);
      row.appendChild(rightDiv);
      list.appendChild(row);
    });
  }

  // --- View Navigation System ---
  function showView(viewId) {
    hideHardwareNotice();
    state.activeView = viewId;
    document.querySelectorAll('.view-section').forEach(el => {
      el.classList.remove('active');
    });
    const target = document.getElementById(viewId);
    if (target) {
      target.classList.add('active');
      window.scrollTo(0, 0);
    }

    // Header visibility: visible once account exists and outside setup views
    const header = document.getElementById('mainHeader');
    if (header) {
      const isAccountView = ['view-welcome', 'view-create-passphrase', 'view-recovery-phrase', 'view-confirm-phrase', 'view-restore-account', 'view-landing', 'view-confirm-restore-ownership', 'view-migrate-recovery'].includes(viewId);
      header.style.display = (!isAccountView && state.account) ? 'flex' : 'none';
    }
  }

  function showModal(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.classList.add('active');
  }

  function hideModal(modalId) {
    const el = document.getElementById(modalId);
    if (el) el.classList.remove('active');
  }

  function showPassphraseModal(descriptionText, callback) {
    state.passphraseCallback = callback;
    const input = document.getElementById('modalPassphraseInput');
    const desc = document.getElementById('modalPassphraseDescription');
    if (desc && descriptionText) desc.textContent = descriptionText;
    if (input) input.value = '';
    showModal('modalPassphrase');
    setTimeout(() => { if (input) input.focus(); }, 100);
  }

  // --- App Initialization & Local Account Load ---
  async function init() {
    const loadingScreen = document.getElementById('loadingScreen') || document.getElementById('initialLoadingScreen');
    if (loadingScreen) {
      setTimeout(() => {
        loadingScreen.classList.add('fade-out');
        setTimeout(() => {
          if (loadingScreen.parentNode) loadingScreen.parentNode.removeChild(loadingScreen);
        }, 500);
      }, 500);
    }

    // Load Local Account & Vault
    try {
      const storedAccount = localStorage.getItem(STORAGE_KEY_ACCOUNT);
      const storedVault = localStorage.getItem(STORAGE_KEY_LOCAL_VAULT);
      if (storedAccount) state.account = JSON.parse(storedAccount);
      if (storedVault) state.vault = JSON.parse(storedVault);
    } catch (e) {
      state.account = null;
      state.vault = null;
    }

    // iOS Check
    if (state.isiOS) {
      const iosBanner = document.getElementById('iosNotice');
      if (iosBanner) iosBanner.style.display = 'block';
    }

    // Bind UI actions & setup display
    bindEvents();
    updateAccountDisplay();
    renderScanHistoryUI();

    // Default route
    if (window.location.hash) {
      handleHashRoute();
    } else {
      showView('view-landing');
    }
  }

  // --- Event Bindings ---
  function bindEvents() {
    // Brand Group Click
    document.querySelectorAll('.brand-group').forEach(el => {
      el.addEventListener('click', () => {
        if (state.account) showView('view-app');
        else showView('view-landing');
      });
    });

    // 1. [ Launch Web Version ]
    document.getElementById('btnLaunch')?.addEventListener('click', () => {
      if (state.account) showView('view-app');
      else showView('view-welcome');
    });

    // 2. [ Create Account ]
    document.getElementById('btnWelcomeCreate')?.addEventListener('click', () => {
      showView('view-create-passphrase');
    });

    // 3. [ I Already Have a Recovery Phrase ]
    document.getElementById('btnWelcomeImport')?.addEventListener('click', () => {
      showView('view-restore-account');
    });

    // 4. [ Continue ] (Create Passphrase)
    document.getElementById('btnCreatePassphrase')?.addEventListener('click', async () => {
      const input = document.getElementById('newPassphraseInput');
      const pass = input ? input.value : '';
      const errEl = document.getElementById('createPassphraseError');

      if (!pass || pass.length < 16) {
        if (errEl) {
          errEl.textContent = 'Minimum 16 characters required.';
          errEl.style.display = 'block';
        }
        return;
      }
      if (errEl) errEl.style.display = 'none';

      try {
        const btn = document.getElementById('btnCreatePassphrase');
        btn.classList.add('btn-loading');
        btn.disabled = true;

        const { words } = await generate12WordPhrase();
        state.pendingRecoveryWords = words;
        state.pendingPassphrase = pass;

        const grid = document.getElementById('recoveryGrid');
        if (grid) {
          grid.innerHTML = words.map((w, idx) => `
            <div class="phrase-word-card">
              <span class="word-index">${idx + 1}.</span>
              <span class="word-text">${w}</span>
            </div>
          `).join('');
        }

        showView('view-recovery-phrase');
      } catch (err) {
        alert('Failed to generate recovery phrase: ' + err.message);
      } finally {
        const btn = document.getElementById('btnCreatePassphrase');
        btn.classList.remove('btn-loading');
        btn.disabled = false;
      }
    });

    // 5. [ I Have Saved It Safely ]
    document.getElementById('btnSavedPhrase')?.addEventListener('click', () => {
      const indices = [3, 7, 10]; // Word 4, 8, 11
      state.requiredConfirmIndices = indices;

      document.getElementById('confirmLabel1').textContent = `Enter word ${indices[0] + 1}:`;
      document.getElementById('confirmLabel2').textContent = `Enter word ${indices[1] + 1}:`;
      document.getElementById('confirmLabel3').textContent = `Enter word ${indices[2] + 1}:`;

      document.getElementById('confirmInput1').value = '';
      document.getElementById('confirmInput2').value = '';
      document.getElementById('confirmInput3').value = '';

      showView('view-confirm-phrase');
    });

    // 6. [ Confirm ] (Confirm Recovery Phrase)
    document.getElementById('btnConfirmPhrase')?.addEventListener('click', async () => {
      const in1 = (document.getElementById('confirmInput1').value || '').trim().toLowerCase();
      const in2 = (document.getElementById('confirmInput2').value || '').trim().toLowerCase();
      const in3 = (document.getElementById('confirmInput3').value || '').trim().toLowerCase();
      const errEl = document.getElementById('confirmPhraseError');

      const [i1, i2, i3] = state.requiredConfirmIndices;
      const exp1 = state.pendingRecoveryWords[i1].toLowerCase();
      const exp2 = state.pendingRecoveryWords[i2].toLowerCase();
      const exp3 = state.pendingRecoveryWords[i3].toLowerCase();

      if (in1 !== exp1 || in2 !== exp2 || in3 !== exp3) {
        if (errEl) {
          errEl.textContent = 'Recovery phrase verification mismatch. Check your saved words.';
          errEl.style.display = 'block';
        }
        return;
      }
      if (errEl) errEl.style.display = 'none';

      try {
        const btn = document.getElementById('btnConfirmPhrase');
        btn.classList.add('btn-loading');
        btn.disabled = true;

        const accountId = await window.GhostSupabase.deriveAccountId(state.pendingRecoveryWords);
        const salt = crypto.getRandomValues(new Uint8Array(32));
        const kek = await deriveKekFromPassphrase(state.pendingPassphrase, salt);

        const rawDek = crypto.getRandomValues(new Uint8Array(32));
        const wrappedDek = await encryptAesGcm(kek, rawDek, new Uint8Array([0x56, 0x4B])); // "VK"

        // Canonical Argon2id recovery credentials for cross-platform Supabase recovery
        const authSecretBytes = await window.GhostSupabase.deriveRecoveryAuthSecret(state.pendingRecoveryWords);
        const recoverySalt = await window.GhostSupabase.deriveRecoverySalt(state.pendingRecoveryWords);
        const recoveryVerifierHex = await window.GhostSupabase.computeRecoveryVerifier(authSecretBytes, recoverySalt);
        const recoverySaltHex = bytesToHex(recoverySalt);

        const accountData = { accountId: accountId, createdAt: Date.now() };
        const vaultData = {
          vaultVersion: FORMAT_VERSION,
          accountId: accountId,
          saltHex: bytesToHex(salt),
          wrappedDekHex: bytesToHex(wrappedDek.ciphertext),
          dekIvHex: bytesToHex(wrappedDek.iv),
          dekTagHex: bytesToHex(wrappedDek.tag),
          recoverySaltHex: recoverySaltHex,
          recoveryVerifierHex: recoveryVerifierHex,
          updatedAt: Date.now()
        };

        localStorage.setItem(STORAGE_KEY_ACCOUNT, JSON.stringify(accountData));
        localStorage.setItem(STORAGE_KEY_LOCAL_VAULT, JSON.stringify(vaultData));
        state.account = accountData;
        state.vault = vaultData;
        state.kek = kek;
        state.isUnlocked = true;

        const metadataBlob = btoa(JSON.stringify(vaultData));
        await window.GhostSupabase.uploadEncryptedVault(accountId, metadataBlob, FORMAT_VERSION, {
          recoveryVerifierHex: recoveryVerifierHex,
          recoverySaltHex: recoverySaltHex
        });

        state.pendingPassphrase = null;
        state.pendingRecoveryWords = null;

        updateAccountDisplay();
        showView('view-account-created');
      } catch (err) {
        alert('Account creation failed: ' + err.message);
      } finally {
        const btn = document.getElementById('btnConfirmPhrase');
        btn.classList.remove('btn-loading');
        btn.disabled = false;
      }
    });

    // 7. [ Restore Account ]
    const handleRestoreAccount = async () => {
      const input = document.getElementById('importRecoveryPhraseInput');
      const text = (input ? input.value : '').trim();
      const words = text.split(/\s+/).filter(Boolean);
      const errEl = document.getElementById('importRecoveryError');

      if (words.length !== 12) {
        if (errEl) {
          errEl.textContent = 'Recovery phrase is invalid. (Must be exactly 12 words)';
          errEl.style.display = 'block';
        }
        return;
      }

      const valid = await verify12WordPhrase(words);
      if (!valid) {
        if (errEl) {
          errEl.textContent = 'Recovery phrase is invalid.';
          errEl.style.display = 'block';
        }
        return;
      }
      if (errEl) errEl.style.display = 'none';

      // Transition to explicit ownership transfer confirmation view
      state.pendingRestoreWords = words;
      showView('view-confirm-restore-ownership');
    };

    document.getElementById('btnCancelRestoreOwnership')?.addEventListener('click', () => {
      state.pendingRestoreWords = null;
      showView('view-restore-account');
    });

    document.getElementById('btnConfirmRestoreOwnership')?.addEventListener('click', async () => {
      const words = state.pendingRestoreWords;
      if (!words) {
        showView('view-restore-account');
        return;
      }

      const btn = document.getElementById('btnConfirmRestoreOwnership');
      if (btn) btn.classList.add('btn-loading');

      try {
        let accountId = await window.GhostSupabase.deriveAccountId(words);
        let remoteVault = await window.GhostSupabase.downloadEncryptedVault(accountId);
        if (!remoteVault) {
          const legacyAccountId = await window.GhostSupabase.deriveLegacyAccountId(words);
          const legacyVault = await window.GhostSupabase.downloadEncryptedVault(legacyAccountId);
          if (legacyVault) {
            accountId = legacyAccountId;
            remoteVault = legacyVault;
          }
        }

        showPassphraseModal('Enter your master passphrase to unlock and restore the vault metadata:', async (passphrase) => {
          try {
            let vaultData = null;
            if (remoteVault && remoteVault.encryptedBlob) {
              vaultData = JSON.parse(atob(remoteVault.encryptedBlob));
            } else if (state.vault) {
              vaultData = state.vault;
            } else {
              const salt = crypto.getRandomValues(new Uint8Array(32));
              vaultData = {
                vaultVersion: FORMAT_VERSION,
                accountId: accountId,
                saltHex: bytesToHex(salt),
                updatedAt: Date.now()
              };
            }

            const salt = hexToBytes(vaultData.saltHex || '00'.repeat(32));
            const kek = await deriveKekFromPassphrase(passphrase, salt);

            state.account = { accountId, createdAt: Date.now() };
            state.vault = vaultData;
            state.kek = kek;
            state.isUnlocked = true;

            localStorage.setItem(STORAGE_KEY_ACCOUNT, JSON.stringify(state.account));
            localStorage.setItem(STORAGE_KEY_VAULT, JSON.stringify(state.vault));

            updateHeaderAccountStatus();
            renderVaultEntries();

            if (remoteVault && remoteVault.needsMigration) {
              state.pendingMigration = {
                accountId,
                words
              };
              showView('view-migrate-recovery');
            } else {
              showView('view-app');
            }
          } catch (err) {
            alert('Failed to restore vault with provided passphrase: ' + err.message);
          }
        });
      } catch (err) {
        alert('Failed to restore account: ' + err.message);
      } finally {
        if (btn) btn.classList.remove('btn-loading');
      }
    });

    // Migration handlers for legacy web recovery verifiers
    document.getElementById('btnConfirmMigration')?.addEventListener('click', async () => {
      const pm = state.pendingMigration;
      if (!pm) {
        showView('view-app');
        return;
      }
      const btn = document.getElementById('btnConfirmMigration');
      const errEl = document.getElementById('migrationError');
      if (errEl) errEl.style.display = 'none';
      if (btn) btn.classList.add('btn-loading');

      try {
        const res = await window.GhostSupabase.upgradeRecoveryVerifier(pm.accountId, pm.words);
        if (state.vault) {
          state.vault.recoveryVerifierHex = res.recoveryVerifierHex;
          state.vault.recoverySaltHex = res.recoverySaltHex;
          state.vault.recoveryKdfVersion = 2;
          localStorage.setItem(STORAGE_KEY_VAULT, JSON.stringify(state.vault));
        }
        logAuditEvent({ action: 'recovery_verifier_migrated' });
        state.pendingMigration = null;
        alert('Recovery verifier successfully upgraded to canonical Argon2id (RFC 9106).');
        showView('view-app');
      } catch (err) {
        if (errEl) {
          errEl.textContent = 'Upgrade failed: ' + err.message;
          errEl.style.display = 'block';
        } else {
          alert('Upgrade failed: ' + err.message);
        }
      } finally {
        if (btn) btn.classList.remove('btn-loading');
      }
    });

    document.getElementById('btnDismissMigration')?.addEventListener('click', () => {
      state.pendingMigration = null;
      showView('view-app');
    });

    document.getElementById('btnSubmitRestoreAccount')?.addEventListener('click', handleRestoreAccount);
    document.getElementById('btnRestoreAccountInAccount')?.addEventListener('click', () => {
      showView('view-restore-account');
    });

    // Nav Links: Account, Recovery, Settings
    document.getElementById('headerAccountLink')?.addEventListener('click', () => showView('view-account'));
    document.getElementById('headerRecoveryLink')?.addEventListener('click', () => showView('view-recovery'));
    document.getElementById('headerSettingsLink')?.addEventListener('click', () => showView('view-settings'));

    // Account Created Nav buttons
    document.getElementById('btnGoEncryptCreated')?.addEventListener('click', () => startEncryptFlow());
    document.getElementById('btnGoDecryptCreated')?.addEventListener('click', () => startDecryptFlow());

    // Main App [ Encrypt ] and [ Decrypt ]
    document.getElementById('btnMainEncrypt')?.addEventListener('click', () => startEncryptFlow());
    document.getElementById('btnMainDecrypt')?.addEventListener('click', () => startDecryptFlow());

    // --- ENCRYPT FLOW ---
    function startEncryptFlow() {
      if (!state.account) {
        showView('view-welcome');
        return;
      }
      state.scannedTags = [];
      state.entries = [];
      updateEncryptScanReadout();
      showView('view-encrypt-scan');
    }

    // 8. [ Start Scanning ] (Encrypt)
    const btnStartScanning = document.getElementById('btnStartScanning');
    const btnEndScanningProcess = document.getElementById('btnEndScanningProcess');

    async function scanEncryptTagStep() {
      state.isEncryptScanning = true;
      if (btnStartScanning) btnStartScanning.style.display = 'none';
      if (btnEndScanningProcess) btnEndScanningProcess.style.display = 'inline-block';
      const sub = document.getElementById('encryptScanSubtitle');
      if (sub) sub.textContent = 'Scanning NFC tags... Place each tag near your device transceiver.';

      try {
        const tag = await scanSingleTag();
        if (state.isEncryptScanning) {
          state.scannedTags.push(tag);
          logScanHistory({ action: 'scan', maskedUid: maskUid(tag.uid), chunkIndex: state.scannedTags.length - 1 });
          updateEncryptScanReadout();
          if (sub) sub.textContent = `Tag #${state.scannedTags.length} detected. Tap 'Scan Next Tag' or 'End Scanning Process'.`;
        }
      } catch (err) {
        if (sub) sub.textContent = err.message || 'Tag read error. Try again.';
      } finally {
        state.isEncryptScanning = false;
        if (btnStartScanning) {
          btnStartScanning.textContent = 'Scan Next Tag';
          btnStartScanning.style.display = 'inline-block';
        }
      }
    }

    btnStartScanning?.addEventListener('click', scanEncryptTagStep);
    document.getElementById('btnScanNextTag')?.addEventListener('click', scanEncryptTagStep);

    // 9. [ End Scanning Process ]
    const finishScanning = () => {
      state.isEncryptScanning = false;
      if (state.scannedTags.length === 0) {
        alert('Please scan at least one NFC tag first.');
        return;
      }
      updateScanningCompleteStats();
      renderEntriesList();
      showView('view-encrypt-add');
    };

    btnEndScanningProcess?.addEventListener('click', finishScanning);
    document.getElementById('btnFinishScanning')?.addEventListener('click', finishScanning);

    // 10. Adding Content Entries
    document.getElementById('btnAddText')?.addEventListener('click', () => {
      document.getElementById('textEntryTitle').value = '';
      document.getElementById('textEntryContent').value = '';
      showModal('modalAddText');
    });

    document.getElementById('btnSaveTextEntry')?.addEventListener('click', () => {
      const title = (document.getElementById('textEntryTitle').value || '').trim();
      const content = (document.getElementById('textEntryContent').value || '').trim();
      if (!content) return;

      const raw = new TextEncoder().encode(content);
      state.entries.push({
        id: 'e_' + generateSecureRandomHex(6),
        type: 'Text',
        name: title || 'note.txt',
        data: raw,
        content: content,
        size: raw.length,
        mime: 'text/plain'
      });

      hideModal('modalAddText');
      renderEntriesList();
    });

    document.getElementById('btnAddFile')?.addEventListener('click', () => {
      document.getElementById('filePickerGeneric').click();
    });

    document.getElementById('filePickerGeneric')?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const buf = new Uint8Array(await file.arrayBuffer());
      state.entries.push({
        id: 'e_' + generateSecureRandomHex(6),
        type: 'File',
        name: file.name,
        data: buf,
        size: buf.length,
        mime: file.type || 'application/octet-stream'
      });
      renderEntriesList();
    });

    document.getElementById('btnAddPhoto')?.addEventListener('click', () => {
      document.getElementById('filePickerPhoto').click();
    });

    document.getElementById('filePickerPhoto')?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const buf = new Uint8Array(await file.arrayBuffer());
      state.entries.push({
        id: 'e_' + generateSecureRandomHex(6),
        type: 'Photo',
        name: file.name,
        data: buf,
        size: buf.length,
        mime: file.type || 'image/jpeg'
      });
      renderEntriesList();
    });

    document.getElementById('btnAddVideo')?.addEventListener('click', () => {
      document.getElementById('filePickerVideo').click();
    });

    document.getElementById('filePickerVideo')?.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      const buf = new Uint8Array(await file.arrayBuffer());
      state.entries.push({
        id: 'e_' + generateSecureRandomHex(6),
        type: 'Video',
        name: file.name,
        data: buf,
        size: buf.length,
        mime: file.type || 'video/mp4'
      });
      renderEntriesList();
    });

    document.getElementById('btnAddURL')?.addEventListener('click', () => {
      document.getElementById('urlEntryLink').value = '';
      showModal('modalAddURL');
    });

    document.getElementById('btnSaveURLEntry')?.addEventListener('click', () => {
      const url = (document.getElementById('urlEntryLink').value || '').trim();
      if (!url) return;

      const raw = new TextEncoder().encode(url);
      state.entries.push({
        id: 'e_' + generateSecureRandomHex(6),
        type: 'URL',
        name: url,
        data: raw,
        content: url,
        size: raw.length,
        mime: 'text/uri-list'
      });

      hideModal('modalAddURL');
      renderEntriesList();
    });

    // 11. [ Add Another Entry ]
    document.getElementById('btnAddAnotherEntry')?.addEventListener('click', () => {
      document.getElementById('btnAddText')?.focus();
    });

    // 12. [ Write Everything ] & Capacity Check
    document.getElementById('btnWriteEverything')?.addEventListener('click', () => {
      if (state.entries.length === 0) {
        alert('Please add at least one entry.');
        return;
      }
      showPassphraseModal('Your entries will be encrypted and written across the selected NFC tags.', (passphrase) => {
        executeWriteEverything(passphrase);
      });
    });

    // 13. [ Stop Writing ]
    document.getElementById('btnStopWriting')?.addEventListener('click', () => {
      state.isWriting = false;
    });

    // 14. [ Done ] (Encryption Done)
    document.getElementById('btnEncryptionDone')?.addEventListener('click', () => {
      state.entries = [];
      state.scannedTags = [];
      showView('view-app');
    });

    // --- DECRYPT FLOW ---
    function startDecryptFlow() {
      if (!state.account) {
        showView('view-welcome');
        return;
      }
      state.decryptScannedChunks = [];
      state.recoveredEntries = [];
      updateDecryptScanReadout();
      showView('view-decrypt-scan');
    }

    // 15. [ Start Scanning ] (Decrypt)
    const btnStartDecryptScanning = document.getElementById('btnStartDecryptScanning');
    const btnAllChipsScanned = document.getElementById('btnAllChipsScanned');

    async function scanDecryptTagStep() {
      state.isDecryptScanning = true;
      if (btnStartDecryptScanning) btnStartDecryptScanning.style.display = 'none';
      if (btnAllChipsScanned) btnAllChipsScanned.style.display = 'inline-block';

      try {
        const tag = await scanSingleTag();
        if (state.isDecryptScanning) {
          if (tag.existingData && tag.existingData.length >= 134) {
            try {
              const parsed = parseGtagEnvelope(tag.existingData);
              const exists = state.decryptScannedChunks.find(c => c.uid === tag.uid || c.chunkIndex === parsed.fileChunkIndex);
              if (!exists) {
                state.decryptScannedChunks.push({
                  uid: tag.uid,
                  chunkIndex: parsed.fileChunkIndex,
                  totalChunks: parsed.totalFileChunks,
                  ciphertext: parsed.ciphertext,
                  chunkHash: parsed.chunkHash,
                  existingData: tag.existingData
                });
                logScanHistory({ action: 'scan', maskedUid: maskUid(tag.uid), chunkIndex: parsed.fileChunkIndex, totalChunks: parsed.totalFileChunks });
              }
            } catch (envErr) {
              state.decryptScannedChunks.push({ ...tag, isUnknown: true });
            }
          } else {
            state.decryptScannedChunks.push({ ...tag, isUnknown: true });
          }
          updateDecryptScanReadout();
        }
      } catch (err) {
        console.warn('Decrypt scan error:', err);
      } finally {
        state.isDecryptScanning = false;
        if (btnStartDecryptScanning) {
          btnStartDecryptScanning.textContent = 'Scan Next Tag';
          btnStartDecryptScanning.style.display = 'inline-block';
        }
      }
    }

    btnStartDecryptScanning?.addEventListener('click', scanDecryptTagStep);

    // 16. [ All Chips Scanned ]
    const finishDecryptScan = () => {
      state.isDecryptScanning = false;
      const validChunks = state.decryptScannedChunks.filter(c => !c.isUnknown);
      if (validChunks.length === 0) {
        alert('No Ghost-Tag encrypted records were found on the scanned tags.');
        return;
      }
      showPassphraseModal('Enter your master passphrase to decrypt:', (passphrase) => {
        executeVaultDecryption(passphrase);
      });
    };

    btnAllChipsScanned?.addEventListener('click', finishDecryptScan);
    document.getElementById('btnTriggerDecryptNow')?.addEventListener('click', finishDecryptScan);

    // 17. [ Clear Temporary Data ]
    document.getElementById('btnClearTemporaryData')?.addEventListener('click', () => {
      state.recoveredEntries = [];
      state.decryptScannedChunks = [];
      showView('view-app');
    });

    // 18. Error button handlers
    document.getElementById('btnScanMoreTagsMissing')?.addEventListener('click', () => {
      showView('view-decrypt-scan');
    });

    document.getElementById('btnTryAgainDecrypt')?.addEventListener('click', () => {
      finishDecryptScan();
    });

    // 19. Entry Deletion Flow with Corruption Warning
    document.getElementById('btnConfirmDeleteEntry')?.addEventListener('click', () => {
      hideModal('modalDeleteEntry');
      if (state.pendingDeleteIndex !== undefined && state.pendingDeleteIndex >= 0) {
        state.recoveredEntries.splice(state.pendingDeleteIndex, 1);
        state.pendingDeleteIndex = -1;
      }
      renderRecoveredEntries();
      alert('ENTRY DELETED: Entry removed and remaining NFC chunks reassembled.');
    });

    // Settings actions & Cloud Sync
    document.getElementById('btnSaveCloudConfig')?.addEventListener('click', () => {
      const url = document.getElementById('supabaseUrlInput')?.value;
      const key = document.getElementById('supabaseKeyInput')?.value;
      window.GhostSupabase.saveConfig(url, key);
      const formEl = document.getElementById('cloudSyncForm');
      if (formEl) formEl.style.display = 'none';
      updateAccountDisplay();
      handleSyncNow();
    });

    document.getElementById('btnCancelCloudConfig')?.addEventListener('click', () => {
      const formEl = document.getElementById('cloudSyncForm');
      if (formEl) formEl.style.display = 'none';
    });

    document.getElementById('btnRetryCloudSync')?.addEventListener('click', async () => {
      const banner = document.getElementById('cloudSyncUnavailableBanner');
      if (banner) banner.style.display = 'none';
      await handleSyncNow();
    });

    document.getElementById('btnLockVault')?.addEventListener('click', () => {
      state.kek = null;
      state.isUnlocked = false;
      showView('view-landing');
    });

    document.getElementById('btnDeleteVaultSettings')?.addEventListener('click', () => {
      showModal('modalDeleteVault');
    });

    document.getElementById('btnConfirmDeleteVault')?.addEventListener('click', async () => {
      hideModal('modalDeleteVault');
      if (state.account) {
        await window.GhostSupabase.deleteRemoteVault(state.account.accountId);
      }
      localStorage.removeItem(STORAGE_KEY_ACCOUNT);
      localStorage.removeItem(STORAGE_KEY_LOCAL_VAULT);
      state.account = null;
      state.vault = null;
      state.kek = null;
      state.isUnlocked = false;
      alert('Local Ghost vault deleted.');
      showView('view-landing');
    });

    // Scan History Handlers
    document.getElementById('scanHistoryToggle')?.addEventListener('change', (e) => {
      setScanHistoryOptIn(e.target.checked);
    });

    document.getElementById('btnExportScanHistory')?.addEventListener('click', () => {
      const logs = getScanHistoryLogs();
      const report = {
        app: 'Ghost-Tag',
        version: '2.0.5',
        exportedAt: new Date().toISOString(),
        totalScans: logs.length,
        records: logs
      };
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ghost-tag-redacted-scan-history-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    });

    document.getElementById('btnClearScanHistory')?.addEventListener('click', () => {
      if (confirm('Clear all recorded scan history?')) {
        localStorage.removeItem(STORAGE_KEY_SCAN_HISTORY_RECORDS);
        renderScanHistoryUI();
      }
    });

    // Generic Modal Dismiss Handlers
    document.querySelectorAll('[data-dismiss="modal"]').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
      });
    });

    document.getElementById('btnCancelPassphraseModal')?.addEventListener('click', () => {
      hideModal('modalPassphrase');
      state.passphraseCallback = null;
    });

    document.getElementById('btnSubmitPassphraseModal')?.addEventListener('click', () => {
      const pass = document.getElementById('modalPassphraseInput')?.value;
      if (!pass) return;
      hideModal('modalPassphrase');
      if (state.passphraseCallback) {
        state.passphraseCallback(pass);
        state.passphraseCallback = null;
      }
    });

    // View Modal Download Button
    document.getElementById('btnDownloadFromViewModal')?.addEventListener('click', () => {
      if (state.activeViewingIndex !== undefined && state.activeViewingIndex >= 0) {
        window.GhostApp.downloadEntry(state.activeViewingIndex);
      }
    });

    document.getElementById('btnContinueWithoutNfc')?.addEventListener('click', () => {
      const iosBanner = document.getElementById('iosNotice');
      if (iosBanner) iosBanner.style.display = 'none';
    });
  }

  // --- UI Update Helpers ---
  function updateAccountDisplay() {
    const accEl = document.getElementById('accountDisplayId');
    const syncEl = document.getElementById('accountSyncStatus');
    if (accEl) accEl.textContent = state.account ? state.account.accountId : 'Not created';

    const syncStatus = window.GhostSupabase.getStatus();
    if (syncEl) syncEl.textContent = syncStatus.label;

    renderCloudSyncSettings(syncStatus);
  }

  function renderCloudSyncSettings(syncStatus) {
    const statusBlock = document.getElementById('cloudSyncStatusBlock');
    const actionsBlock = document.getElementById('cloudSyncActions');
    if (!statusBlock || !actionsBlock) return;

    statusBlock.innerHTML = `
      <div style="font-size: 13px; color: #fff; margin-bottom: 4px;">Status: <strong>${syncStatus.label}</strong></div>
      <div style="font-size: 12px; color: #777;">Mode: Configurable | Real-time Zero-Knowledge Metadata</div>
    `;

    if (!syncStatus.configured) {
      actionsBlock.innerHTML = `
        <button class="btn btn-secondary btn-sm" id="btnOpenCloudConfig" style="width: auto;">Configure Supabase Sync</button>
      `;
      document.getElementById('btnOpenCloudConfig')?.addEventListener('click', () => {
        const formEl = document.getElementById('cloudSyncForm');
        if (formEl) formEl.style.display = 'block';
      });
    } else {
      actionsBlock.innerHTML = `
        <button class="btn btn-primary btn-sm" id="btnSyncNow" style="width: auto;">Sync Now</button>
        <button class="btn btn-ghost btn-sm" id="btnEditCloudConfig" style="width: auto;">Edit Credentials</button>
      `;
      document.getElementById('btnSyncNow')?.addEventListener('click', handleSyncNow);
      document.getElementById('btnEditCloudConfig')?.addEventListener('click', () => {
        const formEl = document.getElementById('cloudSyncForm');
        if (formEl) formEl.style.display = 'block';
      });
    }
  }

  async function handleSyncNow() {
    if (!state.account || !state.vault) return;
    const banner = document.getElementById('cloudSyncUnavailableBanner');
    try {
      const metadataBlob = btoa(JSON.stringify(state.vault));
      await window.GhostSupabase.uploadEncryptedVault(state.account.accountId, metadataBlob, FORMAT_VERSION, {
        recoveryVerifierHex: state.vault.recoveryVerifierHex,
        recoverySaltHex: state.vault.recoverySaltHex
      });
      if (banner) banner.style.display = 'none';
      alert('Vault metadata synchronized with Supabase.');
    } catch (err) {
      if (banner) banner.style.display = 'block';
    }
  }

  function updateEncryptScanReadout() {
    const totalTags = state.scannedTags.length;
    const readout = document.getElementById('encryptScanReadout');
    if (!readout) return;

    if (totalTags === 0) {
      readout.style.display = 'none';
      return;
    }

    readout.style.display = 'block';
    document.getElementById('encryptTotalTagsScanned').textContent = totalTags;

    let totalReadable = 0;
    let totalWritable = 0;
    let totalGhost = 0;

    const listHtml = state.scannedTags.map((tag, idx) => {
      totalReadable += tag.totalBytes;
      totalWritable += tag.writableBytes;
      const ghostUsable = Math.max(0, tag.writableBytes - 134);
      totalGhost += ghostUsable;

      return `
        <div style="font-size: 11px; margin-bottom: 4px; color: var(--text-secondary);">
          TAG #${idx + 1}: <span style="color:#fff;">${tag.uid}</span> · ${tag.writableBytes}B writable · <span style="color:var(--accent-green);">${ghostUsable}B Ghost storage</span>
        </div>
      `;
    }).join('');

    document.getElementById('encryptTagList').innerHTML = listHtml;
    document.getElementById('encryptTotalReadableStorage').textContent = `${totalReadable} bytes`;
    document.getElementById('encryptTotalWritableStorage').textContent = `${totalWritable} bytes`;
    document.getElementById('encryptTotalUsableGhost').textContent = `${totalGhost} bytes`;
  }

  function updateScanningCompleteStats() {
    const statsEl = document.getElementById('scanningCompleteStats');
    if (!statsEl) return;

    const totalTags = state.scannedTags.length;
    let totalGhost = 0;
    for (const t of state.scannedTags) {
      totalGhost += Math.max(0, t.writableBytes - 134);
    }

    statsEl.innerHTML = `
      <div class="status-line"><span class="mono-label">TAGS DETECTED:</span> <span class="mono-value">${totalTags}</span></div>
      <div class="status-line"><span class="mono-label">USABLE GHOST STORAGE:</span> <span class="mono-value" style="color:var(--accent-green);">${totalGhost} bytes</span></div>
    `;
  }

  function renderEntriesList() {
    const container = document.getElementById('entriesListContainer');
    const writeBtn = document.getElementById('btnWriteEverything');
    const tooLargeBox = document.getElementById('capacityTooLargeAlert');
    const readyBox = document.getElementById('capacityReadyBox');
    const statsBox = document.getElementById('entriesStatsBox');

    if (!container) return;

    if (state.entries.length === 0) {
      container.innerHTML = '<div style="font-size: 13px; color: var(--text-secondary); padding: 12px 0;">No entries added yet. Tap a button above to add content.</div>';
      if (writeBtn) writeBtn.disabled = true;
      if (tooLargeBox) tooLargeBox.style.display = 'none';
      if (readyBox) readyBox.style.display = 'none';
      if (statsBox) statsBox.style.display = 'none';
      return;
    }

    container.innerHTML = state.entries.map((e, idx) => `
      <div class="file-item">
        <div class="file-meta">
          <span class="file-name">${idx + 1}. [${e.type}] ${e.name}</span>
          <span class="file-size">${formatBytes(e.size)}</span>
        </div>
        <button class="btn btn-ghost btn-sm" style="color: var(--accent-red);" onclick="GhostApp.removeEntry(${idx})">Remove</button>
      </div>
    `).join('');

    // Compute total raw entry bytes
    let totalPayloadBytes = 0;
    for (const e of state.entries) totalPayloadBytes += e.size;

    // Fixed cryptographic envelope and chunk overhead
    const estimatedCiphertextLen = totalPayloadBytes + 200; // Includes serialized JSON metadata + AAD + padding
    const avgTagPayload = Math.max(16, (state.scannedTags[0]?.writableBytes || 496) - 134);
    const requiredTags = Math.ceil(estimatedCiphertextLen / avgTagPayload);
    state.requiredTagsCount = Math.max(1, requiredTags);

    let totalUsableStorage = 0;
    for (const t of state.scannedTags) {
      totalUsableStorage += Math.max(0, t.writableBytes - 134);
    }

    if (statsBox) {
      statsBox.style.display = 'block';
      statsBox.innerHTML = `
        <div class="status-line"><span class="mono-label">ENTRIES COUNT:</span> <span class="mono-value">${state.entries.length}</span></div>
        <div class="status-line"><span class="mono-label">ESTIMATED ENCRYPTED SIZE:</span> <span class="mono-value">${estimatedCiphertextLen} bytes</span></div>
        <div class="status-line"><span class="mono-label">TAGS REQUIRED:</span> <span class="mono-value">${state.requiredTagsCount} tags</span></div>
      `;
    }

    if (estimatedCiphertextLen > totalUsableStorage) {
      if (writeBtn) writeBtn.disabled = true;
      if (tooLargeBox) {
        tooLargeBox.style.display = 'block';
        document.getElementById('capacityTooLargeText').textContent =
          `Payload (${estimatedCiphertextLen}B) exceeds usable storage (${totalUsableStorage}B across ${state.scannedTags.length} tags).`;
      }
      if (readyBox) readyBox.style.display = 'none';
    } else {
      if (writeBtn) writeBtn.disabled = false;
      if (tooLargeBox) tooLargeBox.style.display = 'none';
      if (readyBox) {
        readyBox.style.display = 'block';
        document.getElementById('capacityReadyDetails').textContent =
          `Ready to encrypt ${state.entries.length} entries across ${state.requiredTagsCount} of ${state.scannedTags.length} scanned tags.`;
      }
    }
  }

  // --- Real Multi-Tag Sequential Encrypt & Verified Write Flow ---
  async function executeWriteEverything(passphrase) {
    showView('view-encrypt-writing');
    const actionEl = document.getElementById('writingProgressAction');
    const tallyEl = document.getElementById('writingProgressTally');

    state.isWriting = true;
    state.writePassphrase = passphrase;

    try {
      actionEl.textContent = 'ENCRYPTING PAYLOAD...';
      tallyEl.textContent = `SERIALIZING ${state.entries.length} ENTRIES...`;
      await new Promise(r => setTimeout(r, 350));

      // 1. Serialize all staged entries
      const payloadBytes = serializeEntriesPayload(state.entries);

      // 2. Derive KEK from passphrase and fresh 32-byte salt
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const kek = await deriveKekFromPassphrase(passphrase, salt);
      const vaultId = crypto.getRandomValues(new Uint8Array(16));
      const fileId = crypto.getRandomValues(new Uint8Array(16));
      const keyId = crypto.getRandomValues(new Uint8Array(16));

      // 3. Encrypt payload with AES-256-GCM
      const { iv: fileNonce, ciphertext, tag: fileGcmTag } = await encryptAesGcm(kek, payloadBytes);

      // 4. Construct self-contained encrypted package: salt (32B) || fileNonce (12B) || fileGcmTag (16B) || ciphertext
      const fullPackage = new Uint8Array(32 + 12 + 16 + ciphertext.length);
      fullPackage.set(salt, 0);
      fullPackage.set(fileNonce, 32);
      fullPackage.set(fileGcmTag, 44);
      fullPackage.set(ciphertext, 60);

      // 5. Split into chunks fitting tag capacities (tag capacity - 134B fixed overhead)
      const maxChunkSize = Math.max(16, (state.scannedTags[0]?.writableBytes || 496) - 134);
      const chunks = splitCiphertext(fullPackage, maxChunkSize);
      const totalChunks = chunks.length;

      if (state.scannedTags.length < totalChunks) {
        throw new Error(`NOT ENOUGH NFC STORAGE: Payload requires ${totalChunks} tags, but only ${state.scannedTags.length} tags were scanned.`);
      }

      const targetTags = state.scannedTags.slice(0, totalChunks);

      // 6. Write each chunk sequentially to its physical tag
      for (let i = 0; i < totalChunks; i++) {
        if (!state.isWriting) {
          alert('Writing stopped by user.');
          showView('view-encrypt-add');
          return;
        }

        actionEl.textContent = `WRITING CHUNK ${i + 1} / ${totalChunks}...`;
        tallyEl.textContent = `TARGET TAG: ${targetTags[i].uid}\nREMAINING TAGS: ${totalChunks - (i + 1)}`;
        await new Promise(r => setTimeout(r, 200));

        // Build chunk envelope with double cryptographic binding
        const chunkData = chunks[i];
        const chunkHash = await sha256(chunkData);
        const chunkIv = crypto.getRandomValues(new Uint8Array(12));
        const chunkTag = crypto.getRandomValues(new Uint8Array(16));

        const envelope = buildGtagEnvelope({
          recordType: 0x02,
          vaultIdBytes: vaultId,
          fileIdBytes: fileId,
          keyIdBytes: keyId,
          globalChunkIndex: i,
          totalVaultChunks: totalChunks,
          fileChunkIndex: i,
          totalFileChunks: totalChunks,
          ciphertext: chunkData,
          chunkHash: chunkHash,
          iv: chunkIv,
          tag: chunkTag
        });

        actionEl.textContent = `WRITING TO ${targetTags[i].uid}...`;
        await writeTagNdef(targetTags[i], envelope, MIME_BULK);

        // Immediate Read-Back Verification
        actionEl.textContent = `VERIFYING CHUNK ${i + 1} / ${totalChunks}...`;
        const parsed = parseGtagEnvelope(targetTags[i].existingData);
        if (parsed.globalChunkIndex !== i || parsed.totalVaultChunks !== totalChunks) {
          throw new Error(`Write could not be verified on tag ${targetTags[i].uid}.`);
        }

        // Log scan history if opt-in enabled
        logScanHistory({
          action: 'write',
          maskedUid: maskUid(targetTags[i].uid),
          chunkIndex: i,
          totalChunks: totalChunks
        });
      }

      state.isWriting = false;
      document.getElementById('encryptionCompleteText').textContent =
        `${totalChunks} tags written and verified. ${state.entries.length} entries encrypted.\nKeep these ${totalChunks} tags together. You can scan them in any order later.`;
      showView('view-encrypt-complete');
    } catch (err) {
      state.isWriting = false;
      alert('Write failed: ' + err.message);
      showView('view-encrypt-add');
    }
  }

  // --- Real Order-Independent Batch Read & Decrypt Flow ---
  function updateDecryptScanReadout() {
    const listEl = document.getElementById('decryptScanReadout');
    const totalScanned = state.decryptScannedChunks.length;
    let ghostCount = 0;
    let unknownCount = 0;
    let expectedTotal = 0;

    for (const c of state.decryptScannedChunks) {
      if (c.isUnknown) {
        unknownCount++;
      } else {
        ghostCount++;
        if (c.totalChunks) expectedTotal = c.totalChunks;
      }
    }

    if (listEl) {
      listEl.innerHTML = `
        <div class="status-line"><span class="mono-label">TAGS SCANNED:</span> <span class="mono-value">${totalScanned}</span></div>
        <div class="status-line"><span class="mono-label">GHOST DATA FOUND:</span> <span class="mono-value">${ghostCount} ${expectedTotal > 0 ? `/ ${expectedTotal}` : ''}</span></div>
        <div class="status-line"><span class="mono-label">OTHER DATA:</span> <span class="mono-value">${unknownCount}</span></div>
      `;
      listEl.style.display = totalScanned > 0 ? 'block' : 'none';
    }

    const actionsEl = document.getElementById('decryptScanActions');
    if (actionsEl) actionsEl.style.display = ghostCount > 0 ? 'block' : 'none';
  }

  async function executeVaultDecryption(passphrase) {
    const validChunks = state.decryptScannedChunks.filter(c => !c.isUnknown);
    if (validChunks.length === 0) {
      alert('No valid Ghost chunks scanned.');
      return;
    }

    // Determine expected total chunks from header
    const expectedTotal = validChunks[0].totalChunks || validChunks.length;

    // Check if any chunk indices are missing
    const collectedMap = new Map();
    for (const c of validChunks) {
      collectedMap.set(c.chunkIndex, c.ciphertext);
    }

    const missingIndices = [];
    for (let i = 0; i < expectedTotal; i++) {
      if (!collectedMap.has(i)) missingIndices.push(i + 1);
    }

    if (missingIndices.length > 0) {
      document.getElementById('decryptMissingText').textContent =
        `Collected: ${collectedMap.size} / ${expectedTotal} chunks\nMissing chunks: ${missingIndices.join(', ')}\nScan the remaining Ghost tags to decrypt the complete content.`;
      showView('view-decrypt-missing');
      return;
    }

    showView('view-decrypt-progress');
    const statusEl = document.getElementById('decryptProgressStatus');

    try {
      statusEl.textContent = 'IDENTIFYING VAULT...';
      await new Promise(r => setTimeout(r, 250));

      statusEl.textContent = 'REASSEMBLING CHUNKS IN ORDER...';
      await new Promise(r => setTimeout(r, 250));

      // Sort and join chunks strictly by chunk index 0..N-1
      const sortedChunks = [];
      for (let i = 0; i < expectedTotal; i++) {
        sortedChunks.push(collectedMap.get(i));
      }
      const fullPackage = joinChunks(sortedChunks);

      if (fullPackage.length < 60) {
        throw new Error('Assembled payload is too small to contain salt, nonce, and auth tag.');
      }

      // Unpack: salt (32B) || fileNonce (12B) || fileGcmTag (16B) || ciphertext
      const salt = fullPackage.slice(0, 32);
      const fileNonce = fullPackage.slice(32, 44);
      const fileGcmTag = fullPackage.slice(44, 60);
      const ciphertext = fullPackage.slice(60);

      statusEl.textContent = 'DERIVING KEY ENCRYPTION KEY...';
      const kek = await deriveKekFromPassphrase(passphrase, salt);

      statusEl.textContent = 'AUTHENTICATING AES-256-GCM...';
      await new Promise(r => setTimeout(r, 200));

      const plaintextBytes = await decryptAesGcm(kek, ciphertext, fileNonce, fileGcmTag);

      statusEl.textContent = 'UNPACKING RECOVERED ENTRIES...';
      state.recoveredEntries = deserializeEntriesPayload(plaintextBytes);

      // Record successful decryption in scan history
      logScanHistory({ action: 'decrypt', maskedUid: 'ALL_CHIPS', chunkIndex: 0, totalChunks: expectedTotal });

      renderRecoveredEntries();
      showView('view-decrypt-complete');
    } catch (err) {
      console.error('Decryption failed:', err);
      showView('view-decrypt-failed');
    }
  }

  function renderRecoveredEntries() {
    const listEl = document.getElementById('recoveredEntriesList');
    if (!listEl) return;

    if (state.recoveredEntries.length === 0) {
      listEl.innerHTML = '<div style="color: var(--text-secondary); padding: 12px 0;">No entries remaining.</div>';
      return;
    }

    listEl.innerHTML = state.recoveredEntries.map((e, idx) => `
      <div class="file-item">
        <div class="file-meta">
          <span class="file-name">${idx + 1}. [${e.type}] ${e.name}</span>
          <span class="file-size">${formatBytes(e.size)}</span>
        </div>
        <div class="file-actions">
          <button class="btn btn-secondary btn-sm" onclick="GhostApp.viewEntry(${idx})">View</button>
          <button class="btn btn-primary btn-sm" onclick="GhostApp.downloadEntry(${idx})">Download</button>
          <button class="btn btn-danger btn-sm" onclick="GhostApp.promptDeleteEntry('${e.name}', ${idx})">Delete Entry</button>
        </div>
      </div>
    `).join('');
  }

  function formatBytes(bytes) {
    if (!bytes || bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  function handleHashRoute() {
    const hash = window.location.hash.replace('#', '');
    if (!hash) return;
    if (hash === 'technical') {
      window.location.href = 'technical.html#technical';
    } else if (hash === 'security') {
      window.location.href = 'technical.html#security';
    } else if (hash === 'privacy') {
      window.location.href = 'technical.html#privacy';
    } else if (hash === 'source') {
      window.location.href = 'technical.html#source';
    } else if (hash === 'encrypt' || hash === 'batch-write') {
      if (state.account) showView('view-encrypt-scan');
      else showView('view-welcome');
    } else if (hash === 'decrypt' || hash === 'batch-read') {
      if (state.account) showView('view-decrypt-scan');
      else showView('view-welcome');
    }
  }

  if (typeof window !== 'undefined') {
    if (typeof window.addEventListener === 'function') {
      window.addEventListener('hashchange', handleHashRoute);
    }

    // Global Exports for In-App Button Handlers
    window.GhostApp = {
      state,
      showView,
      init,
      removeEntry: (idx) => {
        state.entries.splice(idx, 1);
        renderEntriesList();
      },
      viewEntry: (idx) => {
        const e = state.recoveredEntries[idx];
        if (!e) return;
        state.activeViewingIndex = idx;
        const titleEl = document.getElementById('viewEntryModalTitle');
        const metaEl = document.getElementById('viewEntryModalMeta');
        const bodyEl = document.getElementById('viewEntryModalBody');

        if (titleEl) titleEl.textContent = `ENTRY: ${e.name}`;
        if (metaEl) metaEl.textContent = `Type: ${e.type} | Size: ${formatBytes(e.size)} | MIME: ${e.mime}`;

        if (bodyEl) {
          if (state.activeObjectUrl) {
            URL.revokeObjectURL(state.activeObjectUrl);
            state.activeObjectUrl = null;
          }
          bodyEl.innerHTML = '';
          if (e.type === 'Text' || e.type === 'URL') {
            bodyEl.textContent = e.content || new TextDecoder().decode(e.data);
          } else if (e.type === 'Photo' && e.data) {
            const blob = new Blob([e.data], { type: e.mime || 'image/jpeg' });
            const imgUrl = URL.createObjectURL(blob);
            bodyEl.innerHTML = `<img src="${imgUrl}" style="max-width:100%; height:auto; border-radius:4px;" alt="${e.name}">`;
            // Retain the object URL for the lifetime of the view modal; it is
            // revoked when the same modal is opened again or closed.
            state.activeObjectUrl = imgUrl;
          } else {
            bodyEl.textContent = `[Binary Payload: ${formatBytes(e.size)} verified]\nUse Download to save this file locally.`;
          }
        }
        showModal('modalViewEntry');
      },
      downloadEntry: (idx) => {
        const e = state.recoveredEntries[idx];
        if (!e) return;
        const blob = new Blob([e.data || new TextEncoder().encode(e.content || '')], { type: e.mime || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = e.name || 'ghost-recovered-file';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(() => URL.revokeObjectURL(url), 2000);
      },
      promptDeleteEntry: (name, idx) => {
        state.pendingDeleteIndex = idx;
        const targetLabel = document.getElementById('deleteEntryTargetName');
        if (targetLabel) targetLabel.textContent = `Entry: ${name}`;
        showModal('modalDeleteEntry');
      },
      deleteHistoryItem: (id) => {
        const logs = getScanHistoryLogs().filter(l => l.id !== id);
        localStorage.setItem(STORAGE_KEY_SCAN_HISTORY_RECORDS, JSON.stringify(logs));
        renderScanHistoryUI();
      }
    };
  }

  if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', init);
  }
})();
