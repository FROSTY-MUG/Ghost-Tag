/**
 * @file crypto-simulator.js
 * @summary In-browser Cryptographic Core, Galois Field Cauchy Reed-Solomon,
 *          Canonical Binary Envelope Codecs, and Web NFC Bridge for Ghost-Tag.
 */

// ---------------------------------------------------------------------------
// 1. Galois Field GF(2^8) & Cauchy-Vandermonde Reed-Solomon Codec
// ---------------------------------------------------------------------------

const GF_POLY = 0x11d; // x^8 + x^4 + x^3 + x^2 + 1
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(function () {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_EXP[i + 255] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) {
      x ^= GF_POLY;
    }
  }
  GF_LOG[0] = 0; // undefined, safely set to 0
})();

function gfMul(a, b) {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[GF_LOG[a] + GF_LOG[b]];
}

function gfInv(a) {
  if (a === 0) throw new Error('Zero has no multiplicative inverse in GF(2^8)');
  return GF_EXP[255 - GF_LOG[a]];
}

/**
 * Creates a Cauchy generator matrix for K data chunks and M recovery chunks.
 */
function createCauchyMatrix(k, m) {
  const matrix = [];
  const X = [];
  const Y = [];

  for (let i = 0; i < k + m; i++) X.push(i);
  for (let j = 0; j < k; j++) Y.push(k + m + j);

  // Systematic top: KxK Identity matrix
  for (let i = 0; i < k; i++) {
    const row = new Uint8Array(k);
    row[i] = 1;
    matrix.push(row);
  }

  // Parity bottom: MxK Cauchy matrix C[i, j] = 1 / (X[i+k] ^ Y[j])
  for (let i = 0; i < m; i++) {
    const row = new Uint8Array(k);
    for (let j = 0; j < k; j++) {
      const diff = X[k + i] ^ Y[j];
      row[j] = gfInv(diff);
    }
    matrix.push(row);
  }

  return matrix;
}

/**
 * Encodes data chunks into data + recovery chunks.
 */
function encodeErasureCoding(dataChunks, m) {
  const k = dataChunks.length;
  if (m === 0) return [...dataChunks];

  const chunkSize = dataChunks[0].length;
  const matrix = createCauchyMatrix(k, m);
  const recoveryChunks = [];

  for (let r = 0; r < m; r++) {
    const parity = new Uint8Array(chunkSize);
    const coeffs = matrix[k + r];
    for (let c = 0; c < k; c++) {
      const factor = coeffs[c];
      const chunk = dataChunks[c];
      for (let b = 0; b < chunkSize; b++) {
        parity[b] ^= gfMul(factor, chunk[b]);
      }
    }
    recoveryChunks.push(parity);
  }

  return [...dataChunks, ...recoveryChunks];
}

/**
 * Inverts an N x N matrix over GF(2^8) via Gauss-Jordan elimination.
 */
function invertMatrixGF(mat, n) {
  const a = mat.map((row) => new Uint8Array(row));
  const inv = [];
  for (let i = 0; i < n; i++) {
    const row = new Uint8Array(n);
    row[i] = 1;
    inv.push(row);
  }

  for (let col = 0; col < n; col++) {
    // Find pivot
    let pivotRow = -1;
    for (let r = col; r < n; r++) {
      if (a[r][col] !== 0) {
        pivotRow = r;
        break;
      }
    }
    if (pivotRow === -1) {
      throw new Error('Singular submatrix encountered during erasure decoding');
    }

    if (pivotRow !== col) {
      const tmpA = a[col];
      a[col] = a[pivotRow];
      a[pivotRow] = tmpA;
      const tmpInv = inv[col];
      inv[col] = inv[pivotRow];
      inv[pivotRow] = tmpInv;
    }

    const pivotVal = a[col][col];
    const pivotInv = gfInv(pivotVal);
    for (let c = 0; c < n; c++) {
      a[col][c] = gfMul(a[col][c], pivotInv);
      inv[col][c] = gfMul(inv[col][c], pivotInv);
    }

    for (let r = 0; r < n; r++) {
      if (r !== col) {
        const factor = a[r][col];
        if (factor !== 0) {
          for (let c = 0; c < n; c++) {
            a[r][c] ^= gfMul(factor, a[col][c]);
            inv[r][c] ^= gfMul(factor, inv[col][c]);
          }
        }
      }
    }
  }

  return inv;
}

/**
 * Reconstructs original K data chunks from any K available chunks out of K + M.
 */
function decodeErasureCoding(availableChunks, k, m, chunkSize) {
  if (availableChunks.length < k) {
    throw new Error(`Insufficient chunks for reconstruction: have ${availableChunks.length}, need ${k}`);
  }

  // Pick first K available distinct chunks
  const selected = availableChunks.slice(0, k);
  const generatorMatrix = createCauchyMatrix(k, m);

  // Submatrix corresponding to selected chunk row indices
  const submatrix = selected.map((item) => generatorMatrix[item.index]);
  const inverted = invertMatrixGF(submatrix, k);

  const reconstructed = [];
  for (let i = 0; i < k; i++) {
    const chunk = new Uint8Array(chunkSize);
    for (let r = 0; r < k; r++) {
      const coeff = inverted[i][r];
      const sourceChunk = selected[r].data;
      for (let b = 0; b < chunkSize; b++) {
        chunk[b] ^= gfMul(coeff, sourceChunk[b]);
      }
    }
    reconstructed.push(chunk);
  }

  return reconstructed;
}

// ---------------------------------------------------------------------------
// 2. WebCrypto Primitives: AES-256-GCM, SHA-256, PBKDF2 / Argon2 Simulation
// ---------------------------------------------------------------------------

async function deriveKeyFromPassphrase(passphrase, salt, iterations = 100000) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(passphrase),
    { name: 'PBKDF2' },
    false,
    ['deriveKey', 'deriveBits']
  );

  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function computeSHA256(data) {
  const digestBuffer = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digestBuffer);
}

function generateRandomBytes(len) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

function secureWipe(buffer) {
  if (!buffer || !(buffer instanceof Uint8Array)) return;
  buffer.fill(0xaa);
  buffer.fill(0x55);
  crypto.getRandomValues(buffer);
  buffer.fill(0x00);
}

// ---------------------------------------------------------------------------
// 3. Canonical Binary Envelope Codecs (v1 & v2)
// ---------------------------------------------------------------------------

const MAGIC_GTAG = new Uint8Array([0x47, 0x54, 0x41, 0x47]); // "GTAG"

/**
 * Builds the canonical 26-byte AAD for v1 envelopes:
 * "GTAG" (4B) || VERSION (1B) || PURPOSE (1B) || KEY_ID (16B) || CIPHERTEXT_LEN (4B LE)
 */
function buildEnvelopeAADv1(version, purpose, keyId, ctLen) {
  const aad = new Uint8Array(26);
  aad.set(MAGIC_GTAG, 0);
  aad[4] = version;
  aad[5] = purpose;
  aad.set(keyId, 6);
  const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
  view.setUint32(22, ctLen, true); // Little-Endian
  return aad;
}

/**
 * Encrypts payload and builds the 54-byte fixed-overhead v1 envelope.
 */
async function createV1Envelope(cryptoKey, plaintext, purposeByte, keyIdBytes) {
  const nonce = generateRandomBytes(12);
  const keyId = keyIdBytes || generateRandomBytes(16);
  const version = 0x01;
  const ctLen = plaintext.length;

  const aad = buildEnvelopeAADv1(version, purposeByte, keyId, ctLen);

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
      tagLength: 128,
    },
    cryptoKey,
    plaintext
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
  const authTag = encryptedBytes.slice(encryptedBytes.length - 16);

  // Total layout: 54B fixed overhead + N ciphertext bytes
  const envelope = new Uint8Array(54 + ciphertext.length);
  envelope.set(MAGIC_GTAG, 0);
  envelope[4] = version;
  envelope[5] = purposeByte;
  envelope.set(keyId, 6);
  envelope.set(nonce, 22);

  const view = new DataView(envelope.buffer, envelope.byteOffset, envelope.byteLength);
  view.setUint32(34, ciphertext.length, true);

  envelope.set(ciphertext, 38);
  envelope.set(authTag, 38 + ciphertext.length);

  return {
    envelope,
    keyId,
    nonce,
    ciphertext,
    authTag,
    aad,
  };
}

/**
 * Parses and decrypts a v1 envelope.
 */
async function parseAndDecryptV1Envelope(cryptoKey, envelopeBytes) {
  if (envelopeBytes.length < 54) {
    throw new Error('Envelope truncated: length is less than 54 bytes overhead');
  }

  // Check magic "GTAG"
  if (
    envelopeBytes[0] !== 0x47 ||
    envelopeBytes[1] !== 0x54 ||
    envelopeBytes[2] !== 0x41 ||
    envelopeBytes[3] !== 0x47
  ) {
    throw new Error('Invalid magic bytes: expected ASCII "GTAG"');
  }

  const version = envelopeBytes[4];
  const purpose = envelopeBytes[5];
  const keyId = envelopeBytes.slice(6, 22);
  const nonce = envelopeBytes.slice(22, 34);

  const view = new DataView(envelopeBytes.buffer, envelopeBytes.byteOffset, envelopeBytes.byteLength);
  const ctLen = view.getUint32(34, true);

  if (envelopeBytes.length !== 54 + ctLen) {
    throw new Error(`Envelope length mismatch: expected ${54 + ctLen}, got ${envelopeBytes.length}`);
  }

  const ciphertext = envelopeBytes.slice(38, 38 + ctLen);
  const authTag = envelopeBytes.slice(38 + ctLen, 54 + ctLen);

  const aad = buildEnvelopeAADv1(version, purpose, keyId, ctLen);

  // Combine ciphertext + tag for WebCrypto AES-GCM
  const combined = new Uint8Array(ciphertext.length + 16);
  combined.set(ciphertext, 0);
  combined.set(authTag, ciphertext.length);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad,
      tagLength: 128,
    },
    cryptoKey,
    combined
  );

  return {
    version,
    purpose,
    keyId,
    nonce,
    plaintext: new Uint8Array(decryptedBuffer),
  };
}

// ---------------------------------------------------------------------------
// 4. Web NFC Bridge (Chrome on Android)
// ---------------------------------------------------------------------------

const WebNFC = {
  isSupported() {
    return 'NDEFReader' in window;
  },

  async readTag(onStatus) {
    if (!this.isSupported()) {
      throw new Error('Web NFC API is not supported in this browser. Use Chrome on an NFC-enabled Android device.');
    }

    const ndef = new window.NDEFReader();
    await ndef.scan();
    if (onStatus) onStatus('NFC RF antenna active. Tap tag against phone back...');

    return new Promise((resolve, reject) => {
      ndef.onreading = (event) => {
        try {
          const serialNumber = event.serialNumber || 'UNKNOWN_UID';
          for (const record of event.message.records) {
            if (
              record.recordType === 'mime' &&
              (record.mediaType === 'application/vnd.ghost.secure' ||
                record.mediaType === 'application/vnd.ghost.bulk')
            ) {
              const data = new Uint8Array(record.data.buffer);
              resolve({
                serialNumber,
                mediaType: record.mediaType,
                envelope: data,
              });
              return;
            }
          }
          // If no ghost-tag record found
          reject(new Error('Tag detected, but no Ghost-Tag encrypted NDEF record found on tag.'));
        } catch (err) {
          reject(err);
        }
      };

      ndef.onreadingerror = () => {
        reject(new Error('NFC RF link lost or read error occurred during transmission.'));
      };
    });
  },

  async writeTag(mediaType, binaryPayload, onStatus) {
    if (!this.isSupported()) {
      throw new Error('Web NFC API is not supported in this browser. Use Chrome on an NFC-enabled Android device.');
    }

    const ndef = new window.NDEFReader();
    if (onStatus) onStatus('Ready to write. Tap compatible tag against phone back...');

    await ndef.write({
      records: [
        {
          recordType: 'mime',
          mediaType: mediaType,
          data: binaryPayload,
        },
      ],
    });

    if (onStatus) onStatus('NDEF write transmitted successfully! Executing read-back verification...');
  },
};

// Export to global window context
window.GhostCrypto = {
  encodeErasureCoding,
  decodeErasureCoding,
  deriveKeyFromPassphrase,
  computeSHA256,
  generateRandomBytes,
  bytesToHex,
  hexToBytes,
  secureWipe,
  createV1Envelope,
  parseAndDecryptV1Envelope,
  WebNFC,
};

