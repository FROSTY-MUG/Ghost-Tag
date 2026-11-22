const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { argon2id } = require('hash-wasm');

// 1. BIP-39 test phrases
const phrase1Words = [
  'abandon', 'ability', 'able', 'about', 'above', 'absent',
  'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident'
];
const phrase2Words = [
  'legal', 'winner', 'thank', 'year', 'wave', 'sausage',
  'worth', 'useful', 'legal', 'winner', 'thank', 'yellow'
];

function deriveAccountId(words) {
  const cleanPhrase = words.map(w => w.trim().toLowerCase()).join(' ');
  const input = Buffer.from(`ghost-account-id-v2.0.5:${cleanPhrase}`, 'utf8');
  const hash = crypto.createHash('sha256').update(input).digest();
  const bytes = Buffer.from(hash.subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1
  const hex = bytes.toString('hex');
  return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-${hex.substr(12, 4)}-${hex.substr(16, 4)}-${hex.substr(20, 12)}`;
}

function deriveRecoveryAuthSecret(words) {
  const cleanPhrase = words.map(w => w.trim().toLowerCase()).join(' ');
  const input = Buffer.from(`ghost-recovery-auth-v2.0.5:${cleanPhrase}`, 'utf8');
  return crypto.createHash('sha256').update(input).digest().toString('hex');
}

function deriveRecoverySalt(words) {
  const cleanPhrase = words.map(w => w.trim().toLowerCase()).join(' ');
  const input = Buffer.from(`ghost-recovery-salt-v2.0.5:${cleanPhrase}`, 'utf8');
  return crypto.createHash('sha256').update(input).digest();
}

async function generateFixtures() {
  const salt1 = deriveRecoverySalt(phrase1Words);
  const salt2 = deriveRecoverySalt(phrase2Words);

  const verifier1 = await argon2id({
    password: deriveRecoveryAuthSecret(phrase1Words),
    salt: salt1,
    iterations: 3,
    memorySize: 32768,
    parallelism: 2,
    hashLength: 32,
    outputType: 'hex',
  });

  const verifier2 = await argon2id({
    password: deriveRecoveryAuthSecret(phrase2Words),
    salt: salt2,
    iterations: 3,
    memorySize: 32768,
    parallelism: 2,
    hashLength: 32,
    outputType: 'hex',
  });

  // Recovery vectors
  const recoveryVectors = {
    description: "Cross-platform recovery test vectors for Ghost-Tag",
    version: "2.1.0",
    algorithm_account_id: "SHA-256(ghost-account-id-v2.0.5:<phrase>) formatted as RFC 4122 v4 UUID",
    algorithm_auth_secret: "SHA-256(ghost-recovery-auth-v2.0.5:<phrase>)",
    algorithm_salt: "SHA-256(ghost-recovery-salt-v2.0.5:<phrase>)",
    algorithm_verifier: "Argon2id(secretHex, salt, m=32768, t=3, p=2, len=32)",
    kdf_parameters: {
      algorithm: "Argon2id",
      version: "0x13",
      memoryCostKiB: 32768,
      timeCostPasses: 3,
      parallelism: 2,
      outputLengthBytes: 32,
      saltLengthBytes: 32
    },
    vectors: [
      {
        id: "vector-1",
        words: phrase1Words,
        phrase: phrase1Words.join(' '),
        account_id: deriveAccountId(phrase1Words),
        recovery_auth_secret_hex: deriveRecoveryAuthSecret(phrase1Words),
        recovery_salt_hex: salt1.toString('hex'),
        recovery_verifier_hex: verifier1
      },
      {
        id: "vector-2",
        words: phrase2Words,
        phrase: phrase2Words.join(' '),
        account_id: deriveAccountId(phrase2Words),
        recovery_auth_secret_hex: deriveRecoveryAuthSecret(phrase2Words),
        recovery_salt_hex: salt2.toString('hex'),
        recovery_verifier_hex: verifier2
      }
    ]
  };

  // 2. AES-256-GCM vectors
  const key1 = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
  const nonce1 = Buffer.from('a0a1a2a3a4a5a6a7a8a9aaab', 'hex'); // 12B
  const plaintext1 = Buffer.from('Ghost-Tag cross-platform cryptographic test vector payload 2026', 'utf8');
  const aad1 = Buffer.from('GTAG-AAD-METADATA-BINDING-PROOF', 'utf8');

  const cipher = crypto.createCipheriv('aes-256-gcm', key1, nonce1);
  cipher.setAAD(aad1);
  const ct1 = Buffer.concat([cipher.update(plaintext1), cipher.final()]);
  const tag1 = cipher.getAuthTag();

  const aesGcmVectors = {
    description: "NIST SP 800-38D AES-256-GCM deterministic test vectors",
    cipher: "aes-256-gcm",
    vectors: [
      {
        id: "aes-gcm-vec-1",
        key_hex: key1.toString('hex'),
        nonce_hex: nonce1.toString('hex'),
        plaintext_ascii: plaintext1.toString('utf8'),
        plaintext_hex: plaintext1.toString('hex'),
        aad_ascii: aad1.toString('utf8'),
        aad_hex: aad1.toString('hex'),
        ciphertext_hex: ct1.toString('hex'),
        tag_hex: tag1.toString('hex')
      }
    ]
  };

  // 3. Ghost v1 envelope
  // Overhead: 54 bytes
  // Magic: "GTAG" (4B) = 47 54 41 47
  // Version: 0x01 (1B)
  // Purpose: 0x01 (1B)
  // KeyId: 16B
  // Nonce: 12B
  // Ciphertext Length: 4B LE
  // Ciphertext: N bytes
  // Tag: 16B
  // AAD: 26 bytes (MAGIC || VERSION || PURPOSE || KEY_ID || CIPHERTEXT_LENGTH)
  const v1KeyId = Buffer.from('0102030405060708090a0b0c0d0e0f10', 'hex');
  const v1Nonce = Buffer.from('505152535455565758595a5b', 'hex');
  const v1Plaintext = Buffer.from('Confidential ghost payload v1', 'utf8');
  const v1Key = key1;

  // Build canonical 26-byte AAD
  const v1AAD = Buffer.alloc(26);
  v1AAD.write('GTAG', 0, 4, 'ascii');
  v1AAD.writeUInt8(0x01, 4); // format version
  v1AAD.writeUInt8(0x01, 5); // purpose: SECURE_VAULT_PAYLOAD
  v1KeyId.copy(v1AAD, 6, 0, 16);
  v1AAD.writeUInt32LE(v1Plaintext.length, 22);

  const v1Header = Buffer.alloc(38);
  v1Header.write('GTAG', 0, 4, 'ascii');
  v1Header.writeUInt8(0x01, 4); // format version
  v1Header.writeUInt8(0x01, 5); // purpose: SECURE_VAULT_PAYLOAD
  v1KeyId.copy(v1Header, 6, 0, 16);
  v1Nonce.copy(v1Header, 22, 0, 12);
  v1Header.writeUInt32LE(v1Plaintext.length, 34);

  const v1Cipher = crypto.createCipheriv('aes-256-gcm', v1Key, v1Nonce);
  v1Cipher.setAAD(v1AAD);
  const v1Ciphertext = Buffer.concat([v1Cipher.update(v1Plaintext), v1Cipher.final()]);
  const v1Tag = v1Cipher.getAuthTag();

  const v1EnvelopeBuffer = Buffer.concat([v1Header, v1Ciphertext, v1Tag]);

  const v1EnvelopeVectors = {
    description: "Ghost-Tag Single-Tag v1 Envelope Specification",
    overhead_bytes: 54,
    mime: "application/vnd.ghost.secure",
    header_bytes: 38,
    aad_bytes: 26,
    fields: {
      magic: "GTAG (0x47, 0x54, 0x41, 0x47)",
      format_version: 1,
      purpose: 1,
      key_id_length: 16,
      nonce_length: 12,
      tag_length: 16
    },
    vector: {
      key_id_hex: v1KeyId.toString('hex'),
      nonce_hex: v1Nonce.toString('hex'),
      plaintext_utf8: v1Plaintext.toString('utf8'),
      ciphertext_length: v1Ciphertext.length,
      ciphertext_hex: v1Ciphertext.toString('hex'),
      tag_hex: v1Tag.toString('hex'),
      aad_hex: v1AAD.toString('hex'),
      serialized_envelope_hex: v1EnvelopeBuffer.toString('hex'),
      total_envelope_bytes: v1EnvelopeBuffer.length
    }
  };

  // 4. Ghost v2 bulk envelope
  // Overhead: 134 bytes
  // Magic: "GTAG" (4B)
  // Version: 0x02 (1B)
  // Record Type: 0x10 (1B)
  // Vault ID: 16B
  // File ID: 16B
  // Key ID: 16B
  // Global Chunk Index: 4B LE
  // Total Vault Chunks: 4B LE
  // File Chunk Index: 4B LE
  // Total File Chunks: 4B LE
  // Chunk Ciphertext Length: 4B LE
  // Chunk SHA-256 Hash: 32B
  // Nonce: 12B
  // Ciphertext: N bytes
  // Tag: 16B
  // AAD: Bytes 0..73 (74B)
  const v2VaultId = Buffer.from('11111111222222223333333344444444', 'hex');
  const v2FileId = Buffer.from('55555555666666667777777788888888', 'hex');
  const v2KeyId = Buffer.from('99999999aaaaaaaa00000000bbbbbbbb', 'hex');
  const v2Nonce = Buffer.from('c0c1c2c3c4c5c6c7c8c9cacb', 'hex');
  const v2Plaintext = Buffer.from('Bulk file chunk slice payload 001 for multi-tag recovery verification', 'utf8');
  const v2Key = key1;

  const v2GlobalIdx = 0;
  const v2TotalVault = 3;
  const v2FileIdx = 0;
  const v2TotalFile = 3;

  // AAD is bytes 0..73
  const v2AAD = Buffer.alloc(74);
  v2AAD.write('GTAG', 0, 4, 'ascii');
  v2AAD.writeUInt8(0x02, 4); // FORMAT_VERSION = 2
  v2AAD.writeUInt8(0x10, 5); // RECORD_TYPE_BULK_CHUNK = 0x10
  v2VaultId.copy(v2AAD, 6, 0, 16);
  v2FileId.copy(v2AAD, 22, 0, 16);
  v2KeyId.copy(v2AAD, 38, 0, 16);
  v2AAD.writeUInt32LE(v2GlobalIdx, 54);
  v2AAD.writeUInt32LE(v2TotalVault, 58);
  v2AAD.writeUInt32LE(v2FileIdx, 62);
  v2AAD.writeUInt32LE(v2TotalFile, 66);
  v2AAD.writeUInt32LE(v2Plaintext.length, 70);

  // Encrypt plaintext
  const v2Cipher = crypto.createCipheriv('aes-256-gcm', v2Key, v2Nonce);
  v2Cipher.setAAD(v2AAD);
  const v2Ciphertext = Buffer.concat([v2Cipher.update(v2Plaintext), v2Cipher.final()]);
  const v2Tag = v2Cipher.getAuthTag();

  // Chunk hash = SHA256(chunkCiphertext)
  const v2ChunkHash = crypto.createHash('sha256').update(v2Ciphertext).digest();

  // Assemble complete 134 + N binary envelope
  const v2EnvelopeBuffer = Buffer.concat([
    v2AAD,
    v2ChunkHash, // 32B (bytes 74..105)
    v2Nonce,     // 12B (bytes 106..117)
    v2Ciphertext,// N bytes (bytes 118..118+N-1)
    v2Tag        // 16B (bytes 118+N..133+N)
  ]);

  const v2BulkEnvelopeVectors = {
    description: "Ghost-Tag Bulk Chunk v2 Envelope Specification",
    overhead_bytes: 134,
    mime: "application/vnd.ghost.bulk",
    aad_bytes: 74,
    fields: {
      magic: "GTAG (0x47, 0x54, 0x41, 0x47)",
      format_version: 2,
      record_type: 16, // 0x10
      vault_id_length: 16,
      file_id_length: 16,
      key_id_length: 16,
      chunk_hash_length: 32,
      nonce_length: 12,
      tag_length: 16
    },
    vector: {
      vault_id_hex: v2VaultId.toString('hex'),
      file_id_hex: v2FileId.toString('hex'),
      key_id_hex: v2KeyId.toString('hex'),
      global_chunk_index: v2GlobalIdx,
      total_vault_chunks: v2TotalVault,
      file_chunk_index: v2FileIdx,
      total_file_chunks: v2TotalFile,
      plaintext_utf8: v2Plaintext.toString('utf8'),
      ciphertext_length: v2Ciphertext.length,
      ciphertext_hex: v2Ciphertext.toString('hex'),
      chunk_hash_hex: v2ChunkHash.toString('hex'),
      nonce_hex: v2Nonce.toString('hex'),
      tag_hex: v2Tag.toString('hex'),
      aad_hex: v2AAD.toString('hex'),
      serialized_envelope_hex: v2EnvelopeBuffer.toString('hex'),
      total_envelope_bytes: v2EnvelopeBuffer.length
    }
  };

  // Ensure directories exist
  fs.mkdirSync(path.join(__dirname, '../test-fixtures/crypto'), { recursive: true });
  fs.mkdirSync(path.join(__dirname, '../test-fixtures/recovery'), { recursive: true });
  fs.mkdirSync(path.join(__dirname, '../test-fixtures/envelopes'), { recursive: true });

  // Write JSON fixtures
  fs.writeFileSync(path.join(__dirname, '../test-fixtures/crypto/aesGcmVectors.json'), JSON.stringify(aesGcmVectors, null, 2));
  fs.writeFileSync(path.join(__dirname, '../test-fixtures/recovery/recoveryVectors.json'), JSON.stringify(recoveryVectors, null, 2));
  fs.writeFileSync(path.join(__dirname, '../test-fixtures/envelopes/v1EnvelopeVectors.json'), JSON.stringify(v1EnvelopeVectors, null, 2));
  fs.writeFileSync(path.join(__dirname, '../test-fixtures/envelopes/v2BulkEnvelopeVectors.json'), JSON.stringify(v2BulkEnvelopeVectors, null, 2));

  // Write binary fixtures (.bin)
  fs.writeFileSync(path.join(__dirname, '../test-fixtures/envelopes/v1-reference.bin'), v1EnvelopeBuffer);
  fs.writeFileSync(path.join(__dirname, '../test-fixtures/envelopes/v2-bulk-reference.bin'), v2EnvelopeBuffer);

  console.log("Test fixtures successfully generated!");
  console.log("Vector 1 Account ID:", recoveryVectors.vectors[0].account_id);
  console.log("Vector 1 Auth Secret:", recoveryVectors.vectors[0].recovery_auth_secret_hex);
  console.log("Vector 1 Recovery Verifier:", recoveryVectors.vectors[0].recovery_verifier_hex);
  console.log("V1 Envelope Size:", v1EnvelopeBuffer.length);
  console.log("V2 Bulk Envelope Size:", v2EnvelopeBuffer.length);
}

generateFixtures().catch(err => {
  console.error("Fixture generation failed:", err);
  process.exit(1);
});
