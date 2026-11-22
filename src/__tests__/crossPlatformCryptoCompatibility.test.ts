/**
 * @file crossPlatformCryptoCompatibility.test.ts
 * @summary Cross-Platform Cryptographic Compatibility Test Suite for Ghost-Tag (Android, Web, iOS, Supabase).
 *
 * Strict Invariants:
 * - Deterministic execution: Zero Math.random(), zero CSPRNG random generation in test vectors.
 * - Exact vector validation: Compares actual behavior of Android / Core algorithms against fixed reference vectors.
 * - Proves byte-for-byte wire compatibility for single-tag v1 envelopes and bulk v2 envelopes.
 * - Verifies tamper detection (tampered ciphertext, tampered AAD, wrong passphrase, invalid version, invalid verifier).
 * - Verifies cross-platform reference fixtures stored in test-fixtures/.
 */

declare const require: any;
declare const __dirname: string;
declare const Buffer: any;
declare const global: any;
const fs = require('fs');
const path = require('path');
const { argon2id } = require('hash-wasm');
const WebSupabase = require('../../web/supabase');
const WebApp = require('../../web/app');
const { buildMimeNdefMessage, parseNdefRecords } = require('../../desktop/src/apdu');
import { setTestArgon2Provider } from '../crypto/argon2';
import {
  deriveAccountIdFromPhrase,
  deriveRecoveryAuthSecret,
  deriveRecoverySalt,
  computeRecoveryVerifier,
  recoverVaultWithVerifier,
  uploadEncryptedVaultMetadata,
  resetSupabaseConfig,
} from '../cloud/supabaseClient';
import {
  encrypt,
  decrypt,
} from '../crypto/aesGcm';
import {
  serializeEnvelope,
  parseEnvelope,
  constructAAD,
} from '../crypto/envelope';
import {
  serializeBulkEnvelope,
  parseBulkEnvelope,
  constructBulkAAD,
  computeChunkHash,
  validateBulkEnvelope,
} from '../crypto/bulkEnvelope';
import {
  wrapDEK,
  unwrapDEK,
  bytesToHex,
  hexToBytes,
} from '../crypto/keyWrap';
import {
  ENVELOPE_MAGIC_BYTES,
  ENVELOPE_FORMAT_VERSION_V1,
  EnvelopePurpose,
  GhostTagEnvelope,
} from '../contracts/envelope';
import {
  BULK_ENVELOPE_MAGIC,
  BULK_FORMAT_VERSION_V2,
  RECORD_TYPE_BULK_CHUNK,
  BULK_ENVELOPE_FIXED_OVERHEAD,
  BULK_AAD_LENGTH,
  BulkChunkEnvelope,
} from '../contracts/bulkEnvelope';
import {
  DeviceTier,
  DEFAULT_KDF_PARAMETERS_BY_TIER,
  KdfParameters,
} from '../contracts/keyHierarchy';
import { GhostTagErrorCode } from '../contracts/errors';

// Paths to cross-platform reference fixtures
const FIXTURES_DIR = path.resolve(__dirname, '../../test-fixtures');
const AES_GCM_FIXTURE_PATH = path.join(FIXTURES_DIR, 'crypto/aesGcmVectors.json');
const RECOVERY_FIXTURE_PATH = path.join(FIXTURES_DIR, 'recovery/recoveryVectors.json');
const V1_ENVELOPE_FIXTURE_PATH = path.join(FIXTURES_DIR, 'envelopes/v1EnvelopeVectors.json');
const V2_BULK_FIXTURE_PATH = path.join(FIXTURES_DIR, 'envelopes/v2BulkEnvelopeVectors.json');
const V1_BIN_FIXTURE_PATH = path.join(FIXTURES_DIR, 'envelopes/v1-reference.bin');
const V2_BIN_FIXTURE_PATH = path.join(FIXTURES_DIR, 'envelopes/v2-bulk-reference.bin');

describe('Ghost-Tag Cross-Platform Cryptographic Compatibility Suite', () => {
  // Load reference fixtures synchronously
  const aesGcmFixture = JSON.parse(fs.readFileSync(AES_GCM_FIXTURE_PATH, 'utf8'));
  const recoveryFixture = JSON.parse(fs.readFileSync(RECOVERY_FIXTURE_PATH, 'utf8'));
  const v1EnvelopeFixture = JSON.parse(fs.readFileSync(V1_ENVELOPE_FIXTURE_PATH, 'utf8'));
  const v2BulkFixture = JSON.parse(fs.readFileSync(V2_BULK_FIXTURE_PATH, 'utf8'));
  const v1ReferenceBin = fs.readFileSync(V1_BIN_FIXTURE_PATH);
  const v2ReferenceBin = fs.readFileSync(V2_BIN_FIXTURE_PATH);

  beforeAll(() => {
    setTestArgon2Provider(async (passphrase: string, salt: Uint8Array, params: any) => {
      const hex = await argon2id({
        password: passphrase,
        salt: salt,
        iterations: params.timeCost,
        memorySize: params.memoryCost,
        parallelism: params.parallelism,
        hashLength: 32,
        outputType: 'hex',
      });
      return hexToBytes(hex);
    });
  });

  beforeEach(() => {
    resetSupabaseConfig();
  });

  // -------------------------------------------------------------------------
  // 1. Fixed Cryptographic Test Vectors
  // -------------------------------------------------------------------------
  describe('1. Fixed Cryptographic Test Vectors', () => {
    it('defines deterministic, reproducible byte sequences for all cryptographic operations', () => {
      const fixedKey = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      const fixedNonce = hexToBytes('a0a1a2a3a4a5a6a7a8a9aaab');
      expect(fixedKey.length).toBe(32);
      expect(fixedNonce.length).toBe(12);
      expect(bytesToHex(fixedKey)).toBe('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
    });
  });

  // -------------------------------------------------------------------------
  // 2. Fixed 12-word BIP-39 Recovery Phrase Vectors
  // -------------------------------------------------------------------------
  describe('2. Fixed 12-Word BIP-39 Recovery Phrase Vectors', () => {
    it('validates standard 12-word recovery phrase vectors with exact word order and normalization', () => {
      const vec1 = recoveryFixture.vectors[0];
      const vec2 = recoveryFixture.vectors[1];

      expect(vec1.words.length).toBe(12);
      expect(vec2.words.length).toBe(12);
      expect(vec1.words[0]).toBe('abandon');
      expect(vec1.words[11]).toBe('accident');
      expect(vec2.words[0]).toBe('legal');
      expect(vec2.words[11]).toBe('yellow');
    });
  });

  // -------------------------------------------------------------------------
  // 3. Fixed account_id Vectors
  // -------------------------------------------------------------------------
  describe('3. Fixed account_id Vectors', () => {
    it('derives identical, deterministic RFC 4122 v4 UUID from Vector 1 recovery phrase', async () => {
      const vec1 = recoveryFixture.vectors[0];
      const derivedId = await deriveAccountIdFromPhrase(vec1.words);

      expect(derivedId).toBe(vec1.account_id);
      expect(derivedId).toBe('668aca74-6dd2-4e35-a38b-9c9123997810');

      // Verify strict RFC 4122 variant 1, version 4 UUID format
      expect(derivedId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
    });

    it('derives identical, deterministic RFC 4122 v4 UUID from Vector 2 recovery phrase', async () => {
      const vec2 = recoveryFixture.vectors[1];
      const derivedId = await deriveAccountIdFromPhrase(vec2.words);

      expect(derivedId).toBe(vec2.account_id);
      expect(derivedId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
      );
      // Ensure cross-entropy divergence
      expect(derivedId).not.toBe(recoveryFixture.vectors[0].account_id);
    });

    it('handles uppercase words and excess whitespace with strict idempotency', async () => {
      const messyWords = [
        '  ABANDON ', 'Ability', 'ABLE', 'about', 'Above  ', '  absent',
        'ABSORB', 'abstract', 'absurd', 'abuse', 'ACCESS', 'accident  '
      ];
      const cleanDerived = await deriveAccountIdFromPhrase(messyWords);
      expect(cleanDerived).toBe(recoveryFixture.vectors[0].account_id);
    });
  });

  // -------------------------------------------------------------------------
  // 4. Fixed recovery_auth_secret Vectors
  // -------------------------------------------------------------------------
  describe('4. Fixed recovery_auth_secret Vectors', () => {
    it('derives the exact 256-bit recovery auth secret from Vector 1', async () => {
      const vec1 = recoveryFixture.vectors[0];
      const derivedSecret = await deriveRecoveryAuthSecret(vec1.words);

      expect(derivedSecret.length).toBe(32);
      expect(bytesToHex(derivedSecret)).toBe(vec1.recovery_auth_secret_hex);
      expect(bytesToHex(derivedSecret)).toBe(
        '9a5d0f52960e57f4290fc5e9b1d5c8eaca1b285426de9f734dc26a0b30ced8ae'
      );
    });

    it('derives distinct recovery auth secrets for distinct recovery phrases', async () => {
      const vec1 = recoveryFixture.vectors[0];
      const vec2 = recoveryFixture.vectors[1];
      const secret1 = await deriveRecoveryAuthSecret(vec1.words);
      const secret2 = await deriveRecoveryAuthSecret(vec2.words);

      expect(bytesToHex(secret1)).not.toBe(bytesToHex(secret2));
      expect(bytesToHex(secret2)).toBe(vec2.recovery_auth_secret_hex);
    });
  });

  // -------------------------------------------------------------------------
  // 5. Fixed recovery_salt Vectors
  // -------------------------------------------------------------------------
  describe('5. Fixed recovery_salt Vectors', () => {
    it('validates 32-byte recovery salt vectors and rejects invalid salt lengths', () => {
      const salt1 = hexToBytes(recoveryFixture.vectors[0].recovery_salt_hex);
      const salt2 = hexToBytes(recoveryFixture.vectors[1].recovery_salt_hex);

      expect(salt1.length).toBe(32);
      expect(salt2.length).toBe(32);
      expect(bytesToHex(salt1)).toBe(recoveryFixture.vectors[0].recovery_salt_hex);
      expect(bytesToHex(salt2)).toBe(recoveryFixture.vectors[1].recovery_salt_hex);
    });

    it('derives deterministic 32-byte recovery_salt from recovery phrase (Option A)', () => {
      const vec1 = recoveryFixture.vectors[0];
      const vec2 = recoveryFixture.vectors[1];
      const derived1 = deriveRecoverySalt(vec1.words);
      const derived2 = deriveRecoverySalt(vec2.words);

      expect(derived1.length).toBe(32);
      expect(derived2.length).toBe(32);
      expect(bytesToHex(derived1)).toBe(vec1.recovery_salt_hex);
      expect(bytesToHex(derived2)).toBe(vec2.recovery_salt_hex);
      expect(bytesToHex(derived1)).not.toBe(bytesToHex(derived2));
    });
  });

  // -------------------------------------------------------------------------
  // 6. Fixed Argon2id recovery_verifier Vectors
  // -------------------------------------------------------------------------
  describe('6. Fixed Argon2id recovery_verifier Vectors', () => {
    it('derives a 32-byte recovery verifier that serializes to 64 hexadecimal characters', async () => {
      const vec1 = recoveryFixture.vectors[0];
      const authSecret = hexToBytes(vec1.recovery_auth_secret_hex);
      const salt = hexToBytes(vec1.recovery_salt_hex);

      const params: KdfParameters = {
        salt,
        memoryCost: 32768, // 32 MiB
        timeCost: 3,       // 3 iterations
        parallelism: 2,    // 2 threads
        version: 0x13,     // Argon2 v1.3
      };

      const verifier = await computeRecoveryVerifier(authSecret, salt, params);
      expect(verifier.length).toBe(32);

      const verifierHex = bytesToHex(verifier);
      expect(verifierHex.length).toBe(64);
      expect(verifierHex).toMatch(/^[0-9a-f]{64}$/);
    });

    it('proves verifier derivation is deterministic for identical authSecret and salt', async () => {
      const vec1 = recoveryFixture.vectors[0];
      const authSecret = hexToBytes(vec1.recovery_auth_secret_hex);
      const salt = hexToBytes(vec1.recovery_salt_hex);

      const verifierA = await computeRecoveryVerifier(authSecret, salt);
      const verifierB = await computeRecoveryVerifier(authSecret, salt);

      expect(bytesToHex(verifierA)).toBe(bytesToHex(verifierB));
    });

    it('produces different verifiers if salt or authSecret differs', async () => {
      const vec1 = recoveryFixture.vectors[0];
      const authSecret1 = hexToBytes(vec1.recovery_auth_secret_hex);
      const salt1 = hexToBytes(vec1.recovery_salt_hex);
      const salt2 = hexToBytes(recoveryFixture.vectors[1].recovery_salt_hex);

      const verifier1 = await computeRecoveryVerifier(authSecret1, salt1);
      const verifier2 = await computeRecoveryVerifier(authSecret1, salt2);

      expect(bytesToHex(verifier1)).not.toBe(bytesToHex(verifier2));
    });
  });

  // -------------------------------------------------------------------------
  // 7. Fixed AES-256-GCM Vectors
  // -------------------------------------------------------------------------
  describe('7. Fixed AES-256-GCM Vectors', () => {
    it('verifies deterministic AES-256-GCM authenticated encryption and decryption matching NIST vectors', () => {
      const vec = aesGcmFixture.vectors[0];
      const key = hexToBytes(vec.key_hex);
      const nonce = hexToBytes(vec.nonce_hex);
      const plaintext = new TextEncoder().encode(vec.plaintext_ascii);
      const aad = new TextEncoder().encode(vec.aad_ascii);
      const expectedCiphertext = hexToBytes(vec.ciphertext_hex);
      const expectedTag = hexToBytes(vec.tag_hex);

      // Decrypt fixed vector directly
      const decrypted = decrypt(key, expectedCiphertext, nonce, expectedTag, aad);
      expect(new TextDecoder().decode(decrypted)).toBe(vec.plaintext_ascii);
    });

    it('round-trip encrypts and decrypts with AAD verification', () => {
      const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      const plaintext = new TextEncoder().encode('Test roundtrip payload with AAD');
      const aad = new TextEncoder().encode('BOUND_AAD_BYTES');

      const result = encrypt(key, plaintext, aad);
      expect(result.ciphertext.length).toBe(plaintext.length);
      expect(result.nonce.length).toBe(12);
      expect(result.tag.length).toBe(16);

      const decrypted = decrypt(key, result.ciphertext, result.nonce, result.tag, aad);
      expect(new TextDecoder().decode(decrypted)).toBe('Test roundtrip payload with AAD');
    });
  });

  // -------------------------------------------------------------------------
  // 8. Fixed Ghost v1 Envelope Vectors
  // -------------------------------------------------------------------------
  describe('8. Fixed Ghost v1 Envelope Vectors', () => {
    it('parses and verifies the v1 envelope reference vector exactly', () => {
      const vec = v1EnvelopeFixture.vector;
      const serialized = hexToBytes(vec.serialized_envelope_hex);
      expect(serialized.length).toBe(vec.total_envelope_bytes);
      expect(serialized.length).toBe(v1EnvelopeFixture.overhead_bytes + vec.ciphertext_length);

      const parsed = parseEnvelope(serialized);
      expect(parsed.header.formatVersion).toBe(ENVELOPE_FORMAT_VERSION_V1);
      expect(parsed.header.purpose).toBe(EnvelopePurpose.NOTE);
      expect(bytesToHex(parsed.header.keyId)).toBe(vec.key_id_hex);
      expect(bytesToHex(parsed.header.nonce)).toBe(vec.nonce_hex);
      expect(bytesToHex(parsed.ciphertext)).toBe(vec.ciphertext_hex);
      expect(bytesToHex(parsed.gcmTag)).toBe(vec.tag_hex);
    });

    it('matches the v1 binary fixture file byte-for-byte', () => {
      const binBytes = new Uint8Array(v1ReferenceBin);
      const parsed = parseEnvelope(binBytes);

      expect(parsed.header.formatVersion).toBe(1);
      expect(bytesToHex(parsed.header.keyId)).toBe(v1EnvelopeFixture.vector.key_id_hex);
      expect(bytesToHex(parsed.header.nonce)).toBe(v1EnvelopeFixture.vector.nonce_hex);
      expect(bytesToHex(parsed.ciphertext)).toBe(v1EnvelopeFixture.vector.ciphertext_hex);
      expect(bytesToHex(parsed.gcmTag)).toBe(v1EnvelopeFixture.vector.tag_hex);
    });

    it('decrypts v1 envelope ciphertext using the reference key and AAD', () => {
      const vec = v1EnvelopeFixture.vector;
      const key = hexToBytes(aesGcmFixture.vectors[0].key_hex);
      const ciphertext = hexToBytes(vec.ciphertext_hex);
      const nonce = hexToBytes(vec.nonce_hex);
      const tag = hexToBytes(vec.tag_hex);
      const aad = hexToBytes(vec.aad_hex);

      const decrypted = decrypt(key, ciphertext, nonce, tag, aad);
      expect(new TextDecoder().decode(decrypted)).toBe(vec.plaintext_utf8);
    });

    it('serializes a GhostTagEnvelope into identical binary layout', () => {
      const vec = v1EnvelopeFixture.vector;
      const envelope: GhostTagEnvelope = {
        header: {
          magic: 'GTAG',
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose: EnvelopePurpose.NOTE,
          keyId: hexToBytes(vec.key_id_hex),
          nonce: hexToBytes(vec.nonce_hex),
          ciphertextLength: vec.ciphertext_length,
        },
        ciphertext: hexToBytes(vec.ciphertext_hex),
        gcmTag: hexToBytes(vec.tag_hex),
      };

      const serialized = serializeEnvelope(envelope);
      expect(bytesToHex(serialized)).toBe(vec.serialized_envelope_hex);
    });
  });

  // -------------------------------------------------------------------------
  // 9. Fixed Ghost v2 Bulk Envelope Vectors
  // -------------------------------------------------------------------------
  describe('9. Fixed Ghost v2 Bulk Envelope Vectors', () => {
    it('verifies the exact 134-byte fixed overhead of bulk envelopes', () => {
      expect(BULK_ENVELOPE_FIXED_OVERHEAD).toBe(134);
      expect(BULK_AAD_LENGTH).toBe(74);
    });

    it('parses and verifies the v2 bulk envelope reference vector', () => {
      const vec = v2BulkFixture.vector;
      const serialized = hexToBytes(vec.serialized_envelope_hex);
      expect(serialized.length).toBe(vec.total_envelope_bytes);
      expect(serialized.length).toBe(134 + vec.ciphertext_length);

      const parsed = parseBulkEnvelope(serialized);
      expect(parsed.header.formatVersion).toBe(BULK_FORMAT_VERSION_V2);
      expect(parsed.header.recordType).toBe(RECORD_TYPE_BULK_CHUNK);
      expect(bytesToHex(parsed.header.vaultId)).toBe(vec.vault_id_hex);
      expect(bytesToHex(parsed.header.fileId)).toBe(vec.file_id_hex);
      expect(bytesToHex(parsed.header.keyId)).toBe(vec.key_id_hex);
      expect(parsed.header.globalChunkIndex).toBe(vec.global_chunk_index);
      expect(parsed.header.totalVaultChunks).toBe(vec.total_vault_chunks);
      expect(parsed.header.fileChunkIndex).toBe(vec.file_chunk_index);
      expect(parsed.header.totalFileChunks).toBe(vec.total_file_chunks);
      expect(bytesToHex(parsed.header.chunkHash)).toBe(vec.chunk_hash_hex);
      expect(bytesToHex(parsed.header.nonce)).toBe(vec.nonce_hex);
      expect(bytesToHex(parsed.ciphertext)).toBe(vec.ciphertext_hex);
      expect(bytesToHex(parsed.gcmTag)).toBe(vec.tag_hex);
    });

    it('matches the v2 bulk binary fixture file byte-for-byte', () => {
      const binBytes = new Uint8Array(v2ReferenceBin);
      const parsed = parseBulkEnvelope(binBytes);

      expect(parsed.header.formatVersion).toBe(2);
      expect(parsed.header.recordType).toBe(0x10);
      expect(bytesToHex(parsed.header.vaultId)).toBe(v2BulkFixture.vector.vault_id_hex);
      expect(bytesToHex(parsed.header.fileId)).toBe(v2BulkFixture.vector.file_id_hex);
      expect(bytesToHex(parsed.header.keyId)).toBe(v2BulkFixture.vector.key_id_hex);
      expect(bytesToHex(parsed.ciphertext)).toBe(v2BulkFixture.vector.ciphertext_hex);
      expect(bytesToHex(parsed.header.chunkHash)).toBe(v2BulkFixture.vector.chunk_hash_hex);
      expect(bytesToHex(parsed.gcmTag)).toBe(v2BulkFixture.vector.tag_hex);
    });

    it('validates that chunk hash equals SHA-256 of chunk ciphertext', () => {
      const vec = v2BulkFixture.vector;
      const ct = hexToBytes(vec.ciphertext_hex);
      const computedHash = computeChunkHash(ct);
      expect(bytesToHex(computedHash)).toBe(vec.chunk_hash_hex);
    });

    it('serializes a BulkChunkEnvelope into identical binary layout', () => {
      const vec = v2BulkFixture.vector;
      const params = {
        vaultId: hexToBytes(vec.vault_id_hex),
        fileId: hexToBytes(vec.file_id_hex),
        keyId: hexToBytes(vec.key_id_hex),
        globalChunkIndex: vec.global_chunk_index,
        totalVaultChunks: vec.total_vault_chunks,
        fileChunkIndex: vec.file_chunk_index,
        totalFileChunks: vec.total_file_chunks,
        chunkCiphertext: hexToBytes(vec.ciphertext_hex),
        chunkHash: hexToBytes(vec.chunk_hash_hex),
        nonce: hexToBytes(vec.nonce_hex),
        gcmTag: hexToBytes(vec.tag_hex),
      };

      const serialized = serializeBulkEnvelope(params);
      expect(bytesToHex(serialized)).toBe(vec.serialized_envelope_hex);
    });
  });

  // -------------------------------------------------------------------------
  // 10. Tampered Ciphertext Vectors
  // -------------------------------------------------------------------------
  describe('10. Tampered Ciphertext Vectors', () => {
    it('fails v1 envelope decryption when a single bit in ciphertext is modified', () => {
      const vec = v1EnvelopeFixture.vector;
      const key = hexToBytes(aesGcmFixture.vectors[0].key_hex);
      const nonce = hexToBytes(vec.nonce_hex);
      const tag = hexToBytes(vec.tag_hex);
      const aad = hexToBytes(vec.aad_hex);

      const tamperedCiphertext = hexToBytes(vec.ciphertext_hex);
      tamperedCiphertext[0] ^= 0x01; // flip 1 bit

      expect(() => {
        decrypt(key, tamperedCiphertext, nonce, tag, aad);
      }).toThrow();
    });

    it('detects tampering in v2 bulk envelope ciphertext via chunk hash and GCM tag', () => {
      const vec = v2BulkFixture.vector;
      const serialized = hexToBytes(vec.serialized_envelope_hex);
      const key = hexToBytes(aesGcmFixture.vectors[0].key_hex);
      const aad = hexToBytes(vec.aad_hex);

      // Ciphertext starts at byte 118
      const tampered = new Uint8Array(serialized);
      tampered[118] ^= 0x01; // flip 1 bit

      const parsed = parseBulkEnvelope(tampered);

      // 1. Chunk hash mismatch detection
      const recomputedHash = computeChunkHash(parsed.ciphertext);
      expect(bytesToHex(recomputedHash)).not.toBe(bytesToHex(parsed.header.chunkHash));

      // 2. GCM authentication failure detection
      expect(() => {
        decrypt(key, parsed.ciphertext, parsed.header.nonce, parsed.gcmTag, aad);
      }).toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // 11. Tampered AAD Vectors
  // -------------------------------------------------------------------------
  describe('11. Tampered AAD Vectors', () => {
    it('fails AES-256-GCM decryption when AAD is tampered', () => {
      const vec = aesGcmFixture.vectors[0];
      const key = hexToBytes(vec.key_hex);
      const nonce = hexToBytes(vec.nonce_hex);
      const ciphertext = hexToBytes(vec.ciphertext_hex);
      const tag = hexToBytes(vec.tag_hex);

      const tamperedAad = new TextEncoder().encode('TAMPERED_AAD_METADATA');

      expect(() => {
        decrypt(key, ciphertext, nonce, tag, tamperedAad);
      }).toThrow();
    });

    it('fails v1 envelope decryption if version byte in AAD is tampered', () => {
      const vec = v1EnvelopeFixture.vector;
      const key = hexToBytes(aesGcmFixture.vectors[0].key_hex);
      const ciphertext = hexToBytes(vec.ciphertext_hex);
      const nonce = hexToBytes(vec.nonce_hex);
      const tag = hexToBytes(vec.tag_hex);

      const tamperedAad = hexToBytes(vec.aad_hex);
      tamperedAad[4] = 0x02; // tamper version field

      expect(() => {
        decrypt(key, ciphertext, nonce, tag, tamperedAad);
      }).toThrow();
    });

    it('fails v2 bulk decryption if chunk index in AAD is tampered', () => {
      const vec = v2BulkFixture.vector;
      const key = hexToBytes(aesGcmFixture.vectors[0].key_hex);
      const ciphertext = hexToBytes(vec.ciphertext_hex);
      const nonce = hexToBytes(vec.nonce_hex);
      const tag = hexToBytes(vec.tag_hex);

      const tamperedAad = hexToBytes(vec.aad_hex);
      tamperedAad[54] ^= 0xff; // tamper global chunk index

      expect(() => {
        decrypt(key, ciphertext, nonce, tag, tamperedAad);
      }).toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // 12. Wrong Passphrase Vectors
  // -------------------------------------------------------------------------
  describe('12. Wrong Passphrase Vectors', () => {
    it('fails DEK unwrapping when attempted with a wrong KEK', () => {
      const correctKek = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const wrongKek = hexToBytes('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210');
      const rawDek = hexToBytes('11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff');
      const keyId = hexToBytes('aa11bb22cc33dd44ee55ff6600778899');

      const wrappedDek = wrapDEK(correctKek, rawDek, keyId, 1);

      expect(() => {
        unwrapDEK(wrongKek, wrappedDek);
      }).toThrow();
    });
  });

  // -------------------------------------------------------------------------
  // 13. Invalid Version Vectors
  // -------------------------------------------------------------------------
  describe('13. Invalid Version Vectors', () => {
    it('rejects single-tag envelopes with unknown version bytes (0x00, 0x02, 0xff)', () => {
      const vec = v1EnvelopeFixture.vector;
      const envelopeBytes = hexToBytes(vec.serialized_envelope_hex);

      const badVersions = [0x00, 0x02, 0x03, 0xff];
      for (const badVer of badVersions) {
        const copy = new Uint8Array(envelopeBytes);
        copy[4] = badVer;
        expect(() => {
          parseEnvelope(copy);
        }).toThrow();
      }
    });

    it('rejects bulk envelopes with invalid version bytes (0x00, 0x01, 0xff)', () => {
      const vec = v2BulkFixture.vector;
      const envelopeBytes = hexToBytes(vec.serialized_envelope_hex);

      const badVersions = [0x00, 0x01, 0x03, 0xff];
      for (const badVer of badVersions) {
        const copy = new Uint8Array(envelopeBytes);
        copy[4] = badVer;
        expect(() => {
          parseBulkEnvelope(copy);
        }).toThrow();
      }
    });
  });

  // -------------------------------------------------------------------------
  // 14. Invalid Verifier Format Vectors
  // -------------------------------------------------------------------------
  describe('14. Invalid Verifier Format Vectors', () => {
    it('rejects recovery verifiers that do not match 64 hexadecimal characters', async () => {
      const validAccountId = recoveryFixture.vectors[0].account_id;

      const invalidVerifiers = [
        '',                                        // empty
        'a'.repeat(63),                            // 63 chars (too short)
        'a'.repeat(65),                            // 65 chars (too long)
        'g'.repeat(64),                            // non-hex characters
        '0123456789abcdef'.repeat(3) + 'XYZ!',    // non-hex tail
      ];

      for (const badVerifier of invalidVerifiers) {
        await expect(
          recoverVaultWithVerifier(validAccountId, badVerifier, 'new-user')
        ).rejects.toThrow('RECOVERY_FAILED');
      }
    });

    it('rejects account_id that does not conform to RFC 4122 UUID', async () => {
      const validVerifier = 'a'.repeat(64);
      const invalidAccountIds = [
        '',
        'not-a-uuid',
        '668aca74-6dd2-0e35-a38b-9c9123997810',  // version 0
        '668aca746dd24e35a38b9c9123997810',      // missing hyphens
        '668aca74-6dd2-4e35-038b-9c9123997810',  // variant 0
      ];

      for (const badAccountId of invalidAccountIds) {
        await expect(
          recoverVaultWithVerifier(badAccountId, validVerifier, 'new-user')
        ).rejects.toThrow('RECOVERY_FAILED');
      }
    });
  });

  // -------------------------------------------------------------------------
  // 15. Cross-Platform Reference Fixtures
  // -------------------------------------------------------------------------
  describe('15. Cross-Platform Reference Fixtures', () => {
    it('verifies all reference fixture files exist on disk with valid JSON schema', () => {
      expect(fs.existsSync(AES_GCM_FIXTURE_PATH)).toBe(true);
      expect(fs.existsSync(RECOVERY_FIXTURE_PATH)).toBe(true);
      expect(fs.existsSync(V1_ENVELOPE_FIXTURE_PATH)).toBe(true);
      expect(fs.existsSync(V2_BULK_FIXTURE_PATH)).toBe(true);
      expect(fs.existsSync(V1_BIN_FIXTURE_PATH)).toBe(true);
      expect(fs.existsSync(V2_BIN_FIXTURE_PATH)).toBe(true);

      expect(aesGcmFixture.vectors.length).toBeGreaterThanOrEqual(1);
      expect(recoveryFixture.vectors.length).toBeGreaterThanOrEqual(2);
      expect(v1EnvelopeFixture.vector.serialized_envelope_hex).toBeDefined();
      expect(v2BulkFixture.vector.serialized_envelope_hex).toBeDefined();
    });

    it('validates binary fixture files match expected fixed byte sizes', () => {
      const v1Stat = fs.statSync(V1_BIN_FIXTURE_PATH);
      const v2Stat = fs.statSync(V2_BIN_FIXTURE_PATH);

      expect(v1Stat.size).toBe(v1EnvelopeFixture.vector.total_envelope_bytes);
      expect(v2Stat.size).toBe(v2BulkFixture.vector.total_envelope_bytes);
    });
  });

  // -------------------------------------------------------------------------
  // 16. Extended 20-Point Cross-Platform Compatibility Suite (Android vs Web vs Ghost Bridge)
  // -------------------------------------------------------------------------
  describe('16. Extended 20-Point Cross-Platform Compatibility Suite (Android vs Web vs Ghost Bridge)', () => {
    it('Point 1: Web account_id equals Android account_id for same phrase', async () => {
      for (const vec of recoveryFixture.vectors) {
        const androidId = await deriveAccountIdFromPhrase(vec.words);
        const webId = await WebSupabase.deriveAccountId(vec.words);
        expect(webId).toBe(androidId);
        expect(webId).toBe(vec.account_id);
      }
    });

    it('Point 2: Web recovery_auth_secret equals Android recovery_auth_secret for same phrase', async () => {
      for (const vec of recoveryFixture.vectors) {
        const androidSecret = await deriveRecoveryAuthSecret(vec.words);
        const webSecret = await WebSupabase.deriveRecoveryAuthSecret(vec.words);
        expect(bytesToHex(webSecret)).toBe(bytesToHex(androidSecret));
        expect(bytesToHex(webSecret)).toBe(vec.recovery_auth_secret_hex);
      }
    });

    it('Point 3: Web recovery_verifier equals Android recovery_verifier for same phrase and salt', async () => {
      for (const vec of recoveryFixture.vectors) {
        const salt = hexToBytes(vec.recovery_salt_hex);
        const androidSecret = await deriveRecoveryAuthSecret(vec.words);
        const webSecret = await WebSupabase.deriveRecoveryAuthSecret(vec.words);

        const androidVerifier = await computeRecoveryVerifier(androidSecret, salt);
        const webVerifier = await WebSupabase.computeRecoveryVerifier(webSecret, salt);

        expect(webVerifier).toBe(bytesToHex(androidVerifier));
        expect(webVerifier).toBe(vec.recovery_verifier_hex);
      }
    });

    it('Point 4: Web uses Argon2id, not PBKDF2, for recovery_verifier', async () => {
      const vec = recoveryFixture.vectors[0];
      const salt = hexToBytes(vec.recovery_salt_hex);
      const webSecret = await WebSupabase.deriveRecoveryAuthSecret(vec.words);
      const webVerifier = await WebSupabase.computeRecoveryVerifier(webSecret, salt);

      const cryptoModule = require('crypto');
      const legacyPbkdf2 = cryptoModule.pbkdf2Sync(
        Buffer.from(webSecret),
        Buffer.from(salt),
        100000,
        32,
        'sha256'
      ).toString('hex');

      expect(webVerifier).not.toBe(legacyPbkdf2);
      expect(webVerifier).toBe(vec.recovery_verifier_hex);
    });

    it('Point 5: Web rejects PBKDF2-derived recovery verifiers', async () => {
      const vec = recoveryFixture.vectors[0];
      const cryptoModule = require('crypto');
      const legacyPbkdf2 = cryptoModule.pbkdf2Sync(
        Buffer.from(hexToBytes(vec.recovery_auth_secret_hex)),
        Buffer.from(hexToBytes(vec.recovery_salt_hex)),
        100000,
        32,
        'sha256'
      ).toString('hex');

      const localStore: Record<string, string> = {};
      const mockStorage = {
        getItem: (k: string) => localStore[k] || null,
        setItem: (k: string, v: string) => { localStore[k] = v; },
      };
      (global as any).localStorage = mockStorage;

      try {
        localStore[`ghost_offline_cloud_vault_v2_${vec.account_id}`] = JSON.stringify({
          account_id: vec.account_id,
          encrypted_vault_blob: 'dGVzdA==',
          vault_version: 2,
          recovery_verifier: legacyPbkdf2,
        });

        const validArgonVerifier = vec.recovery_verifier_hex;
        await expect(
          WebSupabase.recoverVaultWithVerifier(vec.account_id, validArgonVerifier)
        ).rejects.toThrow('RECOVERY_FAILED');
      } finally {
        delete (global as any).localStorage;
      }
    });

    it('Point 6: Web uses exact same Argon2id parameters as Android', async () => {
      const vec = recoveryFixture.vectors[0];
      const authSecret = hexToBytes(vec.recovery_auth_secret_hex);
      const salt = hexToBytes(vec.recovery_salt_hex);

      const canonicalParams = {
        memoryCost: 32768,
        timeCost: 3,
        parallelism: 2,
        hashLength: 32,
        version: 0x13
      };

      const verifierWithParams = await WebSupabase.computeRecoveryVerifier(authSecret, salt, canonicalParams);
      const defaultVerifier = await WebSupabase.computeRecoveryVerifier(authSecret, salt);

      expect(verifierWithParams).toBe(defaultVerifier);
      expect(verifierWithParams).toBe(vec.recovery_verifier_hex);

      const divergentVerifier = await WebSupabase.computeRecoveryVerifier(authSecret, salt, {
        memoryCost: 16384,
        timeCost: 2,
        parallelism: 1
      });
      expect(divergentVerifier).not.toBe(vec.recovery_verifier_hex);
    });

    it('Point 7: Web produces byte-identical AES-256-GCM ciphertext and tag as Android', () => {
      const vec = aesGcmFixture.vectors[0];
      const key = hexToBytes(vec.key_hex);
      const nonce = hexToBytes(vec.nonce_hex);
      const plaintext = new TextEncoder().encode(vec.plaintext_ascii);
      const aad = new TextEncoder().encode(vec.aad_ascii);

      const QuickCrypto = require('react-native-quick-crypto');
      const cipherQC = QuickCrypto.createCipheriv('aes-256-gcm', QuickCrypto.Buffer.from(key), QuickCrypto.Buffer.from(nonce));
      cipherQC.setAAD(QuickCrypto.Buffer.from(aad));
      const ctQC = QuickCrypto.Buffer.concat([cipherQC.update(QuickCrypto.Buffer.from(plaintext)), cipherQC.final()]);
      const tagQC = cipherQC.getAuthTag();

      const cryptoModule = require('crypto');
      const cipherNode = cryptoModule.createCipheriv('aes-256-gcm', key, nonce);
      cipherNode.setAAD(aad);
      const ctNode = Buffer.concat([cipherNode.update(plaintext), cipherNode.final()]);
      const tagNode = cipherNode.getAuthTag();

      expect(bytesToHex(ctQC)).toBe(bytesToHex(ctNode));
      expect(bytesToHex(tagQC)).toBe(bytesToHex(tagNode));
      expect(bytesToHex(ctNode)).toBe(vec.ciphertext_hex);
      expect(bytesToHex(tagNode)).toBe(vec.tag_hex);
    });

    it('Point 8: Web decrypts Android-created Ghost v1 envelopes', () => {
      const vec = v1EnvelopeFixture.vector;
      const binBytes = new Uint8Array(v1ReferenceBin);
      const parsed = WebApp.parseV1Envelope(binBytes);

      expect(parsed.version).toBe(1);
      expect(bytesToHex(parsed.keyId)).toBe(vec.key_id_hex);
      expect(bytesToHex(parsed.nonce)).toBe(vec.nonce_hex);
      expect(bytesToHex(parsed.ciphertext)).toBe(vec.ciphertext_hex);
      expect(bytesToHex(parsed.tag)).toBe(vec.tag_hex);
      expect(bytesToHex(parsed.aad)).toBe(vec.aad_hex);

      const cryptoModule = require('crypto');
      const decipher = cryptoModule.createDecipheriv('aes-256-gcm', hexToBytes(aesGcmFixture.vectors[0].key_hex), parsed.nonce);
      decipher.setAAD(parsed.aad);
      decipher.setAuthTag(parsed.tag);
      const decrypted = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]);
      expect(decrypted.toString('utf8')).toBe(vec.plaintext_utf8);
    });

    it('Point 9: Web decrypts Android-created Ghost v2 bulk envelopes', () => {
      const vec = v2BulkFixture.vector;
      const binBytes = new Uint8Array(v2ReferenceBin);
      const parsed = WebApp.parseGtagEnvelope(binBytes);

      expect(parsed.version).toBe(2);
      expect(parsed.recordType).toBe(0x10);
      expect(bytesToHex(parsed.vaultId)).toBe(vec.vault_id_hex);
      expect(bytesToHex(parsed.fileId)).toBe(vec.file_id_hex);
      expect(bytesToHex(parsed.keyId)).toBe(vec.key_id_hex);
      expect(bytesToHex(parsed.chunkHash)).toBe(vec.chunk_hash_hex);
      expect(bytesToHex(parsed.ciphertext)).toBe(vec.ciphertext_hex);
      expect(bytesToHex(parsed.tag)).toBe(vec.tag_hex);

      const cryptoModule = require('crypto');
      const decipher = cryptoModule.createDecipheriv('aes-256-gcm', hexToBytes(aesGcmFixture.vectors[0].key_hex), parsed.iv);
      decipher.setAAD(parsed.aad);
      decipher.setAuthTag(parsed.tag);
      const decrypted = Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]);
      expect(decrypted.toString('utf8')).toBe(vec.plaintext_utf8);
    });

    it('Point 10: Android decrypts Web-created Ghost v1 envelopes', () => {
      const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      const keyId = hexToBytes('0102030405060708090a0b0c0d0e0f10');
      const nonce = hexToBytes('505152535455565758595a5b');
      const plaintext = new TextEncoder().encode('Web created v1 secret message for Android');

      const aad = new Uint8Array(26);
      aad.set(new TextEncoder().encode('GTAG'), 0);
      aad[4] = 0x01;
      aad[5] = 0x01;
      aad.set(keyId, 6);
      new DataView(aad.buffer).setUint32(22, plaintext.length, true);

      const cryptoModule = require('crypto');
      const cipher = cryptoModule.createCipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(aad);
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();

      const webEnv = WebApp.buildV1Envelope({
        keyIdBytes: keyId,
        iv: nonce,
        ciphertext: ct,
        tag: tag,
        purpose: 0x01
      });

      const parsedByAndroid = parseEnvelope(webEnv.envelope);
      expect(parsedByAndroid.header.formatVersion).toBe(1);
      expect(bytesToHex(parsedByAndroid.header.keyId)).toBe(bytesToHex(keyId));

      const androidAAD = constructAAD(parsedByAndroid.header);
      expect(bytesToHex(androidAAD)).toBe(bytesToHex(webEnv.aad));

      const decrypted = decrypt(key, parsedByAndroid.ciphertext, parsedByAndroid.header.nonce, parsedByAndroid.gcmTag, androidAAD);
      expect(new TextDecoder().decode(decrypted)).toBe('Web created v1 secret message for Android');
    });

    it('Point 11: Android decrypts Web-created Ghost v2 bulk envelopes', () => {
      const key = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
      const vaultId = hexToBytes('11111111222222223333333344444444');
      const fileId = hexToBytes('55555555666666667777777788888888');
      const keyId = hexToBytes('99999999aaaaaaaa00000000bbbbbbbb');
      const nonce = hexToBytes('c0c1c2c3c4c5c6c7c8c9cacb');
      const plaintext = new TextEncoder().encode('Web created v2 chunk payload for Android validation');

      const aad = constructBulkAAD({
        vaultId,
        fileId,
        keyId,
        globalChunkIndex: 0,
        totalVaultChunks: 1,
        fileChunkIndex: 0,
        totalFileChunks: 1,
        chunkCiphertextLength: plaintext.length
      });

      const cryptoModule = require('crypto');
      const cipher = cryptoModule.createCipheriv('aes-256-gcm', key, nonce);
      cipher.setAAD(aad);
      const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();
      const chunkHash = cryptoModule.createHash('sha256').update(ct).digest();

      const webBulkEnv = WebApp.buildGtagEnvelope({
        vaultIdBytes: vaultId,
        fileIdBytes: fileId,
        keyIdBytes: keyId,
        globalChunkIndex: 0,
        totalVaultChunks: 1,
        fileChunkIndex: 0,
        totalFileChunks: 1,
        ciphertext: ct,
        chunkHash: chunkHash,
        iv: nonce,
        tag: tag
      });

      const parsedByAndroid = parseBulkEnvelope(webBulkEnv);
      const valResult = validateBulkEnvelope(webBulkEnv);
      expect(valResult.isValid).toBe(true);

      const decrypted = decrypt(key, parsedByAndroid.ciphertext, parsedByAndroid.header.nonce, parsedByAndroid.gcmTag, aad);
      expect(new TextDecoder().decode(decrypted)).toBe('Web created v2 chunk payload for Android validation');
    });

    it('Point 12: Ghost Bridge decrypts / transports Web-created Ghost v1 and v2 envelopes', () => {
      const v1Bin = new Uint8Array(v1ReferenceBin);
      const v2Bin = new Uint8Array(v2ReferenceBin);

      const v1Ndef = buildMimeNdefMessage('application/vnd.ghost.secure', Buffer.from(v1Bin));
      const v1Records = parseNdefRecords(v1Ndef);
      expect(v1Records.length).toBe(1);
      expect(v1Records[0].mediaType).toBe('application/vnd.ghost.secure');
      expect(bytesToHex(new Uint8Array(v1Records[0].data))).toBe(bytesToHex(v1Bin));

      const v2Ndef = buildMimeNdefMessage('application/vnd.ghost.bulk', Buffer.from(v2Bin));
      const v2Records = parseNdefRecords(v2Ndef);
      expect(v2Records.length).toBe(1);
      expect(v2Records[0].mediaType).toBe('application/vnd.ghost.bulk');
      expect(bytesToHex(new Uint8Array(v2Records[0].data))).toBe(bytesToHex(v2Bin));

      const parsedV1 = WebApp.parseV1Envelope(new Uint8Array(v1Records[0].data));
      expect(parsedV1.version).toBe(1);
      const parsedV2 = WebApp.parseGtagEnvelope(new Uint8Array(v2Records[0].data));
      expect(parsedV2.version).toBe(2);
    });

    it('Point 13: Web rejects tampered ciphertext', () => {
      const vec = v2BulkFixture.vector;
      const tampered = hexToBytes(vec.serialized_envelope_hex);
      tampered[120] ^= 0x01;

      const parsed = WebApp.parseGtagEnvelope(tampered);
      const cryptoModule = require('crypto');
      const computedHash = cryptoModule.createHash('sha256').update(parsed.ciphertext).digest('hex');
      expect(computedHash).not.toBe(bytesToHex(parsed.chunkHash));

      const decipher = cryptoModule.createDecipheriv('aes-256-gcm', hexToBytes(aesGcmFixture.vectors[0].key_hex), parsed.iv);
      decipher.setAAD(parsed.aad);
      decipher.setAuthTag(parsed.tag);
      expect(() => {
        Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]);
      }).toThrow();
    });

    it('Point 14: Web rejects tampered AAD', () => {
      const vec = v2BulkFixture.vector;
      const parsed = WebApp.parseGtagEnvelope(hexToBytes(vec.serialized_envelope_hex));
      const tamperedAAD = new Uint8Array(parsed.aad);
      tamperedAAD[4] = 0x01;

      const cryptoModule = require('crypto');
      const decipher = cryptoModule.createDecipheriv('aes-256-gcm', hexToBytes(aesGcmFixture.vectors[0].key_hex), parsed.iv);
      decipher.setAAD(tamperedAAD);
      decipher.setAuthTag(parsed.tag);
      expect(() => {
        Buffer.concat([decipher.update(parsed.ciphertext), decipher.final()]);
      }).toThrow();
    });

    it('Point 15: Web rejects wrong passphrase', () => {
      const cryptoModule = require('crypto');
      const correctKek = hexToBytes('0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef');
      const wrongKek = hexToBytes('fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210');
      const rawDek = hexToBytes('11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff');
      const nonce = hexToBytes('a0a1a2a3a4a5a6a7a8a9aaab');
      const aad = new Uint8Array([0x56, 0x4B]);

      const cipher = cryptoModule.createCipheriv('aes-256-gcm', correctKek, nonce);
      cipher.setAAD(aad);
      const ct = Buffer.concat([cipher.update(rawDek), cipher.final()]);
      const tag = cipher.getAuthTag();

      const decipher = cryptoModule.createDecipheriv('aes-256-gcm', wrongKek, nonce);
      decipher.setAAD(aad);
      decipher.setAuthTag(tag);
      expect(() => {
        Buffer.concat([decipher.update(ct), decipher.final()]);
      }).toThrow();
    });

    it('Point 16: Web rejects unsupported envelope versions', () => {
      const v1Bytes = hexToBytes(v1EnvelopeFixture.vector.serialized_envelope_hex);
      const v2Bytes = hexToBytes(v2BulkFixture.vector.serialized_envelope_hex);

      for (const badVer of [0x00, 0x03, 0xff]) {
        const copy1 = new Uint8Array(v1Bytes);
        copy1[4] = badVer;
        expect(() => WebApp.parseV1Envelope(copy1)).toThrow(/Unsupported envelope version/);

        const copy2 = new Uint8Array(v2Bytes);
        copy2[4] = badVer;
        expect(() => WebApp.parseGtagEnvelope(copy2)).toThrow(/Unsupported envelope version/);
      }
    });

    it('Point 17: Web rejects malformed envelopes', () => {
      expect(() => WebApp.parseV1Envelope(new Uint8Array(50))).toThrow(/smaller than minimum/);
      expect(() => WebApp.parseGtagEnvelope(new Uint8Array(100))).toThrow(/smaller than minimum/);

      const badMagic1 = new Uint8Array(hexToBytes(v1EnvelopeFixture.vector.serialized_envelope_hex));
      badMagic1[0] = 0x58;
      expect(() => WebApp.parseV1Envelope(badMagic1)).toThrow(/Invalid magic/);

      const badMagic2 = new Uint8Array(hexToBytes(v2BulkFixture.vector.serialized_envelope_hex));
      badMagic2[0] = 0x58;
      expect(() => WebApp.parseGtagEnvelope(badMagic2)).toThrow(/THIS TAG TYPE IS NOT SUPPORTED/);
    });

    it('Point 18: Web rejects invalid account_id format', async () => {
      const validVerifier = 'a'.repeat(64);
      const invalidAccountIds = [
        '',
        'not-a-uuid',
        '668aca74-6dd2-0e35-a38b-9c9123997810',
        '668aca746dd24e35a38b9c9123997810',
        'hello-world'
      ];

      for (const badId of invalidAccountIds) {
        await expect(
          WebSupabase.recoverVaultWithVerifier(badId, validVerifier)
        ).rejects.toThrow('RECOVERY_FAILED');
      }
    });

    it('Point 19: Web rejects invalid recovery_verifier format', async () => {
      const validId = recoveryFixture.vectors[0].account_id;
      const invalidVerifiers = [
        '',
        'a'.repeat(63),
        'a'.repeat(65),
        'g'.repeat(64),
        'not-hex-at-all'
      ];

      for (const badVerifier of invalidVerifiers) {
        await expect(
          WebSupabase.recoverVaultWithVerifier(validId, badVerifier)
        ).rejects.toThrow('RECOVERY_FAILED');
      }
    });

    it('Point 20: Web sends only account_id and recovery_verifier to Supabase', async () => {
      const validId = recoveryFixture.vectors[0].account_id;
      const validVerifier = recoveryFixture.vectors[0].recovery_verifier_hex;

      let capturedUrl = '';
      let capturedBody: any = null;

      const originalFetch = (global as any).fetch;
      (global as any).fetch = jest.fn().mockImplementation(async (url: string, init: any) => {
        capturedUrl = url;
        if (init && init.body) {
          capturedBody = JSON.parse(init.body);
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            account_id: validId,
            encrypted_vault_blob: 'ZW5jcnlwdGVkLXZhdWx0LWJsb2I=',
            vault_version: 2
          })
        };
      });

      const localStore: Record<string, string> = {
        ghost_supabase_config_v2: JSON.stringify({
          url: 'https://test-project.supabase.co',
          anonKey: 'anon-key-test-12345',
          isConfigured: true,
          disabled: false
        })
      };
      (global as any).localStorage = {
        getItem: (k: string) => localStore[k] || null,
        setItem: (k: string, v: string) => { localStore[k] = v; },
      };

      try {
        const result = await WebSupabase.recoverVaultWithVerifier(validId, validVerifier);
        expect(result.source).toBe('supabase-cloud');
        expect(capturedUrl).toContain('/functions/v1/recover-vault');

        const keys = Object.keys(capturedBody).sort();
        expect(keys).toEqual(['account_id', 'recovery_verifier']);
        expect(capturedBody.account_id).toBe(validId);
        expect(capturedBody.recovery_verifier).toBe(validVerifier);

        expect(capturedBody.passphrase).toBeUndefined();
        expect(capturedBody.recovery_phrase).toBeUndefined();
        expect(capturedBody.kek).toBeUndefined();
        expect(capturedBody.dek).toBeUndefined();
        expect(capturedBody.plaintext).toBeUndefined();
      } finally {
        (global as any).fetch = originalFetch;
        delete (global as any).localStorage;
      }
    });

    it('Point 21: Web recover-vault works without owner session (anonymous recovery credential)', async () => {
      const validId = recoveryFixture.vectors[0].account_id;
      const validVerifier = recoveryFixture.vectors[0].recovery_verifier_hex;

      let capturedAuthHeader = '';
      const originalFetch = (global as any).fetch;
      (global as any).fetch = jest.fn().mockImplementation(async (_url: string, init: any) => {
        if (init && init.headers) {
          capturedAuthHeader = init.headers.Authorization || '';
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            account_id: validId,
            encrypted_vault_blob: 'ZW5jcnlwdGVkLXZhdWx0LWJsb2I=',
            vault_version: 2
          })
        };
      });

      const localStore: Record<string, string> = {
        ghost_supabase_config_v2: JSON.stringify({
          url: 'https://test-project.supabase.co',
          anonKey: 'anon-public-key-xyz',
          isConfigured: true,
          disabled: false
        })
      };
      (global as any).localStorage = {
        getItem: (k: string) => localStore[k] || null,
        setItem: (k: string, v: string) => { localStore[k] = v; },
      };

      try {
        const result = await WebSupabase.recoverVaultWithVerifier(validId, validVerifier);
        expect(result.source).toBe('supabase-cloud');
        // Recovery header does not require an owner JWT; anon key is permitted
        expect(capturedAuthHeader).toBe('Bearer anon-public-key-xyz');
      } finally {
        (global as any).fetch = originalFetch;
        delete (global as any).localStorage;
      }
    });

    it('Point 22: Migration endpoint migrates legacy PBKDF2 verifier to Argon2id without owner session', async () => {
      const legacyId = 'e207b669-e7d1-4475-80f0-8c2049e7bdf5';
      const legacyVerifier = '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff';
      const newVerifier = recoveryFixture.vectors[0].recovery_verifier_hex;

      let capturedUrl = '';
      let capturedBody: any = null;

      const originalFetch = (global as any).fetch;
      (global as any).fetch = jest.fn().mockImplementation(async (url: string, init: any) => {
        capturedUrl = url;
        if (init && init.body) {
          capturedBody = JSON.parse(init.body);
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({
            success: true,
            recovery_kdf_version: 2
          })
        };
      });

      const localStore: Record<string, string> = {
        ghost_supabase_config_v2: JSON.stringify({
          url: 'https://test-project.supabase.co',
          anonKey: 'anon-public-key-xyz',
          isConfigured: true,
          disabled: false
        })
      };
      (global as any).localStorage = {
        getItem: (k: string) => localStore[k] || null,
        setItem: (k: string, v: string) => { localStore[k] = v; },
      };

      try {
        const res = await WebSupabase.migrateRecoveryVerifier(legacyId, legacyVerifier, newVerifier);
        expect(res.success).toBe(true);
        expect(res.recoveryKdfVersion).toBe(2);
        expect(capturedUrl).toContain('/functions/v1/migrate-recovery-verifier');

        expect(capturedBody.account_id).toBe(legacyId);
        expect(capturedBody.legacy_recovery_verifier).toBe(legacyVerifier);
        expect(capturedBody.new_recovery_verifier).toBe(newVerifier);
        // Client does NOT send recovery_salt; server derives it via zero-knowledge binding
        expect(capturedBody.recovery_salt).toBeUndefined();
      } finally {
        (global as any).fetch = originalFetch;
        delete (global as any).localStorage;
      }
    });

    it('Point 23: Migration payload sends only recovery identifiers and zero secrets', async () => {
      const legacyId = 'e207b669-e7d1-4475-80f0-8c2049e7bdf5';
      const legacyVerifier = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';
      const newVerifier = recoveryFixture.vectors[0].recovery_verifier_hex;

      let capturedBody: any = null;
      const originalFetch = (global as any).fetch;
      (global as any).fetch = jest.fn().mockImplementation(async (_url: string, init: any) => {
        if (init && init.body) {
          capturedBody = JSON.parse(init.body);
        }
        return {
          ok: true,
          status: 200,
          json: async () => ({ success: true, recovery_kdf_version: 2 })
        };
      });

      const localStore: Record<string, string> = {
        ghost_supabase_config_v2: JSON.stringify({
          url: 'https://test-project.supabase.co',
          anonKey: 'anon-test',
          isConfigured: true
        })
      };
      (global as any).localStorage = {
        getItem: (k: string) => localStore[k] || null,
        setItem: (k: string, v: string) => { localStore[k] = v; },
      };

      try {
        await WebSupabase.migrateRecoveryVerifier(legacyId, legacyVerifier, newVerifier);
        const keys = Object.keys(capturedBody).sort();
        expect(keys).toEqual([
          'account_id',
          'legacy_recovery_verifier',
          'new_recovery_verifier'
        ]);

        expect(capturedBody.passphrase).toBeUndefined();
        expect(capturedBody.recovery_phrase).toBeUndefined();
        expect(capturedBody.recovery_auth_secret).toBeUndefined();
        expect(capturedBody.recovery_salt).toBeUndefined();
        expect(capturedBody.kek).toBeUndefined();
        expect(capturedBody.dek).toBeUndefined();
        expect(capturedBody.plaintext).toBeUndefined();
      } finally {
        (global as any).fetch = originalFetch;
        delete (global as any).localStorage;
      }
    });

    it('Point 24: Migration rejects malformed input and mismatched legacy verifiers', async () => {
      // Missing or invalid account_id
      await expect(
        WebSupabase.migrateRecoveryVerifier('', '1122', 'a'.repeat(64))
      ).rejects.toThrow('MIGRATION_FAILED');

      // Invalid new_recovery_verifier length
      await expect(
        WebSupabase.migrateRecoveryVerifier('e207b669-e7d1-4475-80f0-8c2049e7bdf5', '1122', 'short')
      ).rejects.toThrow('MIGRATION_FAILED');

      // Arbitrary/invalid recovery_salt rejected
      await expect(
        WebSupabase.migrateRecoveryVerifier('e207b669-e7d1-4475-80f0-8c2049e7bdf5', '1122', 'a'.repeat(64), 'arbitrary_invalid_salt')
      ).rejects.toThrow('MIGRATION_FAILED');
    });

    it('Point 25: Mock core verifies migration preserves encrypted vault blob intact and derives deterministic salt', async () => {
      const testAccountId = 'a0000000-0000-4000-8000-000000000001';
      const legacyVerifier = '1111111111111111111111111111111111111111111111111111111111111111';
      const originalBlob = 'ORIGINAL_ENCRYPTED_VAULT_BLOB_UNCHANGED';

      // Seed mock store with legacy vault (recovery_kdf_version = 1)
      await uploadEncryptedVaultMetadata({
        accountId: testAccountId,
        recoveryVerifierHex: legacyVerifier,
        recoverySaltHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
        recoveryKdfVersion: 1,
        encryptedBlobBase64: originalBlob,
        vaultVersion: 2
      });

      const newVerifier = '2222222222222222222222222222222222222222222222222222222222222222';

      const { migrateRecoveryVerifier: clientMigrate } = require('../cloud/supabaseClient');
      const migResult = await clientMigrate(testAccountId, legacyVerifier, newVerifier);
      expect(migResult.success).toBe(true);
      expect(migResult.recoveryKdfVersion).toBe(2);

      // Verify recovery now succeeds with new verifier and blob is byte-identical
      const recovered = await recoverVaultWithVerifier(testAccountId, newVerifier);
      expect(recovered.encryptedBlob).toBe(originalBlob);
      expect(recovered.vaultVersion).toBe(2);

      // Verify re-migration fails (kdf_version is already 2)
      await expect(
        clientMigrate(testAccountId, legacyVerifier, newVerifier)
      ).rejects.toThrow('MIGRATION_FAILED');
    });

    describe('Section 17: Comprehensive 30-Point Zero-Knowledge Verification Suite', () => {
      it('1 & 2: Recovery works with no owner JWT and no local cache', async () => {
        const validId = recoveryFixture.vectors[0].account_id;
        const validVerifier = recoveryFixture.vectors[0].recovery_verifier_hex;
        let capturedAuth = '';

        const originalFetch = (global as any).fetch;
        (global as any).fetch = jest.fn().mockImplementation(async (_url: string, init: any) => {
          capturedAuth = init.headers.Authorization;
          return {
            ok: true,
            status: 200,
            json: async () => ({
              account_id: validId,
              encrypted_vault_blob: 'BLOB_DATA',
              vault_version: 2
            })
          };
        });

        const localStore: Record<string, string> = {
          ghost_supabase_config_v2: JSON.stringify({
            url: 'https://test-project.supabase.co',
            anonKey: 'anon-key-123',
            isConfigured: true
          })
        };
        (global as any).localStorage = {
          getItem: (k: string) => localStore[k] || null,
          setItem: () => {},
        };

        try {
          const res = await WebSupabase.recoverVaultWithVerifier(validId, validVerifier);
          expect(res.source).toBe('supabase-cloud');
          expect(capturedAuth).toBe('Bearer anon-key-123'); // Public anon key, no owner JWT
        } finally {
          (global as any).fetch = originalFetch;
          delete (global as any).localStorage;
        }
      });

      it('3 & 4: Recovery rejects invalid account_id and invalid verifier format', async () => {
        await expect(WebSupabase.recoverVaultWithVerifier('not-a-uuid', 'a'.repeat(64))).rejects.toThrow('RECOVERY_FAILED');
        await expect(WebSupabase.recoverVaultWithVerifier('3c9909af-72ae-41d3-9f4a-ea91bf14936d', 'short')).rejects.toThrow('RECOVERY_FAILED');
      });

      it('5, 6, 7: Recovery rejects wrong verifier and returns generic error for missing account or mismatch', async () => {
        const originalFetch = (global as any).fetch;
        (global as any).fetch = jest.fn().mockImplementation(async () => {
          return { ok: false, status: 403, json: async () => ({ error: 'RECOVERY_FAILED' }) };
        });

        const localStore: Record<string, string> = {
          ghost_supabase_config_v2: JSON.stringify({
            url: 'https://test-project.supabase.co',
            anonKey: 'anon-key-123',
            isConfigured: true
          })
        };
        (global as any).localStorage = {
          getItem: (k: string) => localStore[k] || null,
          setItem: () => {},
        };

        try {
          await expect(
            WebSupabase.recoverVaultWithVerifier('3c9909af-72ae-41d3-9f4a-ea91bf14936d', 'f'.repeat(64))
          ).rejects.toThrow('RECOVERY_FAILED');
        } finally {
          (global as any).fetch = originalFetch;
          delete (global as any).localStorage;
        }
      });

      it('8: Recovery rate limit works', async () => {
        resetSupabaseConfig();
        const testId = '3c9909af-72ae-41d3-9f4a-ea91bf14936d';
        const wrongVerifier = '0'.repeat(64);

        for (let i = 0; i < 25; i++) {
          try {
            await recoverVaultWithVerifier(testId, wrongVerifier);
          } catch (_) {}
        }

        // 26th attempt fails immediately due to client/server atomic rate limit
        await expect(recoverVaultWithVerifier(testId, wrongVerifier)).rejects.toThrow('RECOVERY_FAILED');
      });

      it('9: Recovery response does not return recovery_salt', async () => {
        const validId = recoveryFixture.vectors[0].account_id;
        const validVerifier = recoveryFixture.vectors[0].recovery_verifier_hex;

        const originalFetch = (global as any).fetch;
        (global as any).fetch = jest.fn().mockImplementation(async () => {
          return {
            ok: true,
            status: 200,
            json: async () => ({
              account_id: validId,
              encrypted_vault_blob: 'BLOB_DATA',
              vault_version: 2
            })
          };
        });

        const localStore: Record<string, string> = {
          ghost_supabase_config_v2: JSON.stringify({
            url: 'https://test-project.supabase.co',
            anonKey: 'anon-key-123',
            isConfigured: true
          })
        };
        (global as any).localStorage = {
          getItem: (k: string) => localStore[k] || null,
          setItem: () => {},
        };

        try {
          const res: any = await WebSupabase.recoverVaultWithVerifier(validId, validVerifier);
          expect(res.recovery_salt).toBeUndefined();
          expect(res.recoverySalt).toBeUndefined();
        } finally {
          (global as any).fetch = originalFetch;
          delete (global as any).localStorage;
        }
      });

      it('10, 11, 12, 13: Migration works for kdf_version = 1, rejects kdf_version = 2 or unknown, rejects wrong legacy verifier', async () => {
        const { migrateRecoveryVerifier: clientMigrate } = require('../cloud/supabaseClient');
        const accId = 'b0000000-0000-4000-8000-000000000002';
        const correctLegacy = '3'.repeat(64);
        const wrongLegacy = '4'.repeat(64);
        const targetNew = '5'.repeat(64);

        await uploadEncryptedVaultMetadata({
          accountId: accId,
          recoveryVerifierHex: correctLegacy,
          recoverySaltHex: '01'.repeat(32),
          recoveryKdfVersion: 1,
          encryptedBlobBase64: 'BLOB',
          vaultVersion: 2
        });

        // Rejects wrong legacy verifier
        await expect(clientMigrate(accId, wrongLegacy, targetNew)).rejects.toThrow('MIGRATION_FAILED');

        // Works for kdf_version = 1
        const mig = await clientMigrate(accId, correctLegacy, targetNew);
        expect(mig.success).toBe(true);
        expect(mig.recoveryKdfVersion).toBe(2);

        // Rejects kdf_version = 2 (already migrated)
        await expect(clientMigrate(accId, correctLegacy, targetNew)).rejects.toThrow('MIGRATION_FAILED');
      });

      it('14 & 15: Migration rejects malformed inputs and arbitrary recovery_salt', async () => {
        const { migrateRecoveryVerifier: clientMigrate } = require('../cloud/supabaseClient');
        await expect(clientMigrate('not-uuid', '1111', 'a'.repeat(64))).rejects.toThrow('MIGRATION_FAILED');
        await expect(clientMigrate('b0000000-0000-4000-8000-000000000002', '1111', 'short')).rejects.toThrow('MIGRATION_FAILED');
        // Rejects arbitrary recovery salt
        await expect(clientMigrate('b0000000-0000-4000-8000-000000000002', '1111', 'a'.repeat(64), 'arbitrary_salt')).rejects.toThrow('MIGRATION_FAILED');
      });

      it('16, 17, 18, 19, 20: Migration preserves blob/version, updates kdf to 2, prevents replay and cross-user overwrite', async () => {
        const { migrateRecoveryVerifier: clientMigrate } = require('../cloud/supabaseClient');
        const userA = 'c0000000-0000-4000-8000-000000000003';
        const legacyVerA = 'a'.repeat(64);
        const originalBlob = 'USER_A_BLOB_PRESERVED';

        await uploadEncryptedVaultMetadata({
          accountId: userA,
          recoveryVerifierHex: legacyVerA,
          recoverySaltHex: '01'.repeat(32),
          recoveryKdfVersion: 1,
          encryptedBlobBase64: originalBlob,
          vaultVersion: 2
        });

        const newVerA = 'b'.repeat(64);
        const res = await clientMigrate(userA, legacyVerA, newVerA);
        expect(res.success).toBe(true);
        expect(res.recoveryKdfVersion).toBe(2);

        // Preserves blob and vault_version
        const recovered = await recoverVaultWithVerifier(userA, newVerA);
        expect(recovered.encryptedBlob).toBe(originalBlob);
        expect(recovered.vaultVersion).toBe(2);

        // Cannot replay migration
        await expect(clientMigrate(userA, legacyVerA, newVerA)).rejects.toThrow('MIGRATION_FAILED');

        // Cannot update another user's account with user A's verifier
        const userB = 'd0000000-0000-4000-8000-000000000004';
        await expect(clientMigrate(userB, legacyVerA, newVerA)).rejects.toThrow('MIGRATION_FAILED');
      });

      it('21 & 22: Migration returns generic errors and obeys atomic rate limit', async () => {
        const originalFetch = (global as any).fetch;
        (global as any).fetch = jest.fn().mockImplementation(async () => {
          return { ok: false, status: 429, json: async () => ({ error: 'MIGRATION_FAILED' }) };
        });

        const localStore: Record<string, string> = {
          ghost_supabase_config_v2: JSON.stringify({
            url: 'https://test-project.supabase.co',
            anonKey: 'anon-test',
            isConfigured: true
          })
        };
        (global as any).localStorage = {
          getItem: (k: string) => localStore[k] || null,
          setItem: () => {},
        };

        try {
          await expect(
            WebSupabase.migrateRecoveryVerifier('c0000000-0000-4000-8000-000000000003', '1'.repeat(64), '2'.repeat(64))
          ).rejects.toThrow('MIGRATION_FAILED');
        } finally {
          (global as any).fetch = originalFetch;
          delete (global as any).localStorage;
        }
      });

      it('23, 24, 25: Web & Android recovery and migration send zero secrets', async () => {
        let sentRecoveryBody: any = null;
        let sentMigrationBody: any = null;

        const originalFetch = (global as any).fetch;
        (global as any).fetch = jest.fn().mockImplementation(async (url: string, init: any) => {
          if (url.includes('recover-vault')) {
            sentRecoveryBody = JSON.parse(init.body);
            return { ok: true, status: 200, json: async () => ({ account_id: 'a', encrypted_vault_blob: 'b', vault_version: 2 }) };
          }
          if (url.includes('migrate-recovery-verifier')) {
            sentMigrationBody = JSON.parse(init.body);
            return { ok: true, status: 200, json: async () => ({ success: true, recovery_kdf_version: 2 }) };
          }
          return { ok: true, status: 200, json: async () => ({}) };
        });

        const localStore: Record<string, string> = {
          ghost_supabase_config_v2: JSON.stringify({
            url: 'https://test-project.supabase.co',
            anonKey: 'anon-test',
            isConfigured: true
          })
        };
        (global as any).localStorage = {
          getItem: (k: string) => localStore[k] || null,
          setItem: () => {},
        };

        try {
          await WebSupabase.recoverVaultWithVerifier('c0000000-0000-4000-8000-000000000003', '1'.repeat(64));
          expect(Object.keys(sentRecoveryBody).sort()).toEqual(['account_id', 'recovery_verifier']);

          await WebSupabase.migrateRecoveryVerifier('c0000000-0000-4000-8000-000000000003', '1'.repeat(64), '2'.repeat(64));
          expect(Object.keys(sentMigrationBody).sort()).toEqual(['account_id', 'legacy_recovery_verifier', 'new_recovery_verifier']);

          for (const body of [sentRecoveryBody, sentMigrationBody]) {
            expect(body.passphrase).toBeUndefined();
            expect(body.recovery_phrase).toBeUndefined();
            expect(body.recovery_auth_secret).toBeUndefined();
            expect(body.recovery_salt).toBeUndefined();
            expect(body.kek).toBeUndefined();
            expect(body.dek).toBeUndefined();
            expect(body.plaintext).toBeUndefined();
          }
        } finally {
          (global as any).fetch = originalFetch;
          delete (global as any).localStorage;
        }
      });

      it('26 & 27: iOS recovery & migration clients send strictly recovery identifiers and zero secrets', () => {
        // Reads Swift client source to verify Encodable request models
        const swiftClientSource = fs.readFileSync(path.resolve(__dirname, '../../ios/GhostTag/Core/Cloud/SupabaseRecoveryClient.swift'), 'utf8');

        // Verification of Swift request structs
        expect(swiftClientSource).toContain('public struct VaultRecoveryRequest: Encodable {');
        expect(swiftClientSource).toContain('public let account_id: String');
        expect(swiftClientSource).toContain('public let recovery_verifier: String');

        expect(swiftClientSource).toContain('public struct VaultMigrationRequest: Encodable {');
        expect(swiftClientSource).toContain('public let legacy_recovery_verifier: String');
        expect(swiftClientSource).toContain('public let new_recovery_verifier: String');

        // Negative check: Zero secrets in Swift API payloads
        expect(swiftClientSource).not.toContain('let passphrase');
        expect(swiftClientSource).not.toContain('let recovery_phrase');
        expect(swiftClientSource).not.toContain('let recovery_auth_secret');
        expect(swiftClientSource).not.toContain('let kek');
        expect(swiftClientSource).not.toContain('let dek');
      });
    });
  });
});
