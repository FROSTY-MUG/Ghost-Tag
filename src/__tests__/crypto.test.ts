/**
 * @file crypto.test.ts
 * @summary Comprehensive unit test suite for Ghost-Tag Cryptographic Core.
 */

import {
  generateSecureRandom,
  generateNonce,
  generateKeyId,
  generateDEK,
  generateSalt,
  generateRecoverySecret,
  RECOVERY_SECRET_BYTE_LENGTH,
} from '../crypto/random';
import {
  deriveKEK,
  benchmarkDevice,
  getDefaultParams,
  validateParams,
  checkParamDowngrade,
  setTestArgon2Provider,
  KDFParams,
} from '../crypto/argon2';
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
  wrapDEK,
  unwrapDEK,
  bytesToHex,
} from '../crypto/keyWrap';
import {
  zeroize,
  zeroizeAll,
  secureWipeBuffer,
} from '../crypto/secureMemory';
import {
  ENVELOPE_MAGIC,
  ENVELOPE_MAGIC_BYTES,
  ENVELOPE_FORMAT_VERSION_V1,
  ENVELOPE_KEY_ID_SIZE,
  ENVELOPE_NONCE_SIZE,
  ENVELOPE_GCM_TAG_SIZE,
  ENVELOPE_FIXED_OVERHEAD_BYTES,
  ENVELOPE_AAD_SIZE,
  EnvelopePurpose,
  GhostTagEnvelope,
} from '../contracts/envelope';
import { DeviceTier, KdfParameters } from '../contracts/keyHierarchy';

// Fast mock provider for test suites
const mockArgon2Provider = async (
  passphrase: string,
  salt: Uint8Array,
  params: KDFParams
): Promise<Uint8Array> => {
  const output = new Uint8Array(32);
  const encoder = new TextEncoder();
  const passBytes = encoder.encode(passphrase);
  for (let i = 0; i < 32; i++) {
    output[i] =
      ((passBytes[i % passBytes.length] || 0) ^
        salt[i % salt.length] ^
        params.memoryCost ^
        params.timeCost ^
        params.parallelism ^
        i) &
      0xff;
  }
  return output;
};

describe('Ghost-Tag Cryptographic Core Suite', () => {
  beforeAll(() => {
    setTestArgon2Provider(mockArgon2Provider);
  });

  afterAll(() => {
    setTestArgon2Provider(null);
  });

  describe('Random Byte Generation & CSPRNG', () => {
    it('generates secure random bytes of correct length', () => {
      const bytes16 = generateSecureRandom(16);
      expect(bytes16).toBeInstanceOf(Uint8Array);
      expect(bytes16.length).toBe(16);

      const bytes32 = generateSecureRandom(32);
      expect(bytes32.length).toBe(32);
    });

    it('generates nonces of exactly 12 bytes (96 bits)', () => {
      const nonce = generateNonce();
      expect(nonce.length).toBe(ENVELOPE_NONCE_SIZE);
      expect(nonce.length).toBe(12);
    });

    it('generates unique nonces across sequential invocations', () => {
      const nonces = new Set<string>();
      for (let i = 0; i < 100; i++) {
        const nonce = generateNonce();
        const hex = bytesToHex(nonce);
        expect(nonces.has(hex)).toBe(false);
        nonces.add(hex);
      }
    });

    it('generates Key IDs of exactly 16 bytes (128 bits)', () => {
      const keyId = generateKeyId();
      expect(keyId.length).toBe(ENVELOPE_KEY_ID_SIZE);
      expect(keyId.length).toBe(16);
    });

    it('generates DEK of exactly 32 bytes (256 bits)', () => {
      const dek = generateDEK();
      expect(dek.length).toBe(32);
    });

    it('generates Salt of exactly 16 bytes (128 bits)', () => {
      const salt = generateSalt();
      expect(salt.length).toBe(16);
    });

    it('generates recovery secret of exactly 32 bytes', () => {
      const secret = generateRecoverySecret();
      expect(secret.length).toBe(RECOVERY_SECRET_BYTE_LENGTH);
      expect(secret.length).toBe(32);
    });

    it('throws error for invalid byte length requests', () => {
      expect(() => generateSecureRandom(0)).toThrow();
      expect(() => generateSecureRandom(-5)).toThrow();
    });
  });

  describe('Argon2id Key Derivation Function (RFC 9106)', () => {
    const validPassphrase = 'CorrectHorseBatteryStaple#2024!';
    const salt = generateSalt();
    const defaultParams = getDefaultParams(DeviceTier.STANDARD);

    it('derives 256-bit KEK from valid passphrase and salt', async () => {
      const kek = await deriveKEK(validPassphrase, salt, defaultParams);
      expect(kek).toBeInstanceOf(Uint8Array);
      expect(kek.length).toBe(32);
    });

    it('rejects empty passphrases', async () => {
      await expect(deriveKEK('', salt, defaultParams)).rejects.toThrow();
    });

    it('rejects invalid salt lengths (< 8 bytes)', async () => {
      const badSalt = new Uint8Array(4);
      await expect(deriveKEK(validPassphrase, badSalt, defaultParams)).rejects.toThrow();
    });

    it('validates parameter bounds correctly', () => {
      expect(
        validateParams({ ...defaultParams, memoryCost: 10, timeCost: 3, parallelism: 4 })
      ).toBe(false);

      expect(
        validateParams({ ...defaultParams, memoryCost: 65536, timeCost: 0, parallelism: 4 })
      ).toBe(false);

      expect(
        validateParams({ ...defaultParams, memoryCost: 65536, timeCost: 3, parallelism: 0 })
      ).toBe(false);

      expect(
        validateParams({ ...defaultParams, memoryCost: 65536, timeCost: 3, parallelism: 4 })
      ).toBe(true);
    });

    it('detects parameter downgrades correctly', () => {
      const baseline = getDefaultParams(DeviceTier.STANDARD);
      const downgraded: KdfParameters = {
        ...baseline,
        memoryCost: baseline.memoryCost / 2,
      };

      expect(checkParamDowngrade(baseline, downgraded)).toBe(true);
      expect(checkParamDowngrade(baseline, baseline)).toBe(false);
    });

    it('device benchmark produces valid calibrated parameters', async () => {
      const tier = await benchmarkDevice();
      expect([DeviceTier.LOW_END, DeviceTier.STANDARD, DeviceTier.HIGH_END]).toContain(tier);
    });
  });

  describe('AES-256-GCM Encryption & Decryption', () => {
    const key = generateDEK();
    const plaintext = new TextEncoder().encode('Confidential Ghost-Tag Payload 007');
    const aad = new TextEncoder().encode('GTAG_TEST_AAD');

    it('encrypts and decrypts round-trip successfully', () => {
      const { ciphertext, nonce, tag } = encrypt(key, plaintext, aad);

      expect(ciphertext.length).toBe(plaintext.length);
      expect(tag.length).toBe(ENVELOPE_GCM_TAG_SIZE);

      const decrypted = decrypt(key, ciphertext, nonce, tag, aad);
      expect(new TextDecoder().decode(decrypted)).toBe(
        new TextDecoder().decode(plaintext)
      );
    });

    it('fails decryption if ciphertext is tampered by even 1 bit', () => {
      const { ciphertext, nonce, tag } = encrypt(key, plaintext, aad);

      const tampered = new Uint8Array(ciphertext);
      tampered[0] ^= 0x01;

      expect(() => decrypt(key, tampered, nonce, tag, aad)).toThrow();
    });

    it('fails decryption if authentication tag is corrupted', () => {
      const { ciphertext, nonce, tag } = encrypt(key, plaintext, aad);

      const corruptedTag = new Uint8Array(tag);
      corruptedTag[corruptedTag.length - 1] ^= 0xff;

      expect(() => decrypt(key, ciphertext, nonce, corruptedTag, aad)).toThrow();
    });

    it('fails decryption if AAD does not match encryption AAD', () => {
      const { ciphertext, nonce, tag } = encrypt(key, plaintext, aad);
      const forgedAAD = new TextEncoder().encode('FORGED_AAD_ATTACK');

      expect(() => decrypt(key, ciphertext, nonce, tag, forgedAAD)).toThrow();
    });

    it('rejects keys not exactly 32 bytes', () => {
      const badKey = new Uint8Array(16);
      expect(() => encrypt(badKey, plaintext, aad)).toThrow();
    });
  });

  describe('Binary Envelope Serialization & Parsing (v1 54-byte)', () => {
    const purpose = EnvelopePurpose.CREDENTIAL;
    const keyId = generateKeyId();
    const payload = new TextEncoder().encode('Top Secret NFC Password');
    const dek = generateDEK();

    it('constructs deterministic 26-byte AAD correctly', () => {
      const aad = constructAAD(
        ENVELOPE_FORMAT_VERSION_V1,
        purpose,
        keyId,
        payload.length
      );
      expect(aad.length).toBe(ENVELOPE_AAD_SIZE);
      expect(aad.length).toBe(26);

      const magicStr = String.fromCharCode(...aad.subarray(0, 4));
      expect(magicStr).toBe(ENVELOPE_MAGIC);
      expect(aad[4]).toBe(ENVELOPE_FORMAT_VERSION_V1);
      expect(aad[5]).toBe(purpose);
    });

    it('serializes envelope to exact byte layout with 54-byte fixed overhead', () => {
      const aad = constructAAD(
        ENVELOPE_FORMAT_VERSION_V1,
        purpose,
        keyId,
        payload.length
      );
      const { ciphertext, nonce, tag } = encrypt(dek, payload, aad);

      const envelope: GhostTagEnvelope = {
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose,
          keyId,
          nonce,
          ciphertextLength: payload.length,
        },
        ciphertext,
        gcmTag: tag,
      };

      const envelopeBytes = serializeEnvelope(envelope);

      expect(envelopeBytes.length).toBe(
        ENVELOPE_FIXED_OVERHEAD_BYTES + payload.length
      );
      expect(envelopeBytes.length).toBe(54 + payload.length);
    });

    it('parses valid binary envelope back to fields with fidelity', () => {
      const aad = constructAAD(
        ENVELOPE_FORMAT_VERSION_V1,
        purpose,
        keyId,
        payload.length
      );
      const { ciphertext, nonce, tag } = encrypt(dek, payload, aad);

      const envelope: GhostTagEnvelope = {
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose,
          keyId,
          nonce,
          ciphertextLength: payload.length,
        },
        ciphertext,
        gcmTag: tag,
      };

      const envelopeBytes = serializeEnvelope(envelope);
      const parsed = parseEnvelope(envelopeBytes);

      expect(parsed.header.formatVersion).toBe(ENVELOPE_FORMAT_VERSION_V1);
      expect(parsed.header.purpose).toBe(purpose);
      expect(bytesToHex(parsed.header.keyId)).toBe(bytesToHex(keyId));
      expect(bytesToHex(parsed.header.nonce)).toBe(bytesToHex(nonce));
      expect(bytesToHex(parsed.ciphertext)).toBe(bytesToHex(ciphertext));
      expect(bytesToHex(parsed.gcmTag)).toBe(bytesToHex(tag));
    });

    it('rejects envelope with invalid magic bytes', () => {
      const aad = constructAAD(
        ENVELOPE_FORMAT_VERSION_V1,
        purpose,
        keyId,
        payload.length
      );
      const { ciphertext, nonce, tag } = encrypt(dek, payload, aad);
      const envelopeBytes = serializeEnvelope({
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose,
          keyId,
          nonce,
          ciphertextLength: payload.length,
        },
        ciphertext,
        gcmTag: tag,
      });

      envelopeBytes[0] = 0x58; // 'X' instead of 'G'
      expect(() => parseEnvelope(envelopeBytes)).toThrow();
    });

    it('rejects envelope shorter than 54 bytes', () => {
      const tooShort = new Uint8Array(53);
      tooShort.set(ENVELOPE_MAGIC_BYTES, 0);
      expect(() => parseEnvelope(tooShort)).toThrow();
    });
  });

  describe('Key Wrapping & Key Hierarchy', () => {
    const kek = generateSecureRandom(32);
    const dek = generateDEK();
    const keyId = generateKeyId();

    it('wraps and unwraps DEK correctly under KEK with domain separation', () => {
      const wrapped = wrapDEK(kek, dek, keyId, 1);
      expect(wrapped.wrappedCiphertext.length).toBe(dek.length);
      expect(wrapped.nonce.length).toBe(12);
      expect(wrapped.tag.length).toBe(16);

      const unwrapped = unwrapDEK(kek, wrapped);
      expect(bytesToHex(unwrapped)).toBe(bytesToHex(dek));
    });

    it('fails DEK unwrap if wrapped key is altered', () => {
      const wrapped = wrapDEK(kek, dek, keyId, 1);
      const alteredCiphertext = new Uint8Array(wrapped.wrappedCiphertext);
      alteredCiphertext[0] ^= 0x01;

      expect(() =>
        unwrapDEK(kek, { ...wrapped, wrappedCiphertext: alteredCiphertext })
      ).toThrow();
    });

    it('fails DEK unwrap if Key ID does not match AAD binding', () => {
      const wrapped = wrapDEK(kek, dek, keyId, 1);
      const wrongKeyId = bytesToHex(generateKeyId());

      expect(() =>
        unwrapDEK(kek, { ...wrapped, keyId: wrongKeyId })
      ).toThrow();
    });
  });

  describe('Secure In-Memory Key Hygiene & Zeroization', () => {
    it('zeroizes byte buffers completely with 0x00 bytes', () => {
      const secret = new Uint8Array([0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]);
      zeroize(secret);
      for (let i = 0; i < secret.length; i++) {
        expect(secret[i]).toBe(0);
      }
    });

    it('zeroizes multiple buffers in one call', () => {
      const buf1 = new Uint8Array([1, 2, 3]);
      const buf2 = new Uint8Array([4, 5, 6]);
      zeroizeAll(buf1, buf2);
      expect(buf1.every((b) => b === 0)).toBe(true);
      expect(buf2.every((b) => b === 0)).toBe(true);
    });

    it('secureWipeBuffer executes multi-pass overwrite', () => {
      const buf = new Uint8Array([10, 20, 30, 40]);
      secureWipeBuffer(buf);
      expect(buf.every((b) => b === 0)).toBe(true);
    });
  });
});
