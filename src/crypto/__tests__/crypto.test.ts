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
} from '../random';
import {
  deriveKEK,
  benchmarkDevice,
  getDefaultParams,
  validateParams,
  checkParamDowngrade,
  setTestArgon2Provider,
  KDFParams,
} from '../argon2';
import {
  encrypt,
  decrypt,
  wrapKey,
  unwrapKey,
} from '../aesGcm';
import {
  serializeEnvelope,
  parseEnvelope,
  constructAAD,
  validateEnvelope,
} from '../envelope';
import {
  wrapDEK,
  unwrapDEK,
  buildKeyWrapAAD,
  bytesToHex,
  hexToBytes,
} from '../keyWrap';
import {
  zeroize,
  zeroizeAll,
} from '../secureMemory';
import {
  ENVELOPE_MAGIC,
  ENVELOPE_MAGIC_BYTES,
  ENVELOPE_FORMAT_VERSION_V1,
  ENVELOPE_FIXED_OVERHEAD_BYTES,
  ENVELOPE_AAD_SIZE,
  EnvelopePurpose,
  GhostTagEnvelope,
} from '../../contracts/envelope';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../../contracts/errors';
import {
  DeviceTier,
  KeyStatus,
  KEY_WRAP_PURPOSE_BYTE,
  KEY_WRAP_AAD_BYTE_LENGTH,
  DEK_BYTE_LENGTH,
  KEK_BYTE_LENGTH,
  KEY_ID_BYTE_LENGTH,
} from '../../contracts/keyHierarchy';

describe('Ghost-Tag Cryptographic Core Suite', () => {
  afterEach(() => {
    // Reset test provider after each test
    setTestArgon2Provider(null);
    jest.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // 1. CSPRNG Abstraction (random.ts)
  // ---------------------------------------------------------------------------
  describe('CSPRNG (random.ts)', () => {
    it('generates secure random bytes of specified length', () => {
      const bytes = generateSecureRandom(64);
      expect(bytes).toBeInstanceOf(Uint8Array);
      expect(bytes.length).toBe(64);
    });

    it('rejects non-positive lengths', () => {
      expect(() => generateSecureRandom(0)).toThrow(RangeError);
      expect(() => generateSecureRandom(-10)).toThrow(RangeError);
      expect(() => generateSecureRandom(1.5)).toThrow(RangeError);
    });

    it('generates a 12-byte nonce', () => {
      const nonce = generateNonce();
      expect(nonce).toBeInstanceOf(Uint8Array);
      expect(nonce.length).toBe(12);
    });

    it('generates a 16-byte keyId', () => {
      const keyId = generateKeyId();
      expect(keyId.length).toBe(KEY_ID_BYTE_LENGTH);
    });

    it('generates a 32-byte DEK', () => {
      const dek = generateDEK();
      expect(dek.length).toBe(DEK_BYTE_LENGTH);
    });

    it('generates a 16-byte salt', () => {
      const salt = generateSalt();
      expect(salt.length).toBe(16);
    });

    it('generates a 32-byte recovery secret', () => {
      const secret = generateRecoverySecret();
      expect(secret.length).toBe(RECOVERY_SECRET_BYTE_LENGTH);
    });

    it('verifies nonce uniqueness across 1000 generations', () => {
      const count = 1000;
      const seen = new Set<string>();
      for (let i = 0; i < count; i++) {
        const nonce = generateNonce();
        expect(nonce.length).toBe(12);
        const hex = bytesToHex(nonce);
        expect(seen.has(hex)).toBe(false);
        seen.add(hex);
      }
      expect(seen.size).toBe(count);
    });
  });

  // ---------------------------------------------------------------------------
  // 2. AES-256-GCM AEAD (aesGcm.ts)
  // ---------------------------------------------------------------------------
  describe('AES-256-GCM AEAD (aesGcm.ts)', () => {
    const testKey = generateDEK();
    const testPlaintext = new TextEncoder().encode('Ghost-Tag Top Secret Payload 2026');
    const testAad = new TextEncoder().encode('domain-separation-metadata');

    it('encrypts and decrypts round-trip with valid AAD', () => {
      const enc = encrypt(testKey, testPlaintext, testAad);
      expect(enc.ciphertext.length).toBe(testPlaintext.length);
      expect(enc.nonce.length).toBe(12);
      expect(enc.tag.length).toBe(16);

      const decrypted = decrypt(testKey, enc.ciphertext, enc.nonce, enc.tag, testAad);
      expect(decrypted).toEqual(testPlaintext);
      expect(new TextDecoder().decode(decrypted)).toBe('Ghost-Tag Top Secret Payload 2026');
    });

    it('always generates a unique fresh nonce on successive encryptions', () => {
      const enc1 = encrypt(testKey, testPlaintext, testAad);
      const enc2 = encrypt(testKey, testPlaintext, testAad);
      expect(enc1.nonce).not.toEqual(enc2.nonce);
      expect(bytesToHex(enc1.nonce)).not.toBe(bytesToHex(enc2.nonce));
    });

    it('fails decryption when wrong key is provided', () => {
      const enc = encrypt(testKey, testPlaintext, testAad);
      const wrongKey = generateDEK();

      expect(() => {
        decrypt(wrongKey, enc.ciphertext, enc.nonce, enc.tag, testAad);
      }).toThrow(GhostTagError);

      try {
        decrypt(wrongKey, enc.ciphertext, enc.nonce, enc.tag, testAad);
      } catch (err) {
        const gErr = err as GhostTagError;
        expect(gErr.code).toBe(GhostTagErrorCode.GCM_AUTH_FAILED);
        expect(gErr.category).toBe(ErrorCategory.CRYPTO);
        expect(gErr.severity).toBe(ErrorSeverity.CRITICAL);
      }
    });

    it('fails decryption when ciphertext is tampered', () => {
      const enc = encrypt(testKey, testPlaintext, testAad);
      const tamperedCt = new Uint8Array(enc.ciphertext);
      tamperedCt[0] ^= 0x01; // flip 1 bit

      expect(() => {
        decrypt(testKey, tamperedCt, enc.nonce, enc.tag, testAad);
      }).toThrow(GhostTagError);

      try {
        decrypt(testKey, tamperedCt, enc.nonce, enc.tag, testAad);
      } catch (err) {
        const gErr = err as GhostTagError;
        expect(gErr.code).toBe(GhostTagErrorCode.GCM_AUTH_FAILED);
      }
    });

    it('fails decryption when AAD is tampered', () => {
      const enc = encrypt(testKey, testPlaintext, testAad);
      const tamperedAad = new TextEncoder().encode('tampered-separation-metadata');

      expect(() => {
        decrypt(testKey, enc.ciphertext, enc.nonce, enc.tag, tamperedAad);
      }).toThrow(GhostTagError);
    });

    it('fails decryption when auth tag is tampered', () => {
      const enc = encrypt(testKey, testPlaintext, testAad);
      const tamperedTag = new Uint8Array(enc.tag);
      tamperedTag[tamperedTag.length - 1] ^= 0x01;

      expect(() => {
        decrypt(testKey, enc.ciphertext, enc.nonce, tamperedTag, testAad);
      }).toThrow(GhostTagError);
    });

    it('wraps and unwraps key round-trip', () => {
      const kek = generateSecureRandom(KEK_BYTE_LENGTH);
      const dek = generateDEK();
      const aad = new Uint8Array([1, 2, 3, 4]);

      const wrapped = wrapKey(kek, dek, aad);
      expect(wrapped.ciphertext.length).toBe(32);
      expect(wrapped.nonce.length).toBe(12);
      expect(wrapped.tag.length).toBe(16);

      const unwrapped = unwrapKey(kek, wrapped, aad);
      expect(unwrapped).toEqual(dek);
    });

    it('rejects wrapping key when DEK is not 32 bytes', () => {
      const kek = generateSecureRandom(KEK_BYTE_LENGTH);
      const badDek = new Uint8Array(16);
      const aad = new Uint8Array([1]);

      expect(() => wrapKey(kek, badDek, aad)).toThrow(GhostTagError);
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Envelope Serializer, Parser & AAD (envelope.ts)
  // ---------------------------------------------------------------------------
  describe('Envelope Operations (envelope.ts)', () => {
    function createSampleEnvelope(payloadLength = 40): GhostTagEnvelope {
      const ciphertext =
        payloadLength > 0
          ? generateSecureRandom(payloadLength)
          : new Uint8Array(0);
      return {
        header: {
          magic: ENVELOPE_MAGIC,
          formatVersion: ENVELOPE_FORMAT_VERSION_V1,
          purpose: EnvelopePurpose.NOTE,
          keyId: generateKeyId(),
          nonce: generateNonce(),
          ciphertextLength: payloadLength,
        },
        ciphertext,
        gcmTag: generateSecureRandom(16),
      };
    }

    it('serializes and parses an envelope round-trip with payload', () => {
      const original = createSampleEnvelope(48);
      const serialized = serializeEnvelope(original);

      // Expected total length = 54 overhead + 48 payload = 102 bytes
      expect(serialized.length).toBe(ENVELOPE_FIXED_OVERHEAD_BYTES + 48);

      const validation = validateEnvelope(serialized);
      expect(validation.isValid).toBe(true);
      expect(validation.valid).toBe(true);

      const parsed = parseEnvelope(serialized);
      expect(parsed.header.magic).toBe(ENVELOPE_MAGIC);
      expect(parsed.header.formatVersion).toBe(ENVELOPE_FORMAT_VERSION_V1);
      expect(parsed.header.purpose).toBe(EnvelopePurpose.NOTE);
      expect(parsed.header.keyId).toEqual(original.header.keyId);
      expect(parsed.header.nonce).toEqual(original.header.nonce);
      expect(parsed.header.ciphertextLength).toBe(48);
      expect(parsed.ciphertext).toEqual(original.ciphertext);
      expect(parsed.gcmTag).toEqual(original.gcmTag);
    });

    it('serializes and parses an empty-payload envelope (54 bytes overhead)', () => {
      const original = createSampleEnvelope(0);
      const serialized = serializeEnvelope(original);
      expect(serialized.length).toBe(54);

      const parsed = parseEnvelope(serialized);
      expect(parsed.header.ciphertextLength).toBe(0);
      expect(parsed.ciphertext.length).toBe(0);
      expect(parsed.gcmTag).toEqual(original.gcmTag);
    });

    it('rejects truncated envelope shorter than 54 bytes', () => {
      const original = createSampleEnvelope(10);
      const serialized = serializeEnvelope(original);
      const truncated = serialized.slice(0, 53); // 1 byte less than fixed overhead

      const val = validateEnvelope(truncated);
      expect(val.isValid).toBe(false);
      expect(val.errorCode).toBe(GhostTagErrorCode.INVALID_ENVELOPE);

      expect(() => parseEnvelope(truncated)).toThrow(GhostTagError);
      try {
        parseEnvelope(truncated);
      } catch (err) {
        expect((err as GhostTagError).code).toBe(GhostTagErrorCode.INVALID_ENVELOPE);
      }
    });

    it('rejects envelope truncated inside ciphertext or tag', () => {
      const original = createSampleEnvelope(30);
      const serialized = serializeEnvelope(original);
      // Total is 54 + 30 = 84 bytes. Cut at 75 bytes.
      const truncated = serialized.slice(0, 75);

      const val = validateEnvelope(truncated);
      expect(val.isValid).toBe(false);
      expect(val.errorCode).toBe(GhostTagErrorCode.INVALID_ENVELOPE);
      expect(() => parseEnvelope(truncated)).toThrow(GhostTagError);
    });

    it('rejects oversized envelope with trailing bytes', () => {
      const original = createSampleEnvelope(20);
      const serialized = serializeEnvelope(original);
      const oversized = new Uint8Array(serialized.length + 8);
      oversized.set(serialized);
      oversized.fill(0xff, serialized.length); // trailing garbage

      const val = validateEnvelope(oversized);
      expect(val.isValid).toBe(false);
      expect(val.errorCode).toBe(GhostTagErrorCode.INVALID_ENVELOPE);
      expect(() => parseEnvelope(oversized)).toThrow(GhostTagError);
    });

    it('rejects envelope with invalid magic identifier', () => {
      const original = createSampleEnvelope(16);
      const serialized = serializeEnvelope(original);
      serialized[0] = 0x58; // 'X' instead of 'G'

      const val = validateEnvelope(serialized);
      expect(val.isValid).toBe(false);
      expect(val.errorCode).toBe(GhostTagErrorCode.INVALID_ENVELOPE);
      expect(() => parseEnvelope(serialized)).toThrow(GhostTagError);
    });

    it('rejects envelope with unsupported format version', () => {
      const original = createSampleEnvelope(16);
      const serialized = serializeEnvelope(original);
      serialized[4] = 0x02; // version 2 unsupported

      const val = validateEnvelope(serialized);
      expect(val.isValid).toBe(false);
      expect(val.errorCode).toBe(GhostTagErrorCode.UNSUPPORTED_VERSION);

      expect(() => parseEnvelope(serialized)).toThrow(GhostTagError);
      try {
        parseEnvelope(serialized);
      } catch (err) {
        expect((err as GhostTagError).code).toBe(GhostTagErrorCode.UNSUPPORTED_VERSION);
      }
    });

    it('constructs deterministic 26-byte AAD matching specifications', () => {
      const keyId = generateKeyId();
      const ctLength = 1024;
      const aad1 = constructAAD(ENVELOPE_FORMAT_VERSION_V1, EnvelopePurpose.CREDENTIAL, keyId, ctLength);
      const aad2 = constructAAD({
        formatVersion: ENVELOPE_FORMAT_VERSION_V1,
        purpose: EnvelopePurpose.CREDENTIAL,
        keyId,
        ciphertextLength: ctLength,
      });

      expect(aad1.length).toBe(ENVELOPE_AAD_SIZE); // 26 bytes
      expect(aad2.length).toBe(ENVELOPE_AAD_SIZE);
      expect(aad1).toEqual(aad2);

      // Verify layout: MAGIC (4B)
      expect(aad1.slice(0, 4)).toEqual(new Uint8Array(ENVELOPE_MAGIC_BYTES));
      // Version (1B)
      expect(aad1[4]).toBe(0x01);
      // Purpose (1B)
      expect(aad1[5]).toBe(EnvelopePurpose.CREDENTIAL);
      // KeyID (16B)
      expect(aad1.slice(6, 22)).toEqual(keyId);

      // Ciphertext length Little-Endian (4B)
      const view = new DataView(aad1.buffer, aad1.byteOffset, aad1.byteLength);
      expect(view.getUint32(22, true)).toBe(1024);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. Key Wrapping (keyWrap.ts)
  // ---------------------------------------------------------------------------
  describe('Key Wrapping (keyWrap.ts)', () => {
    it('constructs key wrap AAD correctly (19 bytes)', () => {
      const keyId = generateKeyId();
      const kdfVersion = 0x0113;
      const aad = buildKeyWrapAAD(keyId, kdfVersion);

      expect(aad.length).toBe(KEY_WRAP_AAD_BYTE_LENGTH); // 19 bytes
      expect(aad[0]).toBe(KEY_WRAP_PURPOSE_BYTE); // 0x57 ('W')
      expect(aad.slice(1, 17)).toEqual(keyId);

      const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);
      expect(view.getUint16(17, true)).toBe(0x0113);
    });

    it('wraps and unwraps DEK round-trip', () => {
      const kek = generateSecureRandom(KEK_BYTE_LENGTH);
      const dek = generateDEK();
      const keyId = generateKeyId();
      const kdfVersion = 1;

      const wrapped = wrapDEK(kek, dek, keyId, kdfVersion);
      expect(wrapped.keyId).toBe(bytesToHex(keyId));
      expect(wrapped.wrappedCiphertext.length).toBe(32);
      expect(wrapped.nonce.length).toBe(12);
      expect(wrapped.tag.length).toBe(16);
      expect(wrapped.keyVersion).toBe(1);
      expect(wrapped.status).toBe(KeyStatus.ACTIVE);

      const unwrapped = unwrapDEK(kek, wrapped);
      expect(unwrapped).toEqual(dek);
    });

    it('fails unwrapping DEK when wrong KEK is used', () => {
      const kek1 = generateSecureRandom(KEK_BYTE_LENGTH);
      const kek2 = generateSecureRandom(KEK_BYTE_LENGTH);
      const dek = generateDEK();
      const keyId = generateKeyId();

      const wrapped = wrapDEK(kek1, dek, keyId, 1);

      expect(() => unwrapDEK(kek2, wrapped)).toThrow(GhostTagError);
      try {
        unwrapDEK(kek2, wrapped);
      } catch (err) {
        expect((err as GhostTagError).code).toBe(GhostTagErrorCode.GCM_AUTH_FAILED);
      }
    });

    it('fails unwrapping DEK when wrapped ciphertext is tampered', () => {
      const kek = generateSecureRandom(KEK_BYTE_LENGTH);
      const dek = generateDEK();
      const keyId = generateKeyId();
      const wrapped = wrapDEK(kek, dek, keyId, 1);

      const tampered = {
        ...wrapped,
        wrappedCiphertext: new Uint8Array(wrapped.wrappedCiphertext),
      };
      tampered.wrappedCiphertext[0] ^= 0xff;

      expect(() => unwrapDEK(kek, tampered)).toThrow(GhostTagError);
    });

    it('hex conversion helper converts correctly', () => {
      const raw = new Uint8Array([0x00, 0x0f, 0x10, 0xaa, 0xff]);
      const hex = bytesToHex(raw);
      expect(hex).toBe('000f10aaff');
      expect(hexToBytes(hex)).toEqual(raw);
    });
  });

  // ---------------------------------------------------------------------------
  // 5. Secure Memory Zeroization (secureMemory.ts)
  // ---------------------------------------------------------------------------
  describe('Secure Memory (secureMemory.ts)', () => {
    it('zeroizes a single buffer', () => {
      const buf = new Uint8Array([1, 2, 3, 4, 255]);
      zeroize(buf);
      expect(buf).toEqual(new Uint8Array(5));
      for (let i = 0; i < buf.length; i++) {
        expect(buf[i]).toBe(0);
      }
    });

    it('zeroizes multiple buffers including null and undefined', () => {
      const b1 = new Uint8Array([42, 43]);
      const b2 = new Uint8Array([99, 100, 101]);
      zeroizeAll(b1, null, b2, undefined);

      expect(b1).toEqual(new Uint8Array(2));
      expect(b2).toEqual(new Uint8Array(3));
    });
  });

  // ---------------------------------------------------------------------------
  // 6. Argon2id KDF & Device Tier Calibration (argon2.ts)
  // ---------------------------------------------------------------------------
  describe('Argon2id KDF (argon2.ts)', () => {
    it('validates correct KDF parameters', () => {
      const validParams: KDFParams = {
        salt: generateSalt(),
        memoryCost: 32768,
        timeCost: 3,
        parallelism: 2,
        version: 0x13,
      };
      expect(validateParams(validParams)).toBe(true);
    });

    it('rejects invalid KDF parameters', () => {
      const salt = generateSalt();

      // Salt too short (< 8 bytes)
      expect(
        validateParams({
          salt: new Uint8Array(4),
          memoryCost: 32768,
          timeCost: 3,
          parallelism: 2,
          version: 0x13,
        })
      ).toBe(false);

      // Parallelism < 1
      expect(
        validateParams({
          salt,
          memoryCost: 32768,
          timeCost: 3,
          parallelism: 0,
          version: 0x13,
        })
      ).toBe(false);

      // Memory < 8 * parallelism
      expect(
        validateParams({
          salt,
          memoryCost: 15,
          timeCost: 3,
          parallelism: 2,
          version: 0x13,
        })
      ).toBe(false);

      // Time cost < 1
      expect(
        validateParams({
          salt,
          memoryCost: 32768,
          timeCost: 0,
          parallelism: 2,
          version: 0x13,
        })
      ).toBe(false);

      // Unsupported version
      expect(
        validateParams({
          salt,
          memoryCost: 32768,
          timeCost: 3,
          parallelism: 2,
          version: 0x99,
        })
      ).toBe(false);
    });

    it('detects parameter downgrades accurately', () => {
      const current: KDFParams = {
        salt: generateSalt(),
        memoryCost: 32768,
        timeCost: 3,
        parallelism: 2,
        version: 0x13,
      };

      // Lower memory is a downgrade
      expect(
        checkParamDowngrade(current, {
          ...current,
          memoryCost: 16384,
        })
      ).toBe(true);

      // Lower time cost is a downgrade
      expect(
        checkParamDowngrade(current, {
          ...current,
          timeCost: 2,
        })
      ).toBe(true);

      // Lower parallelism is a downgrade
      expect(
        checkParamDowngrade(current, {
          ...current,
          parallelism: 1,
        })
      ).toBe(true);

      // Equal or higher parameters are not a downgrade
      expect(checkParamDowngrade(current, current)).toBe(false);
      expect(
        checkParamDowngrade(current, {
          ...current,
          memoryCost: 65536,
          timeCost: 4,
          parallelism: 4,
        })
      ).toBe(false);
    });

    it('returns default parameters for each device tier with a fresh salt', () => {
      const high = getDefaultParams(DeviceTier.HIGH_END);
      const std = getDefaultParams(DeviceTier.STANDARD);
      const low = getDefaultParams(DeviceTier.LOW_END);

      expect(high.memoryCost).toBe(65536);
      expect(std.memoryCost).toBe(32768);
      expect(low.memoryCost).toBe(16384);

      expect(high.salt.length).toBe(16);
      expect(std.salt.length).toBe(16);
      expect(low.salt.length).toBe(16);
    });

    it('derives a 32-byte KEK deterministically', async () => {
      const salt = generateSalt();
      const params = getDefaultParams(DeviceTier.STANDARD);
      (params as any).salt = salt;

      const kek1 = await deriveKEK('master-passphrase-alpha', salt, params);
      const kek2 = await deriveKEK('master-passphrase-alpha', salt, params);

      expect(kek1.length).toBe(32);
      expect(kek2.length).toBe(32);
      expect(kek1).toEqual(kek2);

      // Different passphrase produces different key
      const kek3 = await deriveKEK('master-passphrase-beta', salt, params);
      expect(kek1).not.toEqual(kek3);
    });

    it('rejects derivation with missing or empty passphrase', async () => {
      const salt = generateSalt();
      const params = getDefaultParams(DeviceTier.STANDARD);

      await expect(deriveKEK('', salt, params)).rejects.toThrow(GhostTagError);
      try {
        await deriveKEK('', salt, params);
      } catch (err) {
        expect((err as GhostTagError).code).toBe(GhostTagErrorCode.PASSPHRASE_REQUIRED);
      }
    });

    it('warns when derivation completes in under 100ms', async () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const salt = generateSalt();
      const params = getDefaultParams(DeviceTier.LOW_END);
      (params as any).salt = salt;

      await deriveKEK('quick-pass', salt, params);
      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('< 100ms minimum recommended')
      );
    });

    it('benchmarks device and returns a valid DeviceTier', async () => {
      const tier = await benchmarkDevice();
      expect([DeviceTier.HIGH_END, DeviceTier.STANDARD, DeviceTier.LOW_END]).toContain(tier);
    });
  });
});

