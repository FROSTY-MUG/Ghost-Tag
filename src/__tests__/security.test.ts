/**
 * @file security.test.ts
 * @summary Unit and Integration Tests for Strict Security, Anti-Tamper, and Anti-Leak Subsystems.
 */

import {
  secureWipeBuffer,
  secureWipeBuffers,
  secureWipeObject,
  zeroize,
  zeroizeAll,
  redactSensitiveData,
  timingSafeEqual,
  sanitizeError,
  SanitizedLogger,
  checkDeviceIntegrity,
  assertDeviceIntegrity,
  setTestIntegrityOverride,
  DeviceIntegrityStatus,
} from '../security';
import {
  GhostTagError,
  GhostTagErrorCode,
  ErrorCategory,
  ErrorSeverity,
} from '../contracts/errors';
import { VaultSession } from '../vault/session';

describe('Strict Security & Memory Protection', () => {
  afterEach(() => {
    // Reset any test overrides after each test
    setTestIntegrityOverride(null);
  });

  describe('secureWipeBuffer & secureWipeBuffers', () => {
    it('wipes a sensitive byte buffer completely with zeros', () => {
      const buffer = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      secureWipeBuffer(buffer);

      for (let i = 0; i < buffer.length; i++) {
        expect(buffer[i]).toBe(0);
      }
    });

    it('handles null, undefined, and empty buffers gracefully', () => {
      expect(() => secureWipeBuffer(null)).not.toThrow();
      expect(() => secureWipeBuffer(undefined)).not.toThrow();
      expect(() => secureWipeBuffer(new Uint8Array(0))).not.toThrow();
    });

    it('wipes multiple buffers in a single invocation', () => {
      const b1 = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
      const b2 = new Uint8Array([0xca, 0xfe, 0xba, 0xbe]);
      secureWipeBuffers(b1, null, b2);

      expect(Array.from(b1)).toEqual([0, 0, 0, 0]);
      expect(Array.from(b2)).toEqual([0, 0, 0, 0]);
    });

    it('recursively scrubs Uint8Array properties in an object', () => {
      const state = {
        key: new Uint8Array([0x11, 0x22, 0x33]),
        nested: {
          secret: new Uint8Array([0x44, 0x55, 0x66]),
          metadata: 'public_string',
        },
        list: [new Uint8Array([0x77, 0x88])],
      };

      const keyRef = state.key;
      const secretRef = state.nested.secret;
      const listRef = state.list[0];

      secureWipeObject(state);

      expect(Array.from(keyRef)).toEqual([0, 0, 0]);
      expect(Array.from(secretRef)).toEqual([0, 0, 0]);
      expect(Array.from(listRef)).toEqual([0, 0]);
      expect(state.key).toBeNull();
      expect(state.nested.metadata).toBe('public_string');
    });

    it('provides backward-compatible zeroize and zeroizeAll aliases', () => {
      const b1 = new Uint8Array([1, 2]);
      const b2 = new Uint8Array([3, 4]);

      zeroize(b1);
      zeroizeAll(b2);

      expect(Array.from(b1)).toEqual([0, 0]);
      expect(Array.from(b2)).toEqual([0, 0]);
    });
  });

  describe('timingSafeEqual', () => {
    it('returns true for identical byte arrays', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 5]);
      expect(timingSafeEqual(a, b)).toBe(true);
    });

    it('returns false for different byte values', () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 6]);
      expect(timingSafeEqual(a, b)).toBe(false);
    });

    it('returns false for mismatched lengths', () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);
      expect(timingSafeEqual(a, b)).toBe(false);
    });

    it('returns false for invalid non-Uint8Array inputs', () => {
      expect(timingSafeEqual(null as any, new Uint8Array([1]))).toBe(false);
      expect(timingSafeEqual(new Uint8Array([1]), 'invalid' as any)).toBe(false);
    });
  });

  describe('Anti-Leak Protection & Redaction', () => {
    it('redacts 64-character hex keys and hash digests', () => {
      const rawText =
        'Generated master key: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 in memory.';
      const clean = redactSensitiveData(rawText);

      expect(clean).toContain('[REDACTED_256BIT_SECRET]');
      expect(clean).not.toContain('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    });

    it('redacts 32-character hex IVs and nonces', () => {
      const rawText = 'Nonce used: 0123456789abcdef0123456789abcdef for AES-GCM.';
      const clean = redactSensitiveData(rawText);

      expect(clean).toContain('[REDACTED_128BIT_BUFFER]');
      expect(clean).not.toContain('0123456789abcdef0123456789abcdef');
    });

    it('sanitizes GhostTagError messages and technical details', () => {
      const error = new GhostTagError({
        code: GhostTagErrorCode.ARGON2ID_FAILED,
        userMessage: 'Key 11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff failed.',
        technicalDetail: 'Hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 mismatch.',
        category: ErrorCategory.CRYPTO,
        severity: ErrorSeverity.ERROR,
      });

      const sanitized = sanitizeError(error) as GhostTagError;
      expect(sanitized.userMessage).toContain('[REDACTED_256BIT_SECRET]');
      expect(sanitized.technicalDetail).toContain('[REDACTED_256BIT_SECRET]');
    });

    it('SanitizedLogger scrubs outputs before emitting', () => {
      const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
      const logger = new SanitizedLogger('CryptoAudit');

      logger.warn(
        'Potential leak of KEK: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
      );

      expect(warnSpy).toHaveBeenCalledWith(
        expect.stringContaining('[REDACTED_256BIT_SECRET]')
      );
      warnSpy.mockRestore();
    });
  });

  describe('Device Integrity Enforcement & Fail-Closed Guard', () => {
    it('passes assertion when device is secure and untampered', async () => {
      const cleanStatus: DeviceIntegrityStatus = {
        isSecure: true,
        isDebuggerActive: false,
        isHooked: false,
        isRooted: false,
        isEmulator: false,
        isSignatureValid: true,
        tamperIndicators: [],
      };
      setTestIntegrityOverride(cleanStatus);

      await expect(assertDeviceIntegrity()).resolves.toBeUndefined();
    });

    it('fails closed and zeroes sensitive buffers when a debugger is active', async () => {
      const debuggerStatus: DeviceIntegrityStatus = {
        isSecure: false,
        isDebuggerActive: true,
        isHooked: false,
        isRooted: false,
        isEmulator: false,
        isSignatureValid: true,
        tamperIndicators: ['PTRACE_ATTACH_DETECTED'],
      };
      setTestIntegrityOverride(debuggerStatus);

      const secretBuffer = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]);

      await expect(assertDeviceIntegrity(secretBuffer)).rejects.toThrow(
        /Security violation: Debugger detected/
      );

      // Sensitive buffer must have been scrubbed upon violation
      expect(Array.from(secretBuffer)).toEqual([0, 0, 0, 0]);
    });

    it('fails closed when hooking framework (Frida/Xposed) is detected', async () => {
      const hookedStatus: DeviceIntegrityStatus = {
        isSecure: false,
        isDebuggerActive: false,
        isHooked: true,
        isRooted: false,
        isEmulator: false,
        isSignatureValid: true,
        tamperIndicators: ['HOOK_LIB_frida-agent'],
      };
      setTestIntegrityOverride(hookedStatus);

      try {
        await assertDeviceIntegrity();
        fail('Should have thrown an integrity error');
      } catch (err: any) {
        expect(err.code).toBe(GhostTagErrorCode.HOOKING_DETECTED);
        expect(err.category).toBe(ErrorCategory.SECURITY);
        expect(err.severity).toBe(ErrorSeverity.FATAL);
      }
    });

    it('fails closed when root privilege escalation is detected', async () => {
      const rootedStatus: DeviceIntegrityStatus = {
        isSecure: false,
        isDebuggerActive: false,
        isHooked: false,
        isRooted: true,
        isEmulator: false,
        isSignatureValid: true,
        tamperIndicators: ['SU_BINARY_/system/bin/su'],
      };
      setTestIntegrityOverride(rootedStatus);

      try {
        await assertDeviceIntegrity();
        fail('Should have thrown an integrity error');
      } catch (err: any) {
        expect(err.code).toBe(GhostTagErrorCode.ROOT_DETECTED);
        expect(err.category).toBe(ErrorCategory.SECURITY);
      }
    });

    it('aborts VaultSession unlock when device integrity is compromised', async () => {
      const compromisedStatus: DeviceIntegrityStatus = {
        isSecure: false,
        isDebuggerActive: true,
        isHooked: false,
        isRooted: false,
        isEmulator: false,
        isSignatureValid: true,
        tamperIndicators: ['TRACER_PID_ACTIVE'],
      };
      setTestIntegrityOverride(compromisedStatus);

      const dummyHandler = jest.fn().mockResolvedValue(new Uint8Array(32).fill(0x77));
      const session = new VaultSession(null, dummyHandler);

      await expect(session.unlock('test-passphrase')).rejects.toThrow(
        /Security violation: Debugger detected/
      );
      expect(session.isUnlocked).toBe(false);
      expect(dummyHandler).not.toHaveBeenCalled();
    });
  });
});

