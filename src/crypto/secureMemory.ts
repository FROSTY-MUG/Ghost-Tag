/**
 * @file secureMemory.ts
 * @summary Secure memory erasure and zeroization utilities.
 *
 * Provides multi-pass zeroization and sanitization of sensitive cryptographic buffers in memory.
 */

export {
  zeroize,
  zeroizeAll,
  secureWipeBuffer,
  secureWipeBuffers,
  secureWipeObject,
} from '../security/secureWipe';
