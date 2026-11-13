/**
 * @file secureWipe.ts
 * @summary Military-grade, multi-pass memory wiping and zeroization utilities.
 *
 * Provides defense-in-depth memory scrubbing against heap inspection, cold-boot attacks,
 * and memory dumps. Overwrites sensitive buffers with alternating bit patterns (0xAA, 0x55),
 * cryptographically secure random bytes, and final zeroes.
 */

import QuickCrypto from 'react-native-quick-crypto';

/**
 * Performs a rigorous 4-pass memory overwrite on a sensitive byte array:
 * 1. Pass 1: Pattern 0xAA (10101010 binary)
 * 2. Pass 2: Pattern 0x55 (01010101 binary)
 * 3. Pass 3: Cryptographically secure random byte stream
 * 4. Pass 4: Zeroization 0x00 (00000000 binary)
 *
 * @param buffer Uint8Array containing sensitive material to overwrite.
 */
export function secureWipeBuffer(buffer?: Uint8Array | null): void {
  if (!buffer || !(buffer instanceof Uint8Array) || buffer.length === 0) {
    return;
  }

  const length = buffer.length;

  // Pass 1: Alternating bits 0xAA (10101010)
  buffer.fill(0xaa);

  // Pass 2: Inverted alternating bits 0x55 (01010101)
  buffer.fill(0x55);

  // Pass 3: High-entropy random data to disrupt residual charge / memory remnants
  try {
    const randomBytes = QuickCrypto.randomBytes(length);
    buffer.set(randomBytes);
  } catch {
    // Fallback pseudo-random pattern if crypto provider fails during emergency teardown
    for (let i = 0; i < length; i++) {
      buffer[i] = (Math.random() * 256) | 0;
    }
  }

  // Pass 4: Final complete zeroization
  buffer.fill(0x00);
}

/**
 * Wipes multiple sensitive buffers in sequence.
 *
 * @param buffers List of buffers to securely overwrite.
 */
export function secureWipeBuffers(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buf of buffers) {
    secureWipeBuffer(buf);
  }
}

/**
 * Recursively inspects and wipes any Uint8Array properties on an object.
 * Useful for tearing down session state or key envelope structures.
 *
 * @param target Object whose buffer properties should be wiped.
 */
export function secureWipeObject(target?: Record<string, unknown> | null): void {
  if (!target || typeof target !== 'object') {
    return;
  }

  for (const key of Object.keys(target)) {
    const value = target[key];
    if (value instanceof Uint8Array) {
      secureWipeBuffer(value);
      target[key] = null as unknown;
    } else if (Array.isArray(value)) {
      for (const item of value) {
        if (item instanceof Uint8Array) {
          secureWipeBuffer(item);
        } else if (item && typeof item === 'object') {
          secureWipeObject(item as Record<string, unknown>);
        }
      }
    } else if (value && typeof value === 'object') {
      secureWipeObject(value as Record<string, unknown>);
    }
  }
}

/**
 * Standard single-pass zeroization compatible with existing crypto routines.
 *
 * @param buffer Buffer to zero-fill.
 */
export function zeroize(buffer?: Uint8Array | null): void {
  secureWipeBuffer(buffer);
}

/**
 * Standard single-pass zeroization for multiple buffers.
 *
 * @param buffers Buffers to zero-fill.
 */
export function zeroizeAll(...buffers: (Uint8Array | null | undefined)[]): void {
  secureWipeBuffers(...buffers);
}
