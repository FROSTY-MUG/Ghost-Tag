/**
 * @file secureMemory.ts
 * @summary Secure memory erasure and zeroization utilities.
 *
 * Provides best-effort zeroization of sensitive cryptographic buffers in memory.
 * Note: While this explicitly clears the underlying TypedArray memory buffer,
 * the JavaScript garbage collector and V8 engine optimizations may retain transient
 * copies in heap memory.
 */

/**
 * Best-effort zeroization of a sensitive byte array.
 * Overwrites all elements in the buffer with zeros.
 *
 * @param buffer Uint8Array containing sensitive material to overwrite.
 */
export function zeroize(buffer?: Uint8Array | null): void {
  if (buffer && buffer instanceof Uint8Array && buffer.length > 0) {
    buffer.fill(0);
  }
}

/**
 * Best-effort zeroization of multiple sensitive byte arrays.
 * Safely ignores null or undefined arguments.
 *
 * @param buffers Array of Uint8Arrays to zeroize.
 */
export function zeroizeAll(...buffers: (Uint8Array | null | undefined)[]): void {
  for (const buf of buffers) {
    zeroize(buf);
  }
}

