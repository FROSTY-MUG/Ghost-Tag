/**
 * @file wrappedDekCodec.ts
 * @summary Canonical 78-byte binary serializer and deserializer for WrappedDEK records.
 *
 * Binary Wire Layout (78 bytes total):
 *   - Bytes  0..15 (16B): keyId bytes (lowercase 32-hex keyId)
 *   - Bytes 16..17  (2B): kdfVersion uint16 little-endian
 *   - Bytes 18..29 (12B): AES-256-GCM nonce
 *   - Bytes 30..45 (16B): AES-256-GCM auth tag
 *   - Bytes 46..77 (32B): AES-256-GCM wrappedCiphertext
 *
 * Preserves exact 19-byte Primary Key Wrap AAD:
 *   0x57 || keyId (16B) || kdfVersion (2B LE)
 * as defined by `wrapDEK` / `unwrapDEK` in `./keyWrap`.
 */

import { KeyStatus, WrappedDEK } from '../contracts/keyHierarchy';
import { unwrapDEK, wrapDEK } from './keyWrap';

export const WRAPPED_DEK_WIRE_SIZE = 78;
export const WRAPPED_DEK_KEY_ID_BYTES = 16;
export const WRAPPED_DEK_VERSION_BYTES = 2;
export const WRAPPED_DEK_NONCE_BYTES = 12;
export const WRAPPED_DEK_TAG_BYTES = 16;
export const WRAPPED_DEK_CIPHERTEXT_BYTES = 32;

const HEX32_REGEX = /^[0-9a-fA-F]{32}$/;

/**
 * Converts a 32-character hex keyId into a 16-byte Uint8Array.
 */
export function keyIdHexToBytes(keyIdHex: string): Uint8Array {
  if (!HEX32_REGEX.test(keyIdHex)) {
    throw new Error('keyId must be exactly 32 hexadecimal characters (16 bytes)');
  }
  const bytes = new Uint8Array(WRAPPED_DEK_KEY_ID_BYTES);
  for (let i = 0; i < WRAPPED_DEK_KEY_ID_BYTES; i++) {
    bytes[i] = parseInt(keyIdHex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Converts a 16-byte Uint8Array into a lowercase 32-character hex keyId string.
 */
export function bytesToKeyIdHex(bytes: Uint8Array): string {
  if (bytes.length !== WRAPPED_DEK_KEY_ID_BYTES) {
    throw new Error('keyId bytes must be exactly 16 bytes');
  }
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Serializes a WrappedDEK struct + kdfVersion into the canonical 78-byte wire format.
 * Bytes 0..15 match `key_id` for PostgreSQL `chk_vm_wrapped_dek_prefix` verification.
 */
export function serializeWrappedDEK(
  wrapped: WrappedDEK,
  kdfVersion?: number
): Uint8Array {
  const version = kdfVersion ?? wrapped.keyVersion;
  if (!Number.isInteger(version) || version < 1 || version > 65535) {
    throw new Error('kdfVersion must be an integer between 1 and 65535');
  }

  const keyIdBytes = keyIdHexToBytes(wrapped.keyId);
  if (wrapped.nonce.length !== WRAPPED_DEK_NONCE_BYTES) {
    throw new Error('WrappedDEK nonce must be exactly 12 bytes');
  }
  if (wrapped.tag.length !== WRAPPED_DEK_TAG_BYTES) {
    throw new Error('WrappedDEK tag must be exactly 16 bytes');
  }
  if (wrapped.wrappedCiphertext.length !== WRAPPED_DEK_CIPHERTEXT_BYTES) {
    throw new Error('WrappedDEK wrappedCiphertext must be exactly 32 bytes');
  }

  const out = new Uint8Array(WRAPPED_DEK_WIRE_SIZE);
  out.set(keyIdBytes, 0);
  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  view.setUint16(16, version, true); // little-endian matches 19B AAD
  out.set(wrapped.nonce, 18);
  out.set(wrapped.tag, 30);
  out.set(wrapped.wrappedCiphertext, 46);
  return out;
}

/**
 * Deserializes a canonical 78-byte wire record back into a WrappedDEK struct.
 */
export function deserializeWrappedDEK(
  wireBytes: Uint8Array,
  status: KeyStatus = KeyStatus.ACTIVE,
  creationTime = 0
): WrappedDEK {
  if (!(wireBytes instanceof Uint8Array) || wireBytes.length !== WRAPPED_DEK_WIRE_SIZE) {
    throw new Error(`Serialized WrappedDEK must be exactly ${WRAPPED_DEK_WIRE_SIZE} bytes`);
  }

  const keyIdBytes = wireBytes.slice(0, 16);
  const view = new DataView(wireBytes.buffer, wireBytes.byteOffset, wireBytes.byteLength);
  const kdfVersion = view.getUint16(16, true);
  if (kdfVersion < 1) {
    throw new Error('Serialized WrappedDEK kdfVersion must be >= 1');
  }

  return {
    keyId: bytesToKeyIdHex(keyIdBytes),
    nonce: wireBytes.slice(18, 30),
    tag: wireBytes.slice(30, 46),
    wrappedCiphertext: wireBytes.slice(46, 78),
    creationTime,
    keyVersion: kdfVersion,
    status,
  };
}

/**
 * Wraps a 32-byte DEK under a 32-byte KEK using canonical 19B `0x57` AAD
 * and returns the 78-byte canonical binary representation.
 */
export function wrapAndSerializeDEK(
  kek: Uint8Array,
  dek: Uint8Array,
  keyIdBytes: Uint8Array,
  kdfVersion: number
): Uint8Array {
  const wrapped = wrapDEK(kek, dek, keyIdBytes, kdfVersion);
  return serializeWrappedDEK(wrapped, kdfVersion);
}

/**
 * Deserializes a canonical 78-byte record and unwraps the 32-byte DEK using
 * canonical 19B `0x57` AAD verification.
 */
export function deserializeAndUnwrapDEK(
  kek: Uint8Array,
  wireBytes: Uint8Array
): Uint8Array {
  const wrapped = deserializeWrappedDEK(wireBytes);
  return unwrapDEK(kek, wrapped);
}
