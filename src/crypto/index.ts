/**
 * @file index.ts
 * @summary Ghost-Tag Cryptographic Core Barrel Export.
 *
 * Exports all cryptographic primitives, CSPRNG abstractions, KDF routines,
 * AEAD symmetric encryption, envelope serialization/parsing, key wrapping,
 * and secure memory zeroization helpers.
 */

export * from './random';
export * from './argon2';
export * from './aesGcm';
export * from './envelope';
export * from './keyWrap';
export * from './secureMemory';
export * from './bulkEnvelope';
export * from './erasureCoding';
export * from './fileEncryption';
export * from './wrappedDekCodec';

