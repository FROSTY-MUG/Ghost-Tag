/**
 * @file index.ts
 * @summary Ghost-Tag v2.0.5 Core Protocol & Client SDK
 * 
 * Hardware-anchored encrypted NFC distributed vault, binary envelope codecs (GTAG),
 * zero-knowledge Supabase sync, and BIP-39 recovery identity.
 */

// Contracts
export * from './contracts/bulkEnvelope';
export * from './contracts/bulkVault';
export * from './contracts/errors';
export * from './contracts/keyHierarchy';
export * from './contracts/recovery';

// Cryptography & Envelopes
export * from './crypto/bulkEnvelope';
export * from './crypto/aesGcm';
export * from './crypto/keyWrap';

// Cloud Sync
export * from './cloud/supabaseClient';

// Operations & Entry Management
export * from './operations/deleteEntryOperation';
