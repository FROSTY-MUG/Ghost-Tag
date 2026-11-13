/**
 * @file index.ts
 * @summary Ghost-Tag Local Encrypted Vault Barrel Export.
 *
 * Re-exports all components of Phase 3:
 * - VaultDatabase (at-rest encrypted storage via MMKV)
 * - VaultManager (lifecycle, initialization, unlock, metadata)
 * - VaultSession (session management, auto-lock, volatile KEK zeroization)
 * - DEKManager (DEK generation, key wrapping, rotation, revocation)
 * - RecoveryManager (24-word BIP39 recovery phrase, envelope wrapping, emergency restore)
 * - VaultManifest (HMAC-SHA-256 metadata authentication and tamper detection)
 * - AuditLog (tamper-evident hash-chained operational audit trail)
 * - BIP39 English Wordlist dictionary and validation utilities
 */

export * from './database';
export * from './vaultManager';
export * from './session';
export * from './dekManager';
export * from './recoveryManager';
export * from './manifest';
export * from './auditLog';
export * from './wordlist';
export * from './chunkCache';
export * from './journalManager';
export * from './bulkVaultManager';

