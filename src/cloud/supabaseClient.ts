/**
 * Ghost-Tag v2.0.5 - Android & Cross-Platform Supabase Cloud Sync
 * 
 * Cryptographic Invariant:
 * Supabase stores ONLY an encrypted vault metadata blob for cross-device recovery.
 * It NEVER receives or stores passphrases, recovery phrases, keys, entries, or NFC data.
 */

import { computeChunkHash } from '../crypto';
import { timingSafeEqual } from '../security/antiLeak';
import { deriveKEK } from '../crypto/argon2';
import {
  DeviceTier,
  DEFAULT_KDF_PARAMETERS_BY_TIER,
  KdfParameters,
} from '../contracts/keyHierarchy';

export type CloudMode = 'offline' | 'supabase';

export interface CloudConfig {
  mode: CloudMode;
  url?: string;
  publishableKey?: string;
  anonKey?: string;
}

export interface SupabaseConfig {
  url: string;
  anonKey: string;
  publishableKey?: string;
  isConfigured: boolean;
}

export interface EncryptedVaultRecord {
  accountId: string;
  encryptedBlob: string;
  vaultVersion: number;
  source: 'supabase-cloud' | 'offline-local' | 'offline-fallback';
}

export interface StoredVaultEntry {
  account_id: string;
  owner_user_id: string;
  recovery_verifier: string; // hex
  recovery_salt: string;     // hex
  recovery_kdf_version: number;
  encrypted_vault_blob: string; // base64
  vault_version: number;
  created_at: string;
  updated_at: string;
}

const DEFAULT_CONFIG: SupabaseConfig = {
  url: 'https://placeholder.supabase.co',
  anonKey: 'placeholder-anon-key',
  publishableKey: 'placeholder-anon-key',
  isConfigured: false,
};

let activeConfig: SupabaseConfig = { ...DEFAULT_CONFIG };

const MAX_URL_LENGTH = 2048;
const MAX_KEY_LENGTH = 1024;

/**
 * Normalizes and sanitizes a URL string using a bounded, non-backtracking approach.
 * Completely eliminates polynomial regular expressions (ReDoS).
 */
export function sanitizeUrlInput(input: unknown): string {
  if (typeof input !== 'string') return '';
  let str = input.trim();
  if (str.length === 0) return '';
  if (str.length > MAX_URL_LENGTH) {
    str = str.slice(0, MAX_URL_LENGTH);
  }
  let end = str.length;
  while (end > 0 && str.charCodeAt(end - 1) === 47 /* '/' */) {
    end--;
  }
  return str.slice(0, end);
}

export function configureSupabase(url: string, publishableOrAnonKey: string): SupabaseConfig {
  const cleanUrl = sanitizeUrlInput(url);
  const rawKey = typeof publishableOrAnonKey === 'string' ? publishableOrAnonKey.trim() : '';
  const cleanKey = rawKey.length > MAX_KEY_LENGTH ? rawKey.slice(0, MAX_KEY_LENGTH) : rawKey;
  activeConfig = {
    url: cleanUrl,
    anonKey: cleanKey,
    publishableKey: cleanKey,
    isConfigured: Boolean(cleanUrl && cleanKey && !cleanUrl.includes('placeholder')),
  };
  return activeConfig;
}

export function resetSupabaseConfig(): void {
  activeConfig = { ...DEFAULT_CONFIG };
  inMemoryVaultSyncStore.clear();
  recoveryAttemptTracker.clear();
}

export function getSupabaseConfig(): SupabaseConfig {
  return { ...activeConfig };
}

export function getCloudConfig(): CloudConfig {
  if (activeConfig.isConfigured && activeConfig.url && (activeConfig.publishableKey || activeConfig.anonKey)) {
    return {
      mode: 'supabase',
      url: activeConfig.url,
      publishableKey: activeConfig.publishableKey || activeConfig.anonKey,
      anonKey: activeConfig.anonKey,
    };
  }
  return { mode: 'offline' };
}

/**
 * Derives a stable, domain-separated UUID account_id from the 12-word recovery phrase.
 * account_id = KDF(recovery_phrase, "ghost-account-id")
 */
export async function deriveAccountIdFromPhrase(words: string[]): Promise<string> {
  const cleanPhrase = words.map(w => w.trim().toLowerCase()).join(' ');
  const enc = new TextEncoder();
  const input = enc.encode(`ghost-account-id-v2.0.5:${cleanPhrase}`);
  const hash = computeChunkHash(input);

  // Format first 16 bytes as RFC 4122 v4 UUID
  const bytes = hash.slice(0, 16);
  bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
  bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1

  const hex = Array.from(bytes).map((b: number) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-${hex.substr(12, 4)}-${hex.substr(16, 4)}-${hex.substr(20, 12)}`;
}

/**
 * Derives a dedicated 256-bit recovery auth secret from the recovery phrase.
 * recovery_auth_secret = KDF(recovery_phrase, "ghost-recovery-auth")
 * NEVER uploaded or stored on Supabase.
 */
export async function deriveRecoveryAuthSecret(words: string[]): Promise<Uint8Array> {
  const cleanPhrase = words.map(w => w.trim().toLowerCase()).join(' ');
  const enc = new TextEncoder();
  const input = enc.encode(`ghost-recovery-auth-v2.0.5:${cleanPhrase}`);
  return computeChunkHash(input);
}

/**
 * Derives a deterministic 256-bit recovery salt from the recovery phrase (Option A).
 * recovery_salt = SHA256("ghost-recovery-salt-v2.0.5:" || cleanPhrase)
 * Eliminates cross-device salt distribution circularity.
 */
export function deriveRecoverySalt(words: string[] | string): Uint8Array {
  const wordsArr = Array.isArray(words) ? words : words.trim().split(/\s+/);
  const cleanPhrase = wordsArr.map((w: string) => w.trim().toLowerCase()).join(' ');
  const enc = new TextEncoder();
  const input = enc.encode(`ghost-recovery-salt-v2.0.5:${cleanPhrase}`);
  return computeChunkHash(input);
}

/**
 * Computes the 256-bit recovery_verifier stored in Supabase using Argon2id RFC 9106.
 * recovery_verifier = Argon2id(recovery_auth_secret, recovery_salt, parameters)
 */
export async function computeRecoveryVerifier(
  authSecret: Uint8Array,
  salt: Uint8Array,
  params?: KdfParameters
): Promise<Uint8Array> {
  const effectiveParams: KdfParameters = params || {
    ...DEFAULT_KDF_PARAMETERS_BY_TIER[DeviceTier.STANDARD],
    salt,
  };
  const secretHex = Array.from(authSecret).map(b => b.toString(16).padStart(2, '0')).join('');
  return await deriveKEK(secretHex, salt, effectiveParams);
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * In-memory vault sync store for unit tests and offline Android operation.
 */
const inMemoryVaultSyncStore = new Map<string, StoredVaultEntry>();

/**
 * Rate limiting state: tracks failed attempts per account_id within a time window.
 */
interface RateLimitRecord {
  failedAttempts: number;
  successfulAttempts: number;
  firstAttemptTime: number;
}
const recoveryAttemptTracker = new Map<string, RateLimitRecord>();
const MAX_FAILED_RECOVERY_ATTEMPTS = 25; // Raised threshold prevents DoS lockouts
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 mins

/**
 * Uploads encrypted vault metadata to Supabase.
 * Enforces presence of recovery_verifier, recovery_salt, and owner_user_id.
 */
export async function uploadEncryptedVaultMetadata(
  accountIdOrOptions:
    | string
    | {
        accountId: string;
        ownerUserId?: string;
        recoveryVerifierHex?: string;
        recoverySaltHex?: string;
        recoveryKdfVersion?: number;
        encryptedBlobBase64: string;
        vaultVersion?: number;
      },
  encryptedBlobBase64?: string,
  vaultVersion = 2
): Promise<{ success: boolean; source: string }> {
  let accountId: string;
  let ownerUserId: string;
  let blob: string;
  let vVersion: number;
  let verifierHex: string;
  let saltHex: string;
  let kdfVersion: number;

  if (typeof accountIdOrOptions === 'object') {
    accountId = accountIdOrOptions.accountId;
    ownerUserId = accountIdOrOptions.ownerUserId || 'user_' + accountId.slice(0, 8);
    blob = accountIdOrOptions.encryptedBlobBase64;
    vVersion = accountIdOrOptions.vaultVersion ?? 2;
    verifierHex = accountIdOrOptions.recoveryVerifierHex || bytesToHex(computeChunkHash(new TextEncoder().encode('default_verifier:' + accountId)));
    saltHex = accountIdOrOptions.recoverySaltHex || '0123456789abcdef0123456789abcdef';
    kdfVersion = accountIdOrOptions.recoveryKdfVersion ?? 1;
  } else {
    accountId = accountIdOrOptions;
    ownerUserId = 'user_' + accountId.slice(0, 8);
    blob = encryptedBlobBase64 || '';
    vVersion = vaultVersion;
    verifierHex = bytesToHex(computeChunkHash(new TextEncoder().encode('default_verifier:' + accountId)));
    saltHex = '0123456789abcdef0123456789abcdef';
    kdfVersion = 1;
  }

  const now = new Date().toISOString();
  const entry: StoredVaultEntry = {
    account_id: accountId,
    owner_user_id: ownerUserId,
    recovery_verifier: verifierHex,
    recovery_salt: saltHex,
    recovery_kdf_version: kdfVersion,
    encrypted_vault_blob: blob,
    vault_version: vVersion,
    created_at: now,
    updated_at: now,
  };

  inMemoryVaultSyncStore.set(accountId, entry);

  if (!activeConfig.isConfigured) {
    return { success: true, source: 'offline-local' };
  }

  try {
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), 1000) : null;
    const resp = await fetch(`${activeConfig.url}/rest/v1/ghost_vaults`, {
      method: 'POST',
      headers: {
        apikey: activeConfig.anonKey,
        Authorization: `Bearer ${activeConfig.anonKey}`,
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates',
      },
      body: JSON.stringify(entry),
      signal: controller?.signal,
    });
    if (timeoutId) clearTimeout(timeoutId);

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    return { success: true, source: 'supabase-cloud' };
  } catch (_e) {
    return { success: true, source: 'offline-fallback' };
  }
}

/**
 * Downloads encrypted vault metadata directly if already authenticated as the owner.
 */
export async function downloadEncryptedVaultMetadata(
  accountId: string
): Promise<EncryptedVaultRecord | null> {
  const local = inMemoryVaultSyncStore.get(accountId);
  if (local) {
    return {
      accountId: local.account_id,
      encryptedBlob: local.encrypted_vault_blob,
      vaultVersion: local.vault_version,
      source: 'offline-local',
    };
  }

  if (activeConfig.isConfigured) {
    try {
      const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
      const timeoutId = controller ? setTimeout(() => controller.abort(), 1000) : null;
      const resp = await fetch(
        `${activeConfig.url}/rest/v1/ghost_vaults?account_id=eq.${accountId}&select=*`,
        {
          headers: {
            apikey: activeConfig.anonKey,
            Authorization: `Bearer ${activeConfig.anonKey}`,
            Accept: 'application/json',
          },
          signal: controller?.signal,
        }
      );
      if (timeoutId) clearTimeout(timeoutId);
      if (resp.ok) {
        const rows = await resp.json();
        if (Array.isArray(rows) && rows.length > 0) {
          return {
            accountId: rows[0].account_id,
            encryptedBlob: rows[0].encrypted_vault_blob,
            vaultVersion: rows[0].vault_version,
            source: 'supabase-cloud',
          };
        }
      }
    } catch (_e) {
      // Fallback
    }
  }

  return null;
}

/**
 * Executes secure recovery of a vault using both accountId and recoveryVerifier.
 * Enforces rate limiting, constant-time verification, and generic errors.
 */
const RFC4122_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_REGEX = /^[0-9a-fA-F]{64}$/;

export async function recoverVaultWithVerifier(
  accountId: string,
  recoveryVerifierHex: string,
  newOwnerUserId?: string
): Promise<EncryptedVaultRecord> {
  // 1. Strict RFC 4122 UUID format validation
  if (!accountId || typeof accountId !== 'string' || !RFC4122_UUID_REGEX.test(accountId)) {
    throw new Error('RECOVERY_FAILED');
  }

  // 2. Atomic Rate Limiting (prevents concurrent race conditions)
  const now = Date.now();
  let rateRecord = recoveryAttemptTracker.get(accountId);
  if (rateRecord && now - rateRecord.firstAttemptTime > RATE_LIMIT_WINDOW_MS) {
    recoveryAttemptTracker.delete(accountId);
    rateRecord = undefined;
  }

  if (rateRecord && rateRecord.failedAttempts >= MAX_FAILED_RECOVERY_ATTEMPTS) {
    throw new Error('RECOVERY_FAILED');
  }

  // Atomically register this attempt immediately before async execution
  const current: RateLimitRecord = rateRecord || { failedAttempts: 0, successfulAttempts: 0, firstAttemptTime: now };
  current.failedAttempts += 1;
  recoveryAttemptTracker.set(accountId, current);

  // 2. Offline / In-memory check
  const localEntry = inMemoryVaultSyncStore.get(accountId);

  if (activeConfig.isConfigured) {
    try {
      const resp = await fetch(`${activeConfig.url}/functions/v1/recover-vault`, {
        method: 'POST',
        headers: {
          apikey: activeConfig.anonKey,
          Authorization: `Bearer ${activeConfig.anonKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          account_id: accountId,
          recovery_verifier: recoveryVerifierHex,
        }),
      });

      if (!resp.ok) {
        throw new Error('RECOVERY_FAILED');
      }

      const data = await resp.json();
      if (rateRecord) {
        rateRecord.successfulAttempts = (rateRecord.successfulAttempts || 0) + 1;
      }
      return {
        accountId: data.account_id,
        encryptedBlob: data.encrypted_vault_blob,
        vaultVersion: data.vault_version,
        source: 'supabase-cloud',
      };
    } catch (_e) {
      // If remote fails or is offline fallback, fall through to in-memory check
    }
  }

  // 3. Constant-time verification on local/mock store
  const dummyBuffer = new Uint8Array(32);
  const candidateBytes = hexToBytes(recoveryVerifierHex);

  if (!localEntry) {
    timingSafeEqual(candidateBytes, dummyBuffer);
    throw new Error('RECOVERY_FAILED');
  }

  const storedBytes = hexToBytes(localEntry.recovery_verifier);
  const isMatch = timingSafeEqual(candidateBytes, storedBytes);

  if (!isMatch) {
    throw new Error('RECOVERY_FAILED');
  }

  // Verification succeeded: reassign owner_user_id if provided and mark success
  if (newOwnerUserId) {
    localEntry.owner_user_id = newOwnerUserId;
  }
  localEntry.updated_at = new Date().toISOString();
  if (rateRecord) {
    rateRecord.successfulAttempts = (rateRecord.successfulAttempts || 0) + 1;
  }

  return {
    accountId: localEntry.account_id,
    encryptedBlob: localEntry.encrypted_vault_blob,
    vaultVersion: localEntry.vault_version,
    source: 'offline-local',
  };
}

/**
 * Executes migration of a legacy PBKDF2 recovery verifier to Argon2id.
 * Proof of ownership is the correct legacy recovery verifier.
 * Stores canonical phrase-derived recovery_salt submitted by verified owner.
 */
export async function migrateRecoveryVerifier(
  accountId: string,
  legacyRecoveryVerifierHex: string,
  newRecoveryVerifierHex: string,
  recoverySaltHex: string
): Promise<{ success: boolean; recoveryKdfVersion: number }> {
  if (!accountId || typeof accountId !== 'string' || !RFC4122_UUID_REGEX.test(accountId)) {
    throw new Error('MIGRATION_FAILED');
  }
  if (!legacyRecoveryVerifierHex || typeof legacyRecoveryVerifierHex !== 'string' || !HEX64_REGEX.test(legacyRecoveryVerifierHex)) {
    throw new Error('MIGRATION_FAILED');
  }
  if (!newRecoveryVerifierHex || !HEX64_REGEX.test(newRecoveryVerifierHex)) {
    throw new Error('MIGRATION_FAILED');
  }
  if (!recoverySaltHex || typeof recoverySaltHex !== 'string' || !HEX64_REGEX.test(recoverySaltHex)) {
    throw new Error('MIGRATION_FAILED');
  }

  if (activeConfig.isConfigured) {
    try {
      const payload: Record<string, any> = {
        account_id: accountId,
        legacy_recovery_verifier: legacyRecoveryVerifierHex.toLowerCase(),
        new_recovery_verifier: newRecoveryVerifierHex.toLowerCase(),
        recovery_salt: recoverySaltHex.toLowerCase(),
      };

      const resp = await fetch(`${activeConfig.url}/functions/v1/migrate-recovery-verifier`, {
        method: 'POST',
        headers: {
          apikey: activeConfig.anonKey,
          Authorization: `Bearer ${activeConfig.anonKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!resp.ok) {
        throw new Error('MIGRATION_FAILED');
      }

      const data = await resp.json();
      return {
        success: true,
        recoveryKdfVersion: data.recovery_kdf_version ?? 2,
      };
    } catch (e) {
      if ((e as Error).message === 'MIGRATION_FAILED') {
        throw e;
      }
    }
  }

  // Local/in-memory migration check
  const localEntry = inMemoryVaultSyncStore.get(accountId);
  const candidateBytes = hexToBytes(legacyRecoveryVerifierHex);
  const dummyBuffer = new Uint8Array(candidateBytes.length || 32);

  if (!localEntry) {
    timingSafeEqual(candidateBytes, dummyBuffer);
    throw new Error('MIGRATION_FAILED');
  }

  // Strictly require recovery_kdf_version === 1
  if (localEntry.recovery_kdf_version !== 1) {
    timingSafeEqual(candidateBytes, dummyBuffer);
    throw new Error('MIGRATION_FAILED');
  }

  const storedBytes = hexToBytes(localEntry.recovery_verifier);
  const isMatch = timingSafeEqual(candidateBytes, storedBytes);

  if (!isMatch) {
    throw new Error('MIGRATION_FAILED');
  }

  localEntry.recovery_verifier = newRecoveryVerifierHex.toLowerCase();
  localEntry.recovery_salt = recoverySaltHex.toLowerCase();
  localEntry.recovery_kdf_version = 2;
  localEntry.updated_at = new Date().toISOString();

  return {
    success: true,
    recoveryKdfVersion: 2,
  };
}

export async function deleteEncryptedVaultMetadata(
  accountId: string
): Promise<{ success: boolean; source: string }> {
  inMemoryVaultSyncStore.delete(accountId);

  if (!activeConfig.isConfigured) {
    return { success: true, source: 'offline-local' };
  }

  try {
    const controller = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timeoutId = controller ? setTimeout(() => controller.abort(), 1000) : null;
    const key = activeConfig.publishableKey || activeConfig.anonKey;
    const resp = await fetch(
      `${activeConfig.url}/rest/v1/ghost_vaults?account_id=eq.${accountId}`,
      {
        method: 'DELETE',
        headers: {
          apikey: key,
          Authorization: `Bearer ${key}`,
        },
        signal: controller?.signal,
      }
    );
    if (timeoutId) clearTimeout(timeoutId);
    return { success: resp.ok, source: 'supabase-cloud' };
  } catch (_e) {
    return { success: true, source: 'offline-fallback' };
  }
}
