/**
 * Ghost-Tag v2.0.5 - Android & Cross-Platform Supabase Cloud Sync
 * 
 * Cryptographic Invariant:
 * Supabase stores ONLY an encrypted vault metadata blob for cross-device recovery.
 * It NEVER receives or stores passphrases, recovery phrases, keys, entries, or NFC data.
 */

import { computeChunkHash } from '../crypto';

export interface SupabaseConfig {
  url: string;
  anonKey: string;
  isConfigured: boolean;
}

export interface EncryptedVaultRecord {
  accountId: string;
  encryptedBlob: string;
  vaultVersion: number;
  source: 'supabase-cloud' | 'offline-local' | 'offline-fallback';
}

const DEFAULT_CONFIG: SupabaseConfig = {
  url: 'https://placeholder.supabase.co',
  anonKey: 'placeholder-anon-key',
  isConfigured: false,
};

let activeConfig: SupabaseConfig = { ...DEFAULT_CONFIG };

export function configureSupabase(url: string, anonKey: string): SupabaseConfig {
  const cleanUrl = url.trim().replace(/\/+$/, '');
  const cleanKey = anonKey.trim();
  activeConfig = {
    url: cleanUrl,
    anonKey: cleanKey,
    isConfigured: Boolean(cleanUrl && cleanKey && !cleanUrl.includes('placeholder')),
  };
  return activeConfig;
}

export function resetSupabaseConfig(): void {
  activeConfig = { ...DEFAULT_CONFIG };
}

export function getSupabaseConfig(): SupabaseConfig {
  return { ...activeConfig };
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
 * Mock / In-memory sync store for unit tests and offline Android operation
 */
const inMemoryVaultSyncStore = new Map<string, string>();

export async function uploadEncryptedVaultMetadata(
  accountId: string,
  encryptedBlobBase64: string,
  vaultVersion = 2
): Promise<{ success: boolean; source: string }> {
  inMemoryVaultSyncStore.set(accountId, JSON.stringify({
    account_id: accountId,
    encrypted_vault_blob: encryptedBlobBase64,
    vault_version: vaultVersion,
  }));

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
      body: JSON.stringify({
        account_id: accountId,
        user_id: accountId,
        encrypted_vault_blob: encryptedBlobBase64,
        vault_version: vaultVersion,
      }),
      signal: controller?.signal,
    });
    if (timeoutId) clearTimeout(timeoutId);

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    return { success: true, source: 'supabase-cloud' };
  } catch (e) {
    return { success: true, source: 'offline-fallback' };
  }
}

export async function downloadEncryptedVaultMetadata(
  accountId: string
): Promise<EncryptedVaultRecord | null> {
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
    } catch (e) {
      // Fallback
    }
  }

  const local = inMemoryVaultSyncStore.get(accountId);
  if (local) {
    const parsed = JSON.parse(local);
    return {
      accountId: parsed.account_id,
      encryptedBlob: parsed.encrypted_vault_blob,
      vaultVersion: parsed.vault_version,
      source: 'offline-local',
    };
  }

  return null;
}
