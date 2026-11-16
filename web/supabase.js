/**
 * Ghost-Tag v2.0.5 - Supabase Anonymous Cloud Sync Client
 * 
 * Cryptographic Invariant:
 * Supabase stores ONLY an encrypted vault metadata blob for cross-device recovery.
 * It NEVER receives or stores:
 * - Passphrase
 * - Recovery phrase
 * - KEK (Key Encryption Key)
 * - DEK (Data Encryption Key)
 * - Plaintext files or entries
 * - Plaintext URLs
 * - NFC contents or scanned chunks
 * - Location data or analytics
 */

(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.GhostSupabase = factory();
  }
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const STORAGE_KEY_SUPABASE_CONFIG = 'ghost_supabase_config_v2';
  const STORAGE_KEY_OFFLINE_SYNC = 'ghost_offline_cloud_vault_v2';

  // Default configuration (Configurable via UI or .env)
  const defaultConfig = {
    url: 'https://placeholder.supabase.co',
    anonKey: 'placeholder-anon-key',
    publishableKey: 'placeholder-anon-key',
    isConfigured: false,
    mode: 'offline',
    lastSyncTime: null
  };

  function getConfig() {
    try {
      const stored = localStorage.getItem(STORAGE_KEY_SUPABASE_CONFIG);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed.disabled) {
          return { ...defaultConfig, mode: 'offline', isConfigured: false, disabled: true, lastSyncTime: parsed.lastSyncTime || null };
        }
        return {
          ...defaultConfig,
          ...parsed,
          publishableKey: parsed.publishableKey || parsed.anonKey,
          anonKey: parsed.publishableKey || parsed.anonKey,
          mode: parsed.isConfigured ? 'supabase' : 'offline',
          lastSyncTime: parsed.lastSyncTime || null
        };
      }
    } catch (e) {
      // Fallback
    }

    const env = (typeof window !== 'undefined' && window.__ENV__) || {};
    if (env.VITE_GHOST_CLOUD_SYNC_ENABLED === 'true' && env.VITE_SUPABASE_URL && env.VITE_SUPABASE_PUBLISHABLE_KEY) {
      return {
        url: env.VITE_SUPABASE_URL,
        publishableKey: env.VITE_SUPABASE_PUBLISHABLE_KEY,
        anonKey: env.VITE_SUPABASE_PUBLISHABLE_KEY,
        isConfigured: true,
        mode: 'supabase',
        lastSyncTime: null
      };
    }

    return { ...defaultConfig, mode: 'offline' };
  }

  function sanitizeUrl(rawUrl) {
    if (typeof rawUrl !== 'string') return '';
    let str = rawUrl.trim();
    if (str.length > 2048) str = str.slice(0, 2048);
    let end = str.length;
    while (end > 0 && str.charCodeAt(end - 1) === 47 /* '/' */) {
      end--;
    }
    return str.slice(0, end);
  }

  function generateSecureSessionId() {
    const gCrypto = typeof window !== 'undefined' ? window.crypto : (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
    if (gCrypto && typeof gCrypto.getRandomValues === 'function') {
      const bytes = new Uint8Array(16);
      gCrypto.getRandomValues(bytes);
      return 'anon_' + Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    }
    throw new Error('Cryptographically secure random number generator (CSPRNG) is not available.');
  }

  function saveConfig(url, publishableKey) {
    const cleanUrl = sanitizeUrl(url || '');
    const cleanKey = (publishableKey || '').trim().slice(0, 1024);
    const isConfigured = Boolean(cleanUrl && cleanKey && !cleanUrl.includes('placeholder'));
    const config = {
      url: cleanUrl,
      publishableKey: cleanKey,
      anonKey: cleanKey,
      isConfigured: isConfigured,
      disabled: false,
      mode: isConfigured ? 'supabase' : 'offline',
      lastSyncTime: new Date().toISOString()
    };
    try {
      localStorage.setItem(STORAGE_KEY_SUPABASE_CONFIG, JSON.stringify(config));
    } catch (e) {
      console.warn('Unable to persist Supabase config to localStorage:', e);
    }
    return config;
  }

  function disableConfig() {
    const current = getConfig();
    const config = {
      ...current,
      disabled: true,
      isConfigured: false,
      mode: 'offline'
    };
    try {
      localStorage.setItem(STORAGE_KEY_SUPABASE_CONFIG, JSON.stringify(config));
    } catch (e) {
      // Storage error
    }
    return config;
  }

  function getCloudConfig() {
    const config = getConfig();
    if (config.isConfigured && !config.disabled) {
      return {
        mode: 'supabase',
        url: config.url,
        publishableKey: config.publishableKey || config.anonKey
      };
    }
    return { mode: 'offline' };
  }

  /**
   * Derive a stable, domain-separated UUID account_id from the 12-word BIP-39 recovery phrase
   * account_id = KDF(recovery_phrase, "ghost-account-id")
   */
  async function deriveAccountId(recoveryWords) {
    const phrase = Array.isArray(recoveryWords) ? recoveryWords.join(' ').trim().toLowerCase() : String(recoveryWords).trim().toLowerCase();
    const enc = new TextEncoder();
    const salt = enc.encode('ghost-account-id-v2.0.5');

    // SHA-256 HMAC or double SHA-256 domain-separated hash
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(phrase),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 10000,
        hash: 'SHA-256'
      },
      keyMaterial,
      128 // 16 bytes for UUID
    );

    const bytes = new Uint8Array(derivedBits);
    // Format as RFC 4122 variant 1, version 4 UUID
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1

    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-${hex.substr(12, 4)}-${hex.substr(16, 4)}-${hex.substr(20, 12)}`;
  }

  /**
   * Derive a dedicated 256-bit recovery auth secret from the 12-word recovery phrase.
   * recovery_auth_secret = KDF(recovery_phrase, "ghost-recovery-auth")
   * NEVER sent to or stored in Supabase.
   */
  async function deriveRecoveryAuthSecret(recoveryWords) {
    const phrase = Array.isArray(recoveryWords) ? recoveryWords.join(' ').trim().toLowerCase() : String(recoveryWords).trim().toLowerCase();
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(phrase),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: enc.encode('ghost-recovery-auth-v2.0.5'),
        iterations: 10000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return new Uint8Array(derivedBits);
  }

  /**
   * Computes the 256-bit recovery verifier stored in Supabase.
   * recovery_verifier = KDF(recovery_auth_secret, recovery_salt, parameters)
   */
  async function computeRecoveryVerifier(authSecretBytes, saltBytes) {
    const salt = saltBytes || new Uint8Array(16);
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      authSecretBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 10000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    return Array.from(new Uint8Array(derivedBits)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Supabase Anonymous Authentication
   * Creates or authenticates an anonymous user on Supabase auth.users
   */
  async function signInAnonymously() {
    const config = getConfig();

    if (!config.isConfigured) {
      // Offline fallback: Generate local anonymous session ID via CSPRNG
      let localSession = localStorage.getItem('ghost_local_anon_user');
      if (!localSession) {
        localSession = generateSecureSessionId();
        localStorage.setItem('ghost_local_anon_user', localSession);
      }
      return { userId: localSession, token: 'local-offline-token', isOffline: true };
    }

    try {
      const resp = await fetch(`${config.url}/auth/v1/signup`, {
        method: 'POST',
        headers: {
          'apikey': config.anonKey,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          data: { is_anonymous: true }
        })
      });

      if (!resp.ok) {
        throw new Error(`Anonymous signup failed with status ${resp.status}`);
      }

      const data = await resp.json();
      return {
        userId: data.user ? data.user.id : (data.id || 'anon_remote'),
        token: data.access_token,
        isOffline: false
      };
    } catch (err) {
      console.warn('Supabase anonymous sign-in network error, using local fallback:', err);
      let localSession = localStorage.getItem('ghost_local_anon_user');
      if (!localSession) {
        localSession = generateSecureSessionId();
        localStorage.setItem('ghost_local_anon_user', localSession);
      }
      return { userId: localSession, token: 'local-offline-token', isOffline: true, error: err.message };
    }
  }

  /**
   * Upload encrypted vault metadata blob to Supabase
   * Stores ONLY ciphertext and metadata.
   */
  async function uploadEncryptedVault(accountId, encryptedBlobBase64, vaultVersion = 2) {
    const config = getConfig();
    const record = {
      account_id: accountId,
      encrypted_vault_blob: encryptedBlobBase64,
      vault_version: vaultVersion,
      updated_at: new Date().toISOString()
    };

    // Always mirror to local offline recovery store
    try {
      localStorage.setItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`, JSON.stringify(record));
    } catch (e) {
      // Local storage quota
    }

    if (!config.isConfigured) {
      return { success: true, source: 'offline-local' };
    }

    try {
      const auth = await signInAnonymously();
      const resp = await fetch(`${config.url}/rest/v1/ghost_vaults`, {
        method: 'POST',
        headers: {
          'apikey': config.anonKey,
          'Authorization': `Bearer ${auth.token || config.anonKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify({
          account_id: accountId,
          user_id: auth.userId,
          encrypted_vault_blob: encryptedBlobBase64,
          vault_version: vaultVersion
        })
      });

      if (!resp.ok) {
        throw new Error(`Cloud upload returned HTTP ${resp.status}`);
      }
      try {
        config.lastSyncTime = new Date().toISOString();
        localStorage.setItem(STORAGE_KEY_SUPABASE_CONFIG, JSON.stringify(config));
      } catch (e) {}
      return { success: true, source: 'supabase-cloud' };
    } catch (err) {
      console.warn('Cloud sync error, vault saved in offline fallback:', err);
      return { success: true, source: 'offline-fallback', error: err.message };
    }
  }

  /**
   * Download encrypted vault metadata blob from Supabase
   */
  async function downloadEncryptedVault(accountId) {
    const config = getConfig();

    // Check remote Supabase first if configured
    if (config.isConfigured) {
      try {
        const auth = await signInAnonymously();
        const resp = await fetch(`${config.url}/rest/v1/ghost_vaults?account_id=eq.${accountId}&select=*`, {
          method: 'GET',
          headers: {
            'apikey': config.anonKey,
            'Authorization': `Bearer ${auth.token || config.anonKey}`,
            'Accept': 'application/json'
          }
        });

        if (resp.ok) {
          const rows = await resp.json();
          if (Array.isArray(rows) && rows.length > 0) {
            return {
              accountId: rows[0].account_id,
              encryptedBlob: rows[0].encrypted_vault_blob,
              vaultVersion: rows[0].vault_version,
              source: 'supabase-cloud'
            };
          }
        }
      } catch (err) {
        console.warn('Could not reach Supabase, falling back to local sync store:', err);
      }
    }

    // Check local offline recovery store
    try {
      const local = localStorage.getItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`);
      if (local) {
        const parsed = JSON.parse(local);
        return {
          accountId: parsed.account_id,
          encryptedBlob: parsed.encrypted_vault_blob,
          vaultVersion: parsed.vault_version,
          source: 'offline-local'
        };
      }
    } catch (e) {
      // Error reading local store
    }

    return null;
  }

  /**
   * Executes recovery of encrypted vault metadata using accountId and recovery_verifier.
   * Calls the Edge Function /functions/v1/recover-vault or falls back to local storage.
   */
  async function recoverVaultWithVerifier(accountId, recoveryVerifierHex) {
    const config = getConfig();

    if (config.isConfigured && !config.disabled) {
      try {
        const auth = await signInAnonymously();
        const resp = await fetch(`${config.url}/functions/v1/recover-vault`, {
          method: 'POST',
          headers: {
            'apikey': config.anonKey,
            'Authorization': `Bearer ${auth.token || config.anonKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            account_id: accountId,
            recovery_verifier: recoveryVerifierHex
          })
        });

        if (!resp.ok) {
          throw new Error('RECOVERY_FAILED');
        }

        const data = await resp.json();
        return {
          accountId: data.account_id,
          encryptedBlob: data.encrypted_vault_blob,
          vaultVersion: data.vault_version,
          source: 'supabase-cloud'
        };
      } catch (e) {
        // Fall back to local storage if edge function fails or is offline
      }
    }

    // Local fallback check
    const local = localStorage.getItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`);
    if (local) {
      const parsed = JSON.parse(local);
      return {
        accountId: parsed.account_id,
        encryptedBlob: parsed.encrypted_vault_blob,
        vaultVersion: parsed.vault_version,
        source: 'offline-local'
      };
    }

    throw new Error('RECOVERY_FAILED');
  }

  /**
   * Delete encrypted vault metadata blob from Supabase
   */
  async function deleteEncryptedVault(accountId) {
    const config = getConfig();

    try {
      localStorage.removeItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`);
    } catch (e) {
      // Local storage
    }

    if (!config.isConfigured || config.disabled) {
      return { success: true, source: 'offline-local' };
    }

    try {
      const auth = await signInAnonymously();
      const key = config.publishableKey || config.anonKey;
      const resp = await fetch(`${config.url}/rest/v1/ghost_vaults?account_id=eq.${accountId}`, {
        method: 'DELETE',
        headers: {
          'apikey': key,
          'Authorization': `Bearer ${auth.token || key}`
        }
      });
      return { success: resp.ok, source: 'supabase-cloud' };
    } catch (err) {
      console.warn('Could not delete remote vault record:', err);
      return { success: true, source: 'offline-fallback' };
    }
  }

  return {
    getConfig,
    saveConfig,
    disableConfig,
    getCloudConfig,
    deriveAccountId,
    deriveRecoveryAuthSecret,
    computeRecoveryVerifier,
    signInAnonymously,
    uploadEncryptedVault,
    downloadEncryptedVault,
    recoverVaultWithVerifier,
    deleteEncryptedVault
  };
});
