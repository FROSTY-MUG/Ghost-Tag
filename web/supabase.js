/**
 * Ghost-Tag v2.1.0 - Supabase Anonymous Cloud Sync Client
 * 
 * Canonical Cryptographic Standards:
 * - account_id: RFC4122_UUID(SHA256("ghost-account-id-v2.0.5:" || recovery_phrase))
 * - recovery_auth_secret: SHA256("ghost-recovery-auth-v2.0.5:" || recovery_phrase)
 * - recovery_verifier: Argon2id RFC 9106 (m=32768 KiB, t=3 passes, p=2 threads, h=32 bytes, v=0x13)
 *   encoded as 64 lowercase hexadecimal characters.
 * 
 * Cryptographic Invariants:
 * Supabase stores ONLY an encrypted vault metadata blob for cross-device recovery.
 * It NEVER receives or stores:
 * - Passphrase
 * - Recovery phrase
 * - KEK (Key Encryption Key)
 * - DEK (Data Encryption Key)
 * - Plaintext files, entries, or URLs
 * - NFC contents or scanned chunks
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

  const RFC4122_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  const HEX64_REGEX = /^[0-9a-fA-F]{64}$/;

  // Canonical Argon2id parameters matching Android
  const CANONICAL_ARGON2_PARAMS = {
    memoryCost: 32768, // 32 MiB
    timeCost: 3,       // 3 iterations
    parallelism: 2,    // 2 threads
    hashLength: 32,    // 256 bits
    version: 0x13      // Argon2 v1.3
  };

  // Default configuration (Configurable via UI or .env)
  const defaultConfig = {
    url: 'https://placeholder.supabase.co',
    anonKey: 'placeholder-anon-key',
    publishableKey: 'placeholder-anon-key',
    isConfigured: false,
    mode: 'offline',
    lastSyncTime: null
  };

  function bytesToHex(bytes) {
    if (!bytes) return '';
    return Array.from(bytes).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string') return new Uint8Array(0);
    const clean = hex.replace(/[^0-9a-fA-F]/g, '');
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < clean.length; i += 2) {
      bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
    }
    return bytes;
  }

  async function computeSha256(data) {
    const gCrypto = typeof window !== 'undefined' ? window.crypto : (typeof globalThis !== 'undefined' ? globalThis.crypto : null);
    if (gCrypto && gCrypto.subtle && typeof gCrypto.subtle.digest === 'function') {
      const buf = await gCrypto.subtle.digest('SHA-256', data);
      return new Uint8Array(buf);
    }
    if (typeof require === 'function') {
      try {
        const nodeCrypto = require('crypto');
        const hash = nodeCrypto.createHash('sha256').update(data).digest();
        return new Uint8Array(hash);
      } catch (_) {}
    }
    throw new Error('SHA-256 digest engine unavailable.');
  }

  async function getArgon2idRunner() {
    if (typeof globalThis !== 'undefined' && globalThis.hashwasm && typeof globalThis.hashwasm.argon2id === 'function') {
      return globalThis.hashwasm.argon2id;
    }
    if (typeof window !== 'undefined' && window.hashwasm && typeof window.hashwasm.argon2id === 'function') {
      return window.hashwasm.argon2id;
    }
    if (typeof require === 'function') {
      try {
        const hw = require('hash-wasm');
        if (typeof hw.argon2id === 'function') return hw.argon2id;
      } catch (_) {}
    }
    throw new Error('Argon2id WASM implementation is not available.');
  }

  function getConfig() {
    try {
      if (typeof localStorage !== 'undefined') {
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
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(STORAGE_KEY_SUPABASE_CONFIG, JSON.stringify(config));
      }
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
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(STORAGE_KEY_SUPABASE_CONFIG, JSON.stringify(config));
      }
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
   * Derive a stable, domain-separated UUID account_id from the 12-word BIP-39 recovery phrase.
   * Canonical Android formula: account_id = RFC4122_UUID(SHA256("ghost-account-id-v2.0.5:" || phrase))
   */
  async function deriveAccountId(recoveryWords) {
    const words = Array.isArray(recoveryWords) ? recoveryWords : String(recoveryWords).trim().split(/\s+/);
    const cleanPhrase = words.map(function (w) { return String(w).trim().toLowerCase(); }).join(' ');
    const enc = new TextEncoder();
    const input = enc.encode('ghost-account-id-v2.0.5:' + cleanPhrase);
    const hash = await computeSha256(input);

    // Format first 16 bytes as RFC 4122 variant 1, version 4 UUID
    const bytes = hash.slice(0, 16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1

    const hex = bytesToHex(bytes);
    return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-${hex.substr(12, 4)}-${hex.substr(16, 4)}-${hex.substr(20, 12)}`;
  }

  /**
   * Derive a dedicated 256-bit recovery auth secret from the 12-word recovery phrase.
   * Canonical Android formula: recovery_auth_secret = SHA256("ghost-recovery-auth-v2.0.5:" || phrase)
   * NEVER sent to or stored in Supabase.
   */
  async function deriveRecoveryAuthSecret(recoveryWords) {
    const words = Array.isArray(recoveryWords) ? recoveryWords : String(recoveryWords).trim().split(/\s+/);
    const cleanPhrase = words.map(function (w) { return String(w).trim().toLowerCase(); }).join(' ');
    const enc = new TextEncoder();
    const input = enc.encode('ghost-recovery-auth-v2.0.5:' + cleanPhrase);
    return await computeSha256(input);
  }

  /**
   * Derive a deterministic 256-bit recovery salt from the 12-word recovery phrase (Option A).
   * Canonical Android formula: recovery_salt = SHA256("ghost-recovery-salt-v2.0.5:" || phrase)
   */
  async function deriveRecoverySalt(recoveryWords) {
    const words = Array.isArray(recoveryWords) ? recoveryWords : String(recoveryWords).trim().split(/\s+/);
    const cleanPhrase = words.map(function (w) { return String(w).trim().toLowerCase(); }).join(' ');
    const enc = new TextEncoder();
    const input = enc.encode('ghost-recovery-salt-v2.0.5:' + cleanPhrase);
    return await computeSha256(input);
  }

  /**
   * Computes the 256-bit recovery verifier stored in Supabase using Argon2id RFC 9106.
   * Canonical Android formula:
   * recovery_verifier = Argon2id(passphrase = hex(recovery_auth_secret), salt = recovery_salt, m=32768, t=3, p=2)
   * Returns 32 raw bytes encoded as exactly 64 lowercase hexadecimal characters.
   */
  async function computeRecoveryVerifier(authSecretBytes, saltBytes, params) {
    if (!authSecretBytes || authSecretBytes.length !== 32) {
      throw new Error('recovery_auth_secret must be exactly 32 bytes.');
    }
    const salt = saltBytes || new Uint8Array(32);
    if (salt.length < 8) {
      throw new Error('recovery_salt must be at least 8 bytes.');
    }

    const memory = (params && params.memoryCost) || CANONICAL_ARGON2_PARAMS.memoryCost;
    const iterations = (params && params.timeCost) || CANONICAL_ARGON2_PARAMS.timeCost;
    const parallelism = (params && params.parallelism) || CANONICAL_ARGON2_PARAMS.parallelism;

    const authSecretHex = bytesToHex(authSecretBytes);
    const runner = await getArgon2idRunner();

    const verifierHex = await runner({
      password: authSecretHex,
      salt: salt,
      iterations: iterations,
      memorySize: memory,
      parallelism: parallelism,
      hashLength: 32,
      outputType: 'hex',
    });

    if (typeof verifierHex !== 'string' || !HEX64_REGEX.test(verifierHex)) {
      throw new Error('Failed to derive valid 64-hex Argon2id recovery verifier.');
    }

    return verifierHex.toLowerCase();
  }

  /**
   * Supabase Anonymous Authentication
   * Creates or authenticates an anonymous user on Supabase auth.users
   */
  async function signInAnonymously() {
    const config = getConfig();

    if (!config.isConfigured) {
      let localSession = typeof localStorage !== 'undefined' ? localStorage.getItem('ghost_local_anon_user') : null;
      if (!localSession) {
        localSession = generateSecureSessionId();
        if (typeof localStorage !== 'undefined') localStorage.setItem('ghost_local_anon_user', localSession);
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
      let localSession = typeof localStorage !== 'undefined' ? localStorage.getItem('ghost_local_anon_user') : null;
      if (!localSession) {
        localSession = generateSecureSessionId();
        if (typeof localStorage !== 'undefined') localStorage.setItem('ghost_local_anon_user', localSession);
      }
      return { userId: localSession, token: 'local-offline-token', isOffline: true, error: err.message };
    }
  }

  /**
   * Upload encrypted vault metadata blob to Supabase
   * Stores ONLY ciphertext and metadata.
   */
  async function uploadEncryptedVault(accountIdOrOptions, encryptedBlobBase64, vaultVersion = 2, options = {}) {
    const config = getConfig();
    let accountId;
    let blob;
    let vVersion;
    let verifierHex;
    let saltHex;

    if (typeof accountIdOrOptions === 'object' && accountIdOrOptions !== null) {
      accountId = accountIdOrOptions.accountId;
      blob = accountIdOrOptions.encryptedBlobBase64 || accountIdOrOptions.encryptedBlob;
      vVersion = accountIdOrOptions.vaultVersion || 2;
      verifierHex = accountIdOrOptions.recoveryVerifierHex;
      saltHex = accountIdOrOptions.recoverySaltHex;
    } else {
      accountId = accountIdOrOptions;
      blob = encryptedBlobBase64;
      vVersion = vaultVersion || 2;
      if (options && typeof options === 'object') {
        verifierHex = options.recoveryVerifierHex;
        saltHex = options.recoverySaltHex;
      }
    }

    const record = {
      account_id: accountId,
      encrypted_vault_blob: blob,
      vault_version: vVersion,
      recovery_verifier: verifierHex || null,
      recovery_salt: saltHex || null,
      updated_at: new Date().toISOString()
    };

    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`, JSON.stringify(record));
      }
    } catch (e) {
      // Storage error
    }

    if (!config.isConfigured || config.disabled) {
      return { success: true, source: 'offline-local' };
    }

    try {
      const auth = await signInAnonymously();
      const payload = {
        account_id: accountId,
        user_id: auth.userId,
        encrypted_vault_blob: blob,
        vault_version: vVersion,
      };
      if (verifierHex) payload.recovery_verifier = verifierHex;
      if (saltHex) payload.recovery_salt = saltHex;

      const resp = await fetch(`${config.url}/rest/v1/ghost_vaults`, {
        method: 'POST',
        headers: {
          'apikey': config.anonKey,
          'Authorization': `Bearer ${auth.token || config.anonKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify(payload)
      });

      if (!resp.ok) {
        throw new Error(`Cloud upload returned HTTP ${resp.status}`);
      }
      try {
        config.lastSyncTime = new Date().toISOString();
        if (typeof localStorage !== 'undefined') localStorage.setItem(STORAGE_KEY_SUPABASE_CONFIG, JSON.stringify(config));
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

    if (config.isConfigured && !config.disabled) {
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
            const row = rows[0];
            const isLegacy = row.recovery_kdf_version === 1 || !row.recovery_kdf_version || (row.recovery_verifier && row.recovery_verifier.length !== 64);
            return {
              accountId: row.account_id,
              encryptedBlob: row.encrypted_vault_blob,
              vaultVersion: row.vault_version,
              recoveryKdfVersion: row.recovery_kdf_version || 1,
              recoveryVerifier: row.recovery_verifier || null,
              recoverySalt: row.recovery_salt || null,
              needsMigration: isLegacy,
              source: 'supabase-cloud'
            };
          }
        }
      } catch (err) {
        console.warn('Could not reach Supabase, falling back to local sync store:', err);
      }
    }

    try {
      if (typeof localStorage !== 'undefined') {
        const local = localStorage.getItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`);
        if (local) {
          const parsed = JSON.parse(local);
          const isLegacy = parsed.recovery_kdf_version === 1 || !parsed.recovery_kdf_version || (parsed.recovery_verifier && parsed.recovery_verifier.length !== 64);
          return {
            accountId: parsed.account_id,
            encryptedBlob: parsed.encrypted_vault_blob,
            vaultVersion: parsed.vault_version,
            recoveryKdfVersion: parsed.recovery_kdf_version || 1,
            recoveryVerifier: parsed.recovery_verifier || null,
            recoverySalt: parsed.recovery_salt || null,
            needsMigration: isLegacy,
            source: 'offline-local'
          };
        }
      }
    } catch (e) {
      // Error reading local store
    }

    return null;
  }

  /**
   * Derive legacy PBKDF2 account_id from 12-word recovery phrase.
   * Used for discovering and migrating legacy web vaults on new devices.
   */
  async function deriveLegacyAccountId(recoveryWords) {
    const words = Array.isArray(recoveryWords) ? recoveryWords : String(recoveryWords).trim().split(/\s+/);
    const cleanPhrase = words.map(function (w) { return String(w).trim().toLowerCase(); }).join(' ');
    const enc = new TextEncoder();
    const salt = enc.encode('ghost-account-id-v2.0.5');

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(cleanPhrase),
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
      128
    );

    const bytes = new Uint8Array(derivedBits);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1
    const hex = bytesToHex(bytes);
    return `${hex.substr(0, 8)}-${hex.substr(8, 4)}-${hex.substr(12, 4)}-${hex.substr(16, 4)}-${hex.substr(20, 12)}`;
  }

  /**
   * Derive legacy PBKDF2 recovery verifier from 12-word recovery phrase.
   * Serves as ownership proof for migrating legacy web vaults.
   */
  async function deriveLegacyRecoveryVerifier(recoveryWords, saltBytes) {
    const words = Array.isArray(recoveryWords) ? recoveryWords : String(recoveryWords).trim().split(/\s+/);
    const cleanPhrase = words.map(function (w) { return String(w).trim().toLowerCase(); }).join(' ');
    const enc = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(cleanPhrase),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const authSecretBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: enc.encode('ghost-recovery-auth-v2.0.5'),
        iterations: 10000,
        hash: 'SHA-256'
      },
      keyMaterial,
      256
    );

    const authSecretBytes = new Uint8Array(authSecretBits);
    const salt = saltBytes || new Uint8Array(16);

    const verifierKeyMaterial = await crypto.subtle.importKey(
      'raw',
      authSecretBytes,
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const verifierBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 10000,
        hash: 'SHA-256'
      },
      verifierKeyMaterial,
      256
    );

    return bytesToHex(new Uint8Array(verifierBits));
  }

  /**
   * Dedicated migration endpoint call to upgrade legacy PBKDF2 verifier to Argon2id.
   * Zero-Knowledge Guarantee: Does NOT require an authenticated owner session.
   * The legacy PBKDF2 recovery verifier is the proof of ownership.
   */
  async function migrateRecoveryVerifier(accountId, legacyVerifierHex, newVerifierHex, recoverySaltHex) {
    if (!accountId || !RFC4122_UUID_REGEX.test(accountId)) {
      throw new Error('MIGRATION_FAILED');
    }
    if (!legacyVerifierHex || typeof legacyVerifierHex !== 'string') {
      throw new Error('MIGRATION_FAILED');
    }
    if (!newVerifierHex || !HEX64_REGEX.test(newVerifierHex)) {
      throw new Error('MIGRATION_FAILED');
    }

    // Rejects arbitrary client salt if passed invalidly
    if (recoverySaltHex && (typeof recoverySaltHex !== 'string' || !HEX64_REGEX.test(recoverySaltHex))) {
      throw new Error('MIGRATION_FAILED');
    }

    const config = getConfig();
    if (!config.isConfigured || config.disabled) {
      return { success: true, recoveryKdfVersion: 2, source: 'offline-local' };
    }

    // Server derives canonical recovery_salt via zero-knowledge binding
    // Client sends only account_id, legacy_recovery_verifier, and new_recovery_verifier
    const payload = {
      account_id: accountId,
      legacy_recovery_verifier: legacyVerifierHex.toLowerCase(),
      new_recovery_verifier: newVerifierHex.toLowerCase()
    };

    const resp = await fetch(`${config.url}/functions/v1/migrate-recovery-verifier`, {
      method: 'POST',
      headers: {
        'apikey': config.anonKey,
        'Authorization': `Bearer ${config.anonKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!resp.ok) {
      throw new Error('MIGRATION_FAILED');
    }

    const data = await resp.json();
    return {
      success: true,
      recoveryKdfVersion: data.recovery_kdf_version || 2,
      source: 'supabase-cloud'
    };
  }

  /**
   * Safe, explicit migration of legacy cloud recovery verifier to canonical Argon2id (RFC 9106).
   * Derives canonical recovery_auth_secret, Argon2id recovery_verifier, and deterministic salt.
   * Derives legacy PBKDF2 verifier as proof of ownership.
   * Works on brand-new devices with zero prior authentication state.
   */
  async function upgradeRecoveryVerifier(accountId, recoveryWords) {
    if (!accountId || !RFC4122_UUID_REGEX.test(accountId)) {
      throw new Error('Invalid account ID');
    }
    const cleanWords = Array.isArray(recoveryWords) ? recoveryWords : String(recoveryWords).trim().split(/\s+/);
    if (cleanWords.length !== 12) {
      throw new Error('Recovery phrase must be exactly 12 words.');
    }

    const authSecretBytes = await deriveRecoveryAuthSecret(cleanWords);
    const saltBytes = await deriveRecoverySalt(cleanWords);
    const recoveryVerifierHex = await computeRecoveryVerifier(authSecretBytes, saltBytes);
    const recoverySaltHex = bytesToHex(saltBytes);
    const legacyVerifierHex = await deriveLegacyRecoveryVerifier(cleanWords);

    const config = getConfig();
    if (config.isConfigured && !config.disabled) {
      await migrateRecoveryVerifier(accountId, legacyVerifierHex, recoveryVerifierHex, recoverySaltHex);
    }

    // Also update offline fallback record if present
    try {
      if (typeof localStorage !== 'undefined') {
        const localKey = `${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`;
        const local = localStorage.getItem(localKey);
        if (local) {
          const parsed = JSON.parse(local);
          parsed.recovery_verifier = recoveryVerifierHex;
          parsed.recovery_salt = recoverySaltHex;
          parsed.recovery_kdf_version = 2;
          parsed.updated_at = new Date().toISOString();
          localStorage.setItem(localKey, JSON.stringify(parsed));
        }
      }
    } catch (e) {
      // Ignore local storage error
    }

    return {
      success: true,
      accountId,
      recoveryVerifierHex,
      recoverySaltHex,
      recoveryKdfVersion: 2
    };
  }

  /**
   * Executes recovery of encrypted vault metadata using accountId and recovery_verifier.
   * Calls the Edge Function /functions/v1/recover-vault or falls back to local storage.
   * Strictly validates RFC 4122 UUID and 64-character lowercase hex verifier.
   * Works on brand-new devices without any existing owner session.
   */
  async function recoverVaultWithVerifier(accountId, recoveryVerifierHex) {
    // 1. Strict RFC 4122 UUID format validation
    if (!accountId || typeof accountId !== 'string' || !RFC4122_UUID_REGEX.test(accountId)) {
      throw new Error('RECOVERY_FAILED');
    }

    // 2. Strict 64-hex Argon2id verifier validation
    if (!recoveryVerifierHex || typeof recoveryVerifierHex !== 'string' || !HEX64_REGEX.test(recoveryVerifierHex)) {
      throw new Error('RECOVERY_FAILED');
    }

    const cleanVerifier = recoveryVerifierHex.toLowerCase();
    const config = getConfig();

    if (config.isConfigured && !config.disabled) {
      try {
        const resp = await fetch(`${config.url}/functions/v1/recover-vault`, {
          method: 'POST',
          headers: {
            'apikey': config.anonKey,
            'Authorization': `Bearer ${config.anonKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            account_id: accountId,
            recovery_verifier: cleanVerifier
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
        if (e.message === 'RECOVERY_FAILED') {
          throw e;
        }
        // Fall back to local storage if edge function fails or is offline
      }
    }

    // Local fallback check
    if (typeof localStorage !== 'undefined') {
      const local = localStorage.getItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`);
      if (local) {
        const parsed = JSON.parse(local);
        if (parsed.recovery_verifier && parsed.recovery_verifier.toLowerCase() !== cleanVerifier) {
          throw new Error('RECOVERY_FAILED');
        }
        return {
          accountId: parsed.account_id,
          encryptedBlob: parsed.encrypted_vault_blob,
          vaultVersion: parsed.vault_version,
          source: 'offline-local'
        };
      }
    }

    throw new Error('RECOVERY_FAILED');
  }

  /**
   * Delete encrypted vault metadata blob from Supabase
   */
  async function deleteEncryptedVault(accountId) {
    const config = getConfig();

    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.removeItem(`${STORAGE_KEY_OFFLINE_SYNC}_${accountId}`);
      }
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

  /**
   * Get current connection and sync status for UI presentation
   */
  function getStatus() {
    const config = getConfig();
    if (!config.isConfigured || config.disabled) {
      return {
        configured: false,
        label: 'Offline (Local Only)',
        status: 'offline',
        lastSyncTime: config.lastSyncTime || null
      };
    }
    return {
      configured: true,
      label: 'Connected (Encrypted Sync)',
      status: 'connected',
      lastSyncTime: config.lastSyncTime || null
    };
  }

  return {
    getConfig,
    saveConfig,
    disableConfig,
    getStatus,
    getCloudConfig,
    deriveAccountId,
    deriveLegacyAccountId,
    deriveRecoveryAuthSecret,
    deriveRecoverySalt,
    deriveLegacyRecoveryVerifier,
    computeRecoveryVerifier,
    signInAnonymously,
    uploadEncryptedVault,
    downloadEncryptedVault,
    migrateRecoveryVerifier,
    upgradeRecoveryVerifier,
    recoverVaultWithVerifier,
    deleteEncryptedVault,
    bytesToHex,
    hexToBytes
  };
});
