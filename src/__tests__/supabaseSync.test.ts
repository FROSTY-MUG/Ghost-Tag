/**
 * @file supabaseSync.test.ts
 * @summary Unit tests for Ghost-Tag Supabase anonymous cloud sync and account ID derivation.
 */

import {
  deriveAccountIdFromPhrase,
  configureSupabase,
  resetSupabaseConfig,
  getSupabaseConfig,
  uploadEncryptedVaultMetadata,
  downloadEncryptedVaultMetadata
} from '../cloud/supabaseClient';

describe('Ghost-Tag Supabase Anonymous Sync', () => {
  const TEST_PHRASE = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent',
    'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident'
  ];

  beforeEach(() => {
    resetSupabaseConfig();
  });

  test('derives a deterministic RFC 4122 v4 UUID from 12-word BIP-39 phrase', async () => {
    const accountId1 = await deriveAccountIdFromPhrase(TEST_PHRASE);
    const accountId2 = await deriveAccountIdFromPhrase(TEST_PHRASE);

    expect(accountId1).toBe(accountId2);
    expect(accountId1).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });

  test('different recovery phrases derive different account IDs', async () => {
    const phraseA = ['abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'abandon', 'about'];
    const idA = await deriveAccountIdFromPhrase(phraseA);
    const idB = await deriveAccountIdFromPhrase(TEST_PHRASE);

    expect(idA).not.toBe(idB);
  });

  test('configures custom Supabase endpoint and anon key', () => {
    const config = configureSupabase('https://custom-project.supabase.co/', 'my-custom-anon-key');
    expect(config.url).toBe('https://custom-project.supabase.co');
    expect(config.anonKey).toBe('my-custom-anon-key');
    expect(config.isConfigured).toBe(true);

    const active = getSupabaseConfig();
    expect(active.isConfigured).toBe(true);
  });

  test('uploads and downloads encrypted vault metadata offline without leakage', async () => {
    const accountId = await deriveAccountIdFromPhrase(TEST_PHRASE);
    const mockBlob = btoa('ENCRYPTED_VAULT_BLOB_V2');

    const uploadResult = await uploadEncryptedVaultMetadata(accountId, mockBlob, 2);
    expect(uploadResult.success).toBe(true);

    const record = await downloadEncryptedVaultMetadata(accountId);
    expect(record).not.toBeNull();
    expect(record?.accountId).toBe(accountId);
    expect(record?.encryptedBlob).toBe(mockBlob);
    expect(record?.vaultVersion).toBe(2);
  });
});
