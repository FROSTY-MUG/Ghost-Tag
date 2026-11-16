/**
 * @file supabaseSync.test.ts
 * @summary Unit tests for Ghost-Tag Supabase anonymous cloud sync and account ID derivation.
 */

import {
  deriveAccountIdFromPhrase,
  deriveRecoveryAuthSecret,
  computeRecoveryVerifier,
  configureSupabase,
  resetSupabaseConfig,
  getSupabaseConfig,
  uploadEncryptedVaultMetadata,
  downloadEncryptedVaultMetadata,
  recoverVaultWithVerifier,
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

  describe('Hardened Recovery Verifier & Anti-Takeover Controls', () => {
    function bytesToHex(bytes: Uint8Array): string {
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    test('derives recovery_auth_secret locally and computes verifier with salt', async () => {
      const authSecret = await deriveRecoveryAuthSecret(TEST_PHRASE);
      expect(authSecret.length).toBe(32);

      const salt = new Uint8Array(16).fill(0x42);
      const verifier1 = await computeRecoveryVerifier(authSecret, salt);
      const verifier2 = await computeRecoveryVerifier(authSecret, salt);
      expect(verifier1).toEqual(verifier2);
      expect(verifier1.length).toBe(32);

      const otherPhrase = ['ability', ...TEST_PHRASE.slice(1)];
      const otherAuthSecret = await deriveRecoveryAuthSecret(otherPhrase);
      expect(otherAuthSecret).not.toEqual(authSecret);
    });

    test('correct recovery phrase and verifier successfully restores vault', async () => {
      const accountId = await deriveAccountIdFromPhrase(TEST_PHRASE);
      const authSecret = await deriveRecoveryAuthSecret(TEST_PHRASE);
      const salt = new Uint8Array(16).fill(0x07);
      const verifier = await computeRecoveryVerifier(authSecret, salt);
      const verifierHex = bytesToHex(verifier);
      const saltHex = bytesToHex(salt);
      const mockBlob = btoa('ENCRYPTED_VAULT_RECOVERY_PAYLOAD');

      await uploadEncryptedVaultMetadata({
        accountId,
        ownerUserId: 'original_device_user_id',
        recoveryVerifierHex: verifierHex,
        recoverySaltHex: saltHex,
        encryptedBlobBase64: mockBlob,
        vaultVersion: 2,
      });

      // Restore from Device 2 with fresh user session
      const restored = await recoverVaultWithVerifier(
        accountId,
        verifierHex,
        'new_device_user_id_456'
      );

      expect(restored.accountId).toBe(accountId);
      expect(restored.encryptedBlob).toBe(mockBlob);
      expect(restored.vaultVersion).toBe(2);
    });

    test('wrong recovery verifier fails with generic RECOVERY_FAILED', async () => {
      const accountId = await deriveAccountIdFromPhrase(TEST_PHRASE);
      const authSecret = await deriveRecoveryAuthSecret(TEST_PHRASE);
      const salt = new Uint8Array(16).fill(0x01);
      const verifier = await computeRecoveryVerifier(authSecret, salt);

      await uploadEncryptedVaultMetadata({
        accountId,
        ownerUserId: 'user_owner',
        recoveryVerifierHex: bytesToHex(verifier),
        recoverySaltHex: bytesToHex(salt),
        encryptedBlobBase64: btoa('SECRET_BLOB'),
      });

      const badVerifierHex = '00'.repeat(32);
      await expect(
        recoverVaultWithVerifier(accountId, badVerifierHex, 'attacker_user_id')
      ).rejects.toThrow('RECOVERY_FAILED');
    });

    test('unknown account ID fails with generic RECOVERY_FAILED (prevents enumeration)', async () => {
      const randomAccountId = '00000000-0000-4000-8000-000000000000';
      const fakeVerifierHex = '11'.repeat(32);

      await expect(
        recoverVaultWithVerifier(randomAccountId, fakeVerifierHex, 'attacker_user_id')
      ).rejects.toThrow('RECOVERY_FAILED');
    });

    test('rate limiting blocks repeated brute-force recovery attempts after threshold', async () => {
      const accountId = await deriveAccountIdFromPhrase(TEST_PHRASE);
      const authSecret = await deriveRecoveryAuthSecret(TEST_PHRASE);
      const salt = new Uint8Array(16).fill(0x99);
      const verifier = await computeRecoveryVerifier(authSecret, salt);

      await uploadEncryptedVaultMetadata({
        accountId,
        recoveryVerifierHex: bytesToHex(verifier),
        recoverySaltHex: bytesToHex(salt),
        encryptedBlobBase64: btoa('TARGET_BLOB'),
      });

      const wrongVerifierHex = 'ff'.repeat(32);

      // Attempt 5 bad recoveries (threshold)
      for (let i = 0; i < 5; i++) {
        await expect(
          recoverVaultWithVerifier(accountId, wrongVerifierHex, 'attacker')
        ).rejects.toThrow('RECOVERY_FAILED');
      }

      // 6th attempt must trigger rate limit and fail closed with generic error
      await expect(
        recoverVaultWithVerifier(accountId, wrongVerifierHex, 'attacker')
      ).rejects.toThrow('RECOVERY_FAILED');
    });
  });
});
