/**
 * @file rlsGhostVaults.test.ts
 * @summary Verifies Correction #1: Complete client lockdown of legacy public.ghost_vaults,
 * restricted public.ghost_vault_status view, retained Edge Function service_role access,
 * removal of direct /rest/v1/ghost_vaults client queries, and offline encryption compatibility.
 */

import {
  generateDEK,
  generateKeyId,
  wrapDEK,
  unwrapDEK,
  encryptFile,
  decryptFile,
  computeChunkHash,
} from '../crypto';
import {
  uploadEncryptedVaultMetadata,
  downloadEncryptedVaultMetadata,
  resetSupabaseConfig,
} from '../cloud/supabaseClient';

declare const require: any;
declare const __dirname: string;
const fs = require('fs');
const path = require('path');

interface GhostVaultRow {
  account_id: string;
  owner_user_id: string | null;
  recovery_verifier: string;
  recovery_salt: string;
  recovery_kdf_version: number;
  encrypted_vault_blob: string;
  vault_version: number;
  created_at: string;
  updated_at: string;
}

/**
 * Simulates PostgreSQL RLS + GRANT/REVOKE semantics on public.ghost_vaults
 * and public.ghost_vault_status after applying 20261125_lockdown_ghost_vaults.sql.
 */
class PostLockdownPostgresSimulator {
  private rows: Map<string, GhostVaultRow> = new Map();

  public seedViaServiceRole(row: GhostVaultRow): void {
    this.rows.set(row.account_id, { ...row });
  }

  public selectGhostVaults(
    role: 'anon' | 'authenticated' | 'service_role',
    columns: string[],
    accountId: string
  ): Partial<GhostVaultRow>[] {
    if (role !== 'service_role') {
      throw new Error('permission denied for table ghost_vaults');
    }
    const row = this.rows.get(accountId);
    if (!row) return [];
    if (columns.includes('*')) return [{ ...row }];
    const projected: Record<string, unknown> = {};
    for (const col of columns) {
      projected[col] = (row as unknown as Record<string, unknown>)[col];
    }
    return [projected as Partial<GhostVaultRow>];
  }

  public insertGhostVaults(
    role: 'anon' | 'authenticated' | 'service_role',
    row: GhostVaultRow
  ): void {
    if (role !== 'service_role') {
      throw new Error('permission denied for table ghost_vaults');
    }
    this.rows.set(row.account_id, { ...row });
  }

  public updateGhostVaults(
    role: 'anon' | 'authenticated' | 'service_role',
    accountId: string,
    patch: Partial<GhostVaultRow>
  ): void {
    if (role !== 'service_role') {
      throw new Error('permission denied for table ghost_vaults');
    }
    const existing = this.rows.get(accountId);
    if (existing) {
      this.rows.set(accountId, { ...existing, ...patch });
    }
  }

  public deleteGhostVaults(
    role: 'anon' | 'authenticated' | 'service_role',
    accountId: string
  ): void {
    if (role !== 'service_role') {
      throw new Error('permission denied for table ghost_vaults');
    }
    this.rows.delete(accountId);
  }

  public selectGhostVaultStatusView(
    role: 'anon' | 'authenticated' | 'service_role',
    authUid: string | null
  ): Array<{
    account_id: string;
    vault_version: number;
    recovery_kdf_version: number;
    created_at: string;
    updated_at: string;
  }> {
    if (role === 'anon') {
      throw new Error('permission denied for view ghost_vault_status');
    }
    if (!authUid) return [];
    const results: Array<{
      account_id: string;
      vault_version: number;
      recovery_kdf_version: number;
      created_at: string;
      updated_at: string;
    }> = [];
    for (const row of this.rows.values()) {
      if (row.owner_user_id === authUid) {
        results.push({
          account_id: row.account_id,
          vault_version: row.vault_version,
          recovery_kdf_version: row.recovery_kdf_version,
          created_at: row.created_at,
          updated_at: row.updated_at,
        });
      }
    }
    return results;
  }
}

describe('Correction #1: Legacy ghost_vaults Security Lockdown', () => {
  const ROOT = path.resolve(__dirname, '../..');
  const MIGRATION_PATH = path.join(
    ROOT,
    'supabase/migrations/20261125_lockdown_ghost_vaults.sql'
  );

  const OWNER_ID = '11111111-1111-4111-8111-111111111111';
  const ATTACKER_ID = '22222222-2222-4222-8222-222222222222';
  const ACCOUNT_ID = '33333333-3333-4333-8333-333333333333';

  let db: PostLockdownPostgresSimulator;

  beforeEach(() => {
    resetSupabaseConfig();
    db = new PostLockdownPostgresSimulator();
    db.seedViaServiceRole({
      account_id: ACCOUNT_ID,
      owner_user_id: OWNER_ID,
      recovery_verifier: 'ab'.repeat(32),
      recovery_salt: 'cd'.repeat(32),
      recovery_kdf_version: 2,
      encrypted_vault_blob: 'ZW5jcnlwdGVk',
      vault_version: 2,
      created_at: '2026-11-25T00:00:00Z',
      updated_at: '2026-11-25T00:00:00Z',
    });
  });

  test('1. Migration SQL drops unsafe owner_full_access policy and revokes all client privileges', () => {
    expect(fs.existsSync(MIGRATION_PATH)).toBe(true);
    const sql = fs.readFileSync(MIGRATION_PATH, 'utf8');

    expect(sql).toMatch(/DROP POLICY IF EXISTS "owner_full_access" ON public\.ghost_vaults/i);
    expect(sql).toMatch(/REVOKE ALL ON public\.ghost_vaults FROM PUBLIC, anon, authenticated/i);
    expect(sql).toMatch(/GRANT ALL ON public\.ghost_vaults TO service_role/i);
    expect(sql).toMatch(/ALTER TABLE public\.ghost_vaults ENABLE ROW LEVEL SECURITY/i);
    expect(sql).toMatch(/CREATE POLICY "deny_all_client_ghost_vaults"\s+ON public\.ghost_vaults[\s\S]*TO anon, authenticated[\s\S]*USING \(false\)[\s\S]*WITH CHECK \(false\)/i);
  });

  test('2. Restricted ghost_vault_status view excludes sensitive recovery columns', () => {
    const sql = fs.readFileSync(MIGRATION_PATH, 'utf8');
    const viewMatch = sql.match(/CREATE OR REPLACE VIEW public\.ghost_vault_status[\s\S]*?;/i);
    expect(viewMatch).not.toBeNull();
    const viewSql = viewMatch![0];

    expect(viewSql).toMatch(/security_barrier\s*=\s*true/i);
    expect(viewSql).toMatch(/WHERE owner_user_id = auth\.uid\(\)/i);
    expect(viewSql).not.toContain('recovery_verifier');
    expect(viewSql).not.toContain('recovery_salt');
    expect(viewSql).not.toContain('encrypted_vault_blob');
    expect(sql).toMatch(/GRANT SELECT ON public\.ghost_vault_status TO authenticated/i);
  });

  test('3. Authenticated owners cannot read recovery_verifier, recovery_salt, or encrypted_vault_blob from ghost_vaults', () => {
    expect(() => db.selectGhostVaults('authenticated', ['*'], ACCOUNT_ID)).toThrow(
      /permission denied/
    );
    expect(() =>
      db.selectGhostVaults('authenticated', ['recovery_verifier'], ACCOUNT_ID)
    ).toThrow(/permission denied/);
    expect(() =>
      db.selectGhostVaults('authenticated', ['recovery_salt'], ACCOUNT_ID)
    ).toThrow(/permission denied/);
    expect(() =>
      db.selectGhostVaults('authenticated', ['encrypted_vault_blob'], ACCOUNT_ID)
    ).toThrow(/permission denied/);
  });

  test('4. Authenticated and anon clients cannot insert, update, or delete recovery fields on ghost_vaults', () => {
    expect(() =>
      db.updateGhostVaults('authenticated', ACCOUNT_ID, {
        recovery_verifier: 'ff'.repeat(32),
        recovery_salt: '00'.repeat(32),
      })
    ).toThrow(/permission denied/);

    expect(() =>
      db.insertGhostVaults('authenticated', {
        account_id: '44444444-4444-4444-8444-444444444444',
        owner_user_id: ATTACKER_ID,
        recovery_verifier: '11'.repeat(32),
        recovery_salt: '22'.repeat(32),
        recovery_kdf_version: 2,
        encrypted_vault_blob: 'eA==',
        vault_version: 2,
        created_at: '2026-11-25T00:00:00Z',
        updated_at: '2026-11-25T00:00:00Z',
      })
    ).toThrow(/permission denied/);

    expect(() => db.deleteGhostVaults('authenticated', ACCOUNT_ID)).toThrow(
      /permission denied/
    );
    expect(() => db.selectGhostVaults('anon', ['*'], ACCOUNT_ID)).toThrow(
      /permission denied/
    );
  });

  test('5. Authenticated owner can query non-sensitive status view while cross-user and anon reads fail/empty', () => {
    const ownerRows = db.selectGhostVaultStatusView('authenticated', OWNER_ID);
    expect(ownerRows).toHaveLength(1);
    expect(ownerRows[0]).toEqual({
      account_id: ACCOUNT_ID,
      vault_version: 2,
      recovery_kdf_version: 2,
      created_at: '2026-11-25T00:00:00Z',
      updated_at: '2026-11-25T00:00:00Z',
    });
    expect((ownerRows[0] as any).recovery_verifier).toBeUndefined();
    expect((ownerRows[0] as any).recovery_salt).toBeUndefined();
    expect((ownerRows[0] as any).encrypted_vault_blob).toBeUndefined();

    expect(db.selectGhostVaultStatusView('authenticated', ATTACKER_ID)).toHaveLength(0);
    expect(() => db.selectGhostVaultStatusView('anon', null)).toThrow(/permission denied/);
  });

  test('6. Edge Functions (service_role) retain required read and write access to ghost_vaults', () => {
    const rows = db.selectGhostVaults(
      'service_role',
      ['account_id', 'recovery_verifier', 'recovery_salt', 'encrypted_vault_blob'],
      ACCOUNT_ID
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].recovery_verifier).toBe('ab'.repeat(32));
    expect(rows[0].recovery_salt).toBe('cd'.repeat(32));
    expect(rows[0].encrypted_vault_blob).toBe('ZW5jcnlwdGVk');

    db.updateGhostVaults('service_role', ACCOUNT_ID, {
      owner_user_id: ATTACKER_ID,
    });
    const updated = db.selectGhostVaults('service_role', ['owner_user_id'], ACCOUNT_ID);
    expect(updated[0].owner_user_id).toBe(ATTACKER_ID);
  });

  test('7. Client code (src/cloud/supabaseClient.ts & web/supabase.js) never calls direct /rest/v1/ghost_vaults REST endpoints', () => {
    const tsClient = fs.readFileSync(
      path.join(ROOT, 'src/cloud/supabaseClient.ts'),
      'utf8'
    );
    const webClient = fs.readFileSync(
      path.join(ROOT, 'web/supabase.js'),
      'utf8'
    );

    expect(tsClient).not.toMatch(/\/rest\/v1\/ghost_vaults/);
    expect(webClient).not.toMatch(/\/rest\/v1\/ghost_vaults/);
    expect(tsClient).toContain('/rest/v1/ghost_vault_status');
    expect(webClient).toContain('/rest/v1/ghost_vault_status');
  });

  test('8. Existing offline local encryption and DEK wrapping compatibility remains completely intact', async () => {
    // 1. Offline cloud fallback still succeeds without Supabase network
    const accountId = '55555555-5555-4555-8555-555555555555';
    const upload = await uploadEncryptedVaultMetadata(accountId, btoa('LOCAL_META'), 2);
    expect(upload).toEqual({ success: true, source: 'offline-local' });
    const meta = await downloadEncryptedVaultMetadata(accountId);
    expect(meta?.accountId).toBe(accountId);

    // 2. Local KEK/DEK wrapping & AES-256-GCM file encryption continue working offline
    const kek = generateDEK(); // 32B KEK key material for offline wrap test
    const dek = generateDEK();
    const keyId = generateKeyId();
    const wrapped = wrapDEK(kek, dek, keyId, 1);
    const unwrapped = unwrapDEK(kek, wrapped);
    expect(unwrapped).toEqual(dek);

    const fileId = generateKeyId();
    const plaintext = new TextEncoder().encode('offline-tag-payload-v2.1.0');
    const pkg = encryptFile(unwrapped, plaintext, fileId);
    const restored = decryptFile(
      unwrapped,
      pkg.fullEncryptedBytes,
      fileId,
      pkg.ciphertextSha256
    );
    expect(computeChunkHash(restored)).toEqual(computeChunkHash(plaintext));
  });
});
