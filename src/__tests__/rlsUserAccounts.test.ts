/**
 * @file rlsUserAccounts.test.ts
 * @summary Verifies PR #2 Schema Security Guarantees:
 * - Zero direct client reads or writes on public.user_accounts (including recovery_verifier,
 *   recovery_salt, encrypted_recovery_envelope, account_status, deletion_scheduled_at)
 * - public.user_profile view restricted via security_barrier and auth.uid() with zero secret columns
 * - Zero client mutations on public.account_deletion_requests, recovery_challenges,
 *   account_provisioning_salts, turnstile_consumed_tokens, rate_limit_*, audit_events
 * - public.vault_metadata restricts writes to service_role and enforces 78B wrapped_dek
 * - SECURITY DEFINER RPCs lock search_path = '' and revoke client EXECUTE
 */

export {};
declare const require: any;
declare const __dirname: string;
const fs = require('fs');
const path = require('path');

describe('PR #2: v2.1.0 PostgreSQL Schema & RLS Access Boundaries', () => {
  const ROOT = path.resolve(__dirname, '../..');
  const MIGRATION_PATH = path.join(
    ROOT,
    'supabase/migrations/20261126_v210_account_security_schema.sql'
  );
  const sql: string = fs.readFileSync(MIGRATION_PATH, 'utf8');

  const LOCKED_SERVICE_ONLY_TABLES = [
    'user_accounts',
    'account_provisioning_salts',
    'recovery_challenges',
    'turnstile_consumed_tokens',
    'account_deletion_requests',
    'rate_limit_configs',
    'rate_limit_buckets',
    'audit_events',
  ];

  test.each(LOCKED_SERVICE_ONLY_TABLES)(
    'table public.%s enables RLS, revokes PUBLIC/anon/authenticated, grants service_role, and installs deny-all policy',
    (tableName) => {
      expect(sql).toMatch(
        new RegExp(
          `ALTER TABLE public\\.${tableName} ENABLE ROW LEVEL SECURITY;`,
          'i'
        )
      );
      expect(sql).toMatch(
        new RegExp(
          `REVOKE ALL ON public\\.${tableName} FROM PUBLIC, anon, authenticated;`,
          'i'
        )
      );
      expect(sql).toMatch(
        new RegExp(
          `GRANT ALL ON public\\.${tableName} TO service_role;`,
          'i'
        )
      );
      expect(sql).toMatch(
        new RegExp(
          `CREATE POLICY "deny_all_client_[^"]+"\\s+ON public\\.${tableName}\\s+FOR ALL TO anon, authenticated\\s+USING \\(false\\)\\s+WITH CHECK \\(false\\);`,
          'i'
        )
      );
    }
  );

  test('public.user_accounts enforces 1-email-to-1-account case-insensitive uniqueness and 32B verifier/salt checks', () => {
    expect(sql).toMatch(/CREATE UNIQUE INDEX IF NOT EXISTS uq_user_accounts_lower_email\s+ON public\.user_accounts \(lower\(email\)\);/i);
    expect(sql).toMatch(/CONSTRAINT chk_user_verifier_len CHECK \(octet_length\(recovery_verifier\) = 32\)/i);
    expect(sql).toMatch(/CONSTRAINT chk_user_salt_len CHECK \(octet_length\(recovery_salt\) = 32\)/i);
    expect(sql).toMatch(/CONSTRAINT chk_user_envelope_nonempty CHECK \(octet_length\(encrypted_recovery_envelope\) >= 32\)/i);
    expect(sql).toMatch(/recovery_kdf_version SMALLINT NOT NULL DEFAULT 2/i);
  });

  test('public.user_profile view uses security_barrier, auth.uid() guard, and never exposes sensitive recovery columns', () => {
    const viewMatch = sql.match(
      /CREATE OR REPLACE VIEW public\.user_profile[\s\S]*?FROM public\.user_accounts[\s\S]*?;/i
    );
    expect(viewMatch).not.toBeNull();
    const viewSql = viewMatch![0];

    expect(viewSql).toMatch(/WITH \(security_barrier = true\)/i);
    expect(viewSql).toMatch(/WHERE id = auth\.uid\(\)\s+AND auth\.uid\(\) IS NOT NULL/i);

    expect(viewSql).not.toMatch(/recovery_verifier/i);
    expect(viewSql).not.toMatch(/recovery_salt/i);
    expect(viewSql).not.toMatch(/encrypted_recovery_envelope/i);
    expect(viewSql).not.toMatch(/purge_started_at/i);

    expect(sql).toMatch(/REVOKE ALL ON public\.user_profile FROM PUBLIC, anon, authenticated;/i);
    expect(sql).toMatch(/GRANT SELECT ON public\.user_profile TO authenticated;/i);
  });

  test('public.vault_metadata blocks direct client writes and enforces 78-byte wrapped_dek + 16-byte key_id prefix', () => {
    expect(sql).toMatch(/wrapped_dek BYTEA NOT NULL CHECK \(octet_length\(wrapped_dek\) = 78\)/i);
    expect(sql).toMatch(/key_id BYTEA NOT NULL CHECK \(octet_length\(key_id\) = 16\)/i);
    expect(sql).toMatch(/CONSTRAINT chk_vm_wrapped_dek_prefix CHECK \(substring\(wrapped_dek FROM 1 FOR 16\) = key_id\)/i);

    expect(sql).toMatch(/REVOKE ALL ON public\.vault_metadata FROM PUBLIC, anon, authenticated;/i);
    expect(sql).toMatch(/GRANT SELECT ON public\.vault_metadata TO authenticated;/i);
    expect(sql).not.toMatch(/GRANT (ALL|INSERT|UPDATE|DELETE) ON public\.vault_metadata TO authenticated;/i);
    expect(sql).toMatch(
      /CREATE POLICY "vault_metadata_select_owner"\s+ON public\.vault_metadata\s+FOR SELECT TO authenticated\s+USING \(auth\.uid\(\) = user_id AND auth\.uid\(\) IS NOT NULL\);/i
    );
  });

  test('all SECURITY DEFINER functions enforce empty search_path and revoke EXECUTE from PUBLIC/anon/authenticated', () => {
    const rpcs = [
      'consume_recovery_challenge(UUID)',
      'schedule_account_deletion_rpc(UUID)',
      'cancel_account_deletion_rpc(UUID)',
      'claim_expired_deletion_requests(INTEGER)',
      'check_rate_limit(TEXT, TEXT)',
      'jsonb_contains_forbidden_audit_content(JSONB, INTEGER)',
      'validate_audit_event_details()',
    ];

    const definerMatches = sql.match(/SECURITY DEFINER/gi) || [];
    const searchPathMatches = sql.match(/SET search_path = ''/gi) || [];
    expect(definerMatches.length).toBe(rpcs.length);
    expect(searchPathMatches.length).toBe(rpcs.length);

    for (const sig of rpcs) {
      const escaped = sig.replace(/[()]/g, '\\$&');
      expect(sql).toMatch(
        new RegExp(`REVOKE ALL ON FUNCTION public\\.${escaped} FROM PUBLIC, anon, authenticated;`, 'i')
      );
      expect(sql).toMatch(
        new RegExp(`GRANT EXECUTE ON FUNCTION public\\.${escaped} TO service_role;`, 'i')
      );
    }
  });
});
