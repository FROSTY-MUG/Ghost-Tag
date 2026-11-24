-- ============================================================================
-- Ghost-Tag v2.1.0 Migration: Lock Down Legacy ghost_vaults
-- ============================================================================
-- Remediates excessive RLS exposure where prior migrations granted authenticated
-- owners direct SELECT/UPDATE access to recovery_verifier, recovery_salt,
-- and encrypted_vault_blob via policy "owner_full_access".
--
-- Security Invariants Enforced:
--   1. Direct client access (SELECT, INSERT, UPDATE, DELETE) on public.ghost_vaults
--      is completely revoked for PUBLIC, anon, and authenticated roles.
--   2. service_role retains full access so Edge Functions (recover-vault,
--      migrate-recovery-verifier) operate exclusively through constant-time checks.
--   3. Authenticated owners may query public.ghost_vault_status (security_barrier view)
--      which exposes ONLY non-sensitive metadata (account_id, vault_version,
--      recovery_kdf_version, created_at, updated_at) and NEVER exposes
--      recovery_verifier, recovery_salt, or encrypted_vault_blob.
--   4. Local/offline AES-256-GCM encryption and NFC tag formats are unaffected.

BEGIN;

-- 1. Drop unsafe owner_full_access and stale per-role policies
DROP POLICY IF EXISTS "owner_full_access" ON public.ghost_vaults;
DROP POLICY IF EXISTS "deny_anon_vaults" ON public.ghost_vaults;
DROP POLICY IF EXISTS "ghost_vaults_select_owner" ON public.ghost_vaults;
DROP POLICY IF EXISTS "ghost_vaults_insert_owner" ON public.ghost_vaults;
DROP POLICY IF EXISTS "ghost_vaults_update_owner" ON public.ghost_vaults;
DROP POLICY IF EXISTS "ghost_vaults_delete_owner" ON public.ghost_vaults;

-- 2. Revoke all direct client privileges; grant exclusive table access to service_role
REVOKE ALL ON public.ghost_vaults FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.ghost_vaults TO service_role;

-- 3. Ensure RLS stays enabled and enforce explicit deny-all for client roles
ALTER TABLE public.ghost_vaults ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "deny_all_client_ghost_vaults" ON public.ghost_vaults;
CREATE POLICY "deny_all_client_ghost_vaults"
ON public.ghost_vaults
FOR ALL
TO anon, authenticated
USING (false)
WITH CHECK (false);

-- 4. Restricted status-only view for safe authenticated owner checks
-- Intentionally executes with view-owner privileges (not security_invoker)
-- under security_barrier = true so authenticated owners can inspect migration/sync
-- version state strictly for auth.uid() without table SELECT access to sensitive columns.
CREATE OR REPLACE VIEW public.ghost_vault_status
WITH (security_barrier = true) AS
SELECT
    account_id,
    vault_version,
    recovery_kdf_version,
    created_at,
    updated_at
FROM public.ghost_vaults
WHERE owner_user_id = auth.uid()
  AND auth.uid() IS NOT NULL;

REVOKE ALL ON public.ghost_vault_status FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.ghost_vault_status TO authenticated;

COMMIT;
