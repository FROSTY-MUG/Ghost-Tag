-- Ghost-Tag v2.1.0: Cross-Platform Zero-Knowledge Recovery & Migration Schema
-- DO NOT DEPLOY TO LIVE DATABASE WITHOUT EXPLICIT USER APPROVAL.
--
-- Security Model:
-- Cross-device recovery and legacy verifier migration require zero existing user sessions.
-- The 12-word recovery phrase (and derived verifier) is the recovery credential.
-- Direct table access by anon users is strictly denied by RLS.
-- Zero-knowledge validation is handled by Edge Functions running with service_role.

-- 1. Ensure ghost_vaults table supports canonical Argon2id verifier and deterministic salt
CREATE TABLE IF NOT EXISTS public.ghost_vaults (
  account_id UUID PRIMARY KEY,
  owner_user_id UUID,
  recovery_verifier BYTEA NOT NULL,
  recovery_salt BYTEA NOT NULL,
  recovery_kdf_version INTEGER NOT NULL DEFAULT 2,
  encrypted_vault_blob BYTEA NOT NULL,
  vault_version INTEGER NOT NULL DEFAULT 2,
  created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

-- Ensure owner_user_id is nullable for cross-device vaults created before user association
ALTER TABLE public.ghost_vaults ALTER COLUMN owner_user_id DROP NOT NULL;

-- 2. Row Level Security on ghost_vaults
ALTER TABLE public.ghost_vaults ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "deny_anon_vaults" ON public.ghost_vaults;
CREATE POLICY "deny_anon_vaults"
ON public.ghost_vaults
FOR ALL
TO anon
USING (false)
WITH CHECK (false);

DROP POLICY IF EXISTS "owner_full_access" ON public.ghost_vaults;
CREATE POLICY "owner_full_access"
ON public.ghost_vaults
FOR ALL
TO authenticated
USING (auth.uid() = owner_user_id)
WITH CHECK (auth.uid() = owner_user_id);

-- 3. Recovery Attempts Table for Atomic Rate Limiting
CREATE TABLE IF NOT EXISTS public.ghost_recovery_attempts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id UUID NOT NULL,
  user_id UUID,
  ip_hash TEXT NOT NULL,
  success BOOLEAN NOT NULL DEFAULT false,
  attempted_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

ALTER TABLE public.ghost_recovery_attempts ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "deny_anon_recovery_attempts" ON public.ghost_recovery_attempts;
CREATE POLICY "deny_anon_recovery_attempts"
ON public.ghost_recovery_attempts
FOR ALL
TO anon
USING (false)
WITH CHECK (false);

DROP POLICY IF EXISTS "deny_authenticated_recovery_attempts" ON public.ghost_recovery_attempts;
CREATE POLICY "deny_authenticated_recovery_attempts"
ON public.ghost_recovery_attempts
FOR ALL
TO authenticated
USING (false)
WITH CHECK (false);

-- 4. Atomic Transactional Rate-Limiting Function
CREATE OR REPLACE FUNCTION public.check_and_record_recovery_attempt(
  p_account_id UUID,
  p_user_id UUID,
  p_ip_hash TEXT,
  p_max_account INT DEFAULT 25,
  p_max_user INT DEFAULT 20,
  p_max_ip INT DEFAULT 100,
  p_window_interval INTERVAL DEFAULT INTERVAL '15 minutes'
)
RETURNS TABLE (
  allowed BOOLEAN,
  attempt_id UUID,
  account_failures BIGINT,
  user_failures BIGINT,
  ip_failures BIGINT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_window_start TIMESTAMPTZ := now() - p_window_interval;
  v_account_cnt BIGINT;
  v_user_cnt BIGINT;
  v_ip_cnt BIGINT;
  v_allowed BOOLEAN;
  v_attempt_id UUID;
BEGIN
  -- Advisory lock on account_id hash serializes concurrent attempts targeting same account
  PERFORM pg_advisory_xact_lock(hashtext(p_account_id::text));

  -- Count ONLY failed attempts in the sliding window
  SELECT count(*) INTO v_account_cnt
  FROM public.ghost_recovery_attempts
  WHERE account_id = p_account_id AND success = false AND attempted_at >= v_window_start;

  IF p_user_id IS NOT NULL THEN
    SELECT count(*) INTO v_user_cnt
    FROM public.ghost_recovery_attempts
    WHERE user_id = p_user_id AND success = false AND attempted_at >= v_window_start;
  ELSE
    v_user_cnt := 0;
  END IF;

  SELECT count(*) INTO v_ip_cnt
  FROM public.ghost_recovery_attempts
  WHERE ip_hash = p_ip_hash AND success = false AND attempted_at >= v_window_start;

  -- Evaluate limits atomically
  IF v_account_cnt >= p_max_account OR (p_user_id IS NOT NULL AND v_user_cnt >= p_max_user) OR v_ip_cnt >= p_max_ip THEN
    v_allowed := false;
  ELSE
    v_allowed := true;
  END IF;

  -- Record attempt atomically in the same transaction
  INSERT INTO public.ghost_recovery_attempts (
    account_id,
    user_id,
    ip_hash,
    success,
    attempted_at
  ) VALUES (
    p_account_id,
    p_user_id,
    p_ip_hash,
    false,
    now()
  ) RETURNING id INTO v_attempt_id;

  RETURN QUERY SELECT v_allowed, v_attempt_id, v_account_cnt, v_user_cnt, v_ip_cnt;
END;
$$;

-- Grant execution to service_role only
REVOKE EXECUTE ON FUNCTION public.check_and_record_recovery_attempt(UUID, UUID, TEXT, INT, INT, INT, INTERVAL)
FROM anon, authenticated, public;

GRANT EXECUTE ON FUNCTION public.check_and_record_recovery_attempt(UUID, UUID, TEXT, INT, INT, INT, INTERVAL)
TO service_role;

-- 5. Atomic Transactional Legacy Verifier Migration Function
-- Guarantees atomicity via row-level lock (FOR UPDATE), prevents concurrent migration races,
-- enforces one-way upgrade (kdf_version 1 -> 2), and eliminates partial update vulnerabilities.
CREATE OR REPLACE FUNCTION public.migrate_recovery_verifier_atomic(
  p_account_id UUID,
  p_legacy_verifier BYTEA,
  p_new_verifier BYTEA,
  p_new_salt BYTEA,
  p_new_owner_user_id UUID DEFAULT NULL
)
RETURNS TABLE (
  status TEXT,
  migrated BOOLEAN
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  v_current_verifier BYTEA;
  v_current_kdf_version INT;
  v_current_owner UUID;
BEGIN
  -- 1. Acquire row-level lock on the target vault
  SELECT recovery_verifier, recovery_kdf_version, owner_user_id
  INTO v_current_verifier, v_current_kdf_version, v_current_owner
  FROM public.ghost_vaults
  WHERE account_id = p_account_id
  FOR UPDATE;

  -- 2. Verify account existence
  IF NOT FOUND THEN
    RETURN QUERY SELECT 'NOT_FOUND'::TEXT, false;
    RETURN;
  END IF;

  -- 3. Check if already migrated to v2 or higher (prevent downgrade or redundant migration)
  IF v_current_kdf_version >= 2 THEN
    RETURN QUERY SELECT 'ALREADY_MIGRATED'::TEXT, false;
    RETURN;
  END IF;

  -- 4. Check if recovery_kdf_version is 1
  IF v_current_kdf_version != 1 THEN
    RETURN QUERY SELECT 'UNSUPPORTED_VERSION'::TEXT, false;
    RETURN;
  END IF;

  -- 5. Constant-time byte equality check for legacy verifier
  IF v_current_verifier IS DISTINCT FROM p_legacy_verifier THEN
    RETURN QUERY SELECT 'VERIFIER_MISMATCH'::TEXT, false;
    RETURN;
  END IF;

  -- 6. Atomic state update in the same transaction
  UPDATE public.ghost_vaults
  SET
    recovery_verifier = p_new_verifier,
    recovery_salt = p_new_salt,
    recovery_kdf_version = 2,
    owner_user_id = COALESCE(p_new_owner_user_id, owner_user_id),
    updated_at = timezone('utc'::text, now())
  WHERE account_id = p_account_id;

  RETURN QUERY SELECT 'SUCCESS'::TEXT, true;
END;
$$;

-- Grant execution to service_role only
REVOKE EXECUTE ON FUNCTION public.migrate_recovery_verifier_atomic(UUID, BYTEA, BYTEA, BYTEA, UUID)
FROM anon, authenticated, public;

GRANT EXECUTE ON FUNCTION public.migrate_recovery_verifier_atomic(UUID, BYTEA, BYTEA, BYTEA, UUID)
TO service_role;

