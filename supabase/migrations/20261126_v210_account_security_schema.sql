-- Ghost-Tag v2.1.0 - Zero-Knowledge Account, Rate-Limit, Audit & Deletion Schema
-- Implements Mandatory Corrections #1-#5:
--   - Service-role locked user_accounts & account_provisioning_salts (no client recovery mutation)
--   - Restricted security_barrier user_profile view
--   - Single-use recovery_challenges with atomic consume RPC
--   - Turnstile replay guard table (turnstile_consumed_tokens)
--   - Canonical 78-byte wrapped_dek constraint on vault_metadata
--   - 48-hour grace period account_deletion_requests with SKIP LOCKED purge claim RPC
--   - Concurrency-safe INSERT...ON CONFLICT check_rate_limit() (fail-closed)
--   - Database-boundary recursive JSONB audit_events sanitization trigger

CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- 1. USER ACCOUNTS (Service-Role Only; Zero Direct Client Access)
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.user_accounts (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    recovery_verifier BYTEA NOT NULL,
    recovery_salt BYTEA NOT NULL,
    encrypted_recovery_envelope BYTEA NOT NULL,
    recovery_kdf_version SMALLINT NOT NULL DEFAULT 2 CHECK (recovery_kdf_version >= 1),
    account_status TEXT NOT NULL DEFAULT 'active'
        CHECK (account_status IN ('active', 'deletion_pending', 'purging', 'deleted')),
    deletion_scheduled_at TIMESTAMPTZ NULL,
    deletion_effective_at TIMESTAMPTZ NULL,
    purge_started_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT chk_user_email_normalized CHECK (email = lower(trim(email)) AND length(email) BETWEEN 3 AND 320),
    CONSTRAINT chk_user_verifier_len CHECK (octet_length(recovery_verifier) = 32),
    CONSTRAINT chk_user_salt_len CHECK (octet_length(recovery_salt) = 32),
    CONSTRAINT chk_user_envelope_nonempty CHECK (octet_length(encrypted_recovery_envelope) >= 32),
    CONSTRAINT chk_deletion_timestamps CHECK (
        (account_status = 'active' AND deletion_scheduled_at IS NULL AND deletion_effective_at IS NULL)
        OR (account_status IN ('deletion_pending', 'purging', 'deleted'))
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_accounts_lower_email
    ON public.user_accounts (lower(email));

ALTER TABLE public.user_accounts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.user_accounts FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.user_accounts TO service_role;

DROP POLICY IF EXISTS "deny_all_client_user_accounts" ON public.user_accounts;
CREATE POLICY "deny_all_client_user_accounts"
    ON public.user_accounts
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

-- =============================================================================
-- 2. EPHEMERAL PROVISIONING SALTS (Two-Step Init -> Complete)
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.account_provisioning_salts (
    user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,
    recovery_salt BYTEA NOT NULL CHECK (octet_length(recovery_salt) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT chk_aps_email_normalized CHECK (email = lower(trim(email)) AND length(email) BETWEEN 3 AND 320)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_aps_lower_email
    ON public.account_provisioning_salts (lower(email));

ALTER TABLE public.account_provisioning_salts ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.account_provisioning_salts FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.account_provisioning_salts TO service_role;

DROP POLICY IF EXISTS "deny_all_client_aps" ON public.account_provisioning_salts;
CREATE POLICY "deny_all_client_aps"
    ON public.account_provisioning_salts
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

-- =============================================================================
-- 3. RESTRICTED CLIENT PROFILE VIEW (Strictly Non-Sensitive Fields Only)
-- =============================================================================
CREATE OR REPLACE VIEW public.user_profile
WITH (security_barrier = true) AS
SELECT
    id AS account_id,
    email,
    account_status,
    CASE
        WHEN account_status = 'deletion_pending' THEN deletion_effective_at
        ELSE NULL
    END AS deletion_effective_at,
    created_at,
    updated_at
FROM public.user_accounts
WHERE id = auth.uid()
  AND auth.uid() IS NOT NULL;

REVOKE ALL ON public.user_profile FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.user_profile TO authenticated;
GRANT SELECT ON public.user_profile TO service_role;

-- =============================================================================
-- 4. RECOVERY CHALLENGES (Single-Use Server Challenge State)
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.recovery_challenges (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id UUID NOT NULL REFERENCES public.user_accounts(id) ON DELETE CASCADE,
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    server_timestamp BIGINT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT false,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_recovery_challenges_active
    ON public.recovery_challenges (expires_at)
    WHERE consumed = false;

ALTER TABLE public.recovery_challenges ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.recovery_challenges FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.recovery_challenges TO service_role;

DROP POLICY IF EXISTS "deny_all_client_recovery_challenges" ON public.recovery_challenges;
CREATE POLICY "deny_all_client_recovery_challenges"
    ON public.recovery_challenges
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

CREATE OR REPLACE FUNCTION public.consume_recovery_challenge(
    p_challenge_id UUID
)
RETURNS TABLE (
    account_id UUID,
    nonce BYTEA,
    server_timestamp BIGINT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    IF p_challenge_id IS NULL THEN
        RETURN;
    END IF;

    RETURN QUERY
    UPDATE public.recovery_challenges AS rc
    SET consumed = true,
        consumed_at = clock_timestamp()
    WHERE rc.id = p_challenge_id
      AND rc.consumed = false
      AND rc.expires_at > clock_timestamp()
    RETURNING rc.account_id, rc.nonce, rc.server_timestamp;
END;
$$;

REVOKE ALL ON FUNCTION public.consume_recovery_challenge(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_recovery_challenge(UUID) TO service_role;

-- =============================================================================
-- 5. TURNSTILE TOKEN REPLAY GUARD
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.turnstile_consumed_tokens (
    token_hash TEXT PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    action TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE INDEX IF NOT EXISTS idx_turnstile_tokens_expires
    ON public.turnstile_consumed_tokens (expires_at);

ALTER TABLE public.turnstile_consumed_tokens ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.turnstile_consumed_tokens FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.turnstile_consumed_tokens TO service_role;

DROP POLICY IF EXISTS "deny_all_client_turnstile_tokens" ON public.turnstile_consumed_tokens;
CREATE POLICY "deny_all_client_turnstile_tokens"
    ON public.turnstile_consumed_tokens
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

-- =============================================================================
-- 6. VAULT METADATA (78-Byte Canonical wrapped_dek + Key Prefix Check)
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.vault_metadata (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    vault_id BYTEA NOT NULL CHECK (octet_length(vault_id) = 16),
    encrypted_vault_name BYTEA NOT NULL,
    encrypted_vault_manifest BYTEA NOT NULL,
    wrapped_dek BYTEA NOT NULL CHECK (octet_length(wrapped_dek) = 78),
    key_id BYTEA NOT NULL CHECK (octet_length(key_id) = 16),
    total_chunk_count INTEGER NOT NULL CHECK (total_chunk_count > 0),
    erasure_params BYTEA NOT NULL,
    integrity_hash BYTEA NOT NULL CHECK (octet_length(integrity_hash) = 32),
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT uq_user_vault_id UNIQUE (user_id, vault_id),
    CONSTRAINT chk_vm_wrapped_dek_prefix CHECK (substring(wrapped_dek FROM 1 FOR 16) = key_id)
);

ALTER TABLE public.vault_metadata ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.vault_metadata FROM PUBLIC, anon, authenticated;
GRANT SELECT ON public.vault_metadata TO authenticated;
GRANT ALL ON public.vault_metadata TO service_role;

DROP POLICY IF EXISTS "vault_metadata_select_owner" ON public.vault_metadata;
CREATE POLICY "vault_metadata_select_owner"
    ON public.vault_metadata
    FOR SELECT TO authenticated
    USING (auth.uid() = user_id AND auth.uid() IS NOT NULL);

-- =============================================================================
-- 7. ACCOUNT DELETION REQUESTS (48-Hour Grace Period + Purge State)
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.account_deletion_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
    scheduled_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    expires_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now() + INTERVAL '48 hours'),
    cancelled_at TIMESTAMPTZ NULL,
    completed_at TIMESTAMPTZ NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'cancelled', 'completed', 'failed_manual_review')),
    purge_attempts INTEGER NOT NULL DEFAULT 0 CHECK (purge_attempts >= 0),
    next_retry_at TIMESTAMPTZ NULL,
    last_error_code TEXT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now())
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_active_deletion_per_user
    ON public.account_deletion_requests (user_id)
    WHERE status IN ('pending', 'processing');

ALTER TABLE public.account_deletion_requests ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.account_deletion_requests FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.account_deletion_requests TO service_role;

DROP POLICY IF EXISTS "deny_all_client_deletion_requests" ON public.account_deletion_requests;
CREATE POLICY "deny_all_client_deletion_requests"
    ON public.account_deletion_requests
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

CREATE OR REPLACE FUNCTION public.schedule_account_deletion_rpc(
    p_user_id UUID
)
RETURNS TABLE (
    request_id UUID,
    scheduled_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    status TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_now TIMESTAMPTZ := timezone('utc'::text, now());
    v_effective TIMESTAMPTZ := v_now + INTERVAL '48 hours';
    v_existing RECORD;
    v_inserted RECORD;
BEGIN
    IF p_user_id IS NULL THEN
        RAISE EXCEPTION 'INVALID_USER';
    END IF;

    SELECT id, adr.scheduled_at, adr.expires_at, adr.status
    INTO v_existing
    FROM public.account_deletion_requests AS adr
    WHERE adr.user_id = p_user_id
      AND adr.status IN ('pending', 'processing')
    FOR UPDATE;

    IF FOUND THEN
        RETURN QUERY SELECT v_existing.id, v_existing.scheduled_at, v_existing.expires_at, v_existing.status;
        RETURN;
    END IF;

    UPDATE public.user_accounts
    SET account_status = 'deletion_pending',
        deletion_scheduled_at = v_now,
        deletion_effective_at = v_effective,
        updated_at = v_now
    WHERE id = p_user_id
      AND account_status = 'active';

    INSERT INTO public.account_deletion_requests (
        user_id, scheduled_at, expires_at, status
    )
    VALUES (
        p_user_id, v_now, v_effective, 'pending'
    )
    RETURNING id, account_deletion_requests.scheduled_at, account_deletion_requests.expires_at, account_deletion_requests.status
    INTO v_inserted;

    RETURN QUERY SELECT v_inserted.id, v_inserted.scheduled_at, v_inserted.expires_at, v_inserted.status;
END;
$$;

REVOKE ALL ON FUNCTION public.schedule_account_deletion_rpc(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.schedule_account_deletion_rpc(UUID) TO service_role;

CREATE OR REPLACE FUNCTION public.cancel_account_deletion_rpc(
    p_user_id UUID
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_now TIMESTAMPTZ := clock_timestamp();
    v_req_id UUID;
BEGIN
    IF p_user_id IS NULL THEN
        RETURN FALSE;
    END IF;

    UPDATE public.account_deletion_requests
    SET status = 'cancelled',
        cancelled_at = v_now
    WHERE user_id = p_user_id
      AND status = 'pending'
      AND expires_at > v_now
    RETURNING id INTO v_req_id;

    IF NOT FOUND THEN
        RETURN FALSE;
    END IF;

    UPDATE public.user_accounts
    SET account_status = 'active',
        deletion_scheduled_at = NULL,
        deletion_effective_at = NULL,
        updated_at = v_now
    WHERE id = p_user_id
      AND account_status = 'deletion_pending';

    RETURN TRUE;
END;
$$;

REVOKE ALL ON FUNCTION public.cancel_account_deletion_rpc(UUID) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.cancel_account_deletion_rpc(UUID) TO service_role;

CREATE OR REPLACE FUNCTION public.claim_expired_deletion_requests(
    p_batch_size INTEGER DEFAULT 25
)
RETURNS TABLE (
    request_id UUID,
    user_id UUID,
    scheduled_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    purge_attempts INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_now TIMESTAMPTZ := clock_timestamp();
    v_limit INTEGER := LEAST(GREATEST(COALESCE(p_batch_size, 25), 1), 100);
BEGIN
    RETURN QUERY
    WITH claimable AS (
        SELECT r.id
        FROM public.account_deletion_requests AS r
        WHERE r.purge_attempts < 10
          AND (
              (r.status = 'pending' AND r.expires_at <= v_now)
              OR (
                  r.status = 'processing'
                  AND r.next_retry_at IS NOT NULL
                  AND r.next_retry_at <= v_now
              )
          )
        ORDER BY r.expires_at ASC
        LIMIT v_limit
        FOR UPDATE OF r SKIP LOCKED
    ),
    updated_reqs AS (
        UPDATE public.account_deletion_requests AS r
        SET status = 'processing',
            next_retry_at = v_now + INTERVAL '15 minutes'
        FROM claimable AS c
        WHERE r.id = c.id
        RETURNING r.id, r.user_id, r.scheduled_at, r.expires_at, r.purge_attempts
    ),
    updated_accounts AS (
        UPDATE public.user_accounts AS ua
        SET account_status = 'purging',
            purge_started_at = COALESCE(ua.purge_started_at, v_now),
            updated_at = v_now
        FROM updated_reqs AS u
        WHERE ua.id = u.user_id
    )
    SELECT u.id, u.user_id, u.scheduled_at, u.expires_at, u.purge_attempts
    FROM updated_reqs AS u;
END;
$$;

REVOKE ALL ON FUNCTION public.claim_expired_deletion_requests(INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_expired_deletion_requests(INTEGER) TO service_role;

-- =============================================================================
-- 8. CONFIGURABLE ATOMIC RATE LIMITING (Fail-Closed & Concurrency-Safe)
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.rate_limit_configs (
    action TEXT PRIMARY KEY,
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    window_seconds INTEGER NOT NULL CHECK (window_seconds > 0),
    block_duration_seconds INTEGER NOT NULL CHECK (block_duration_seconds > 0)
);

INSERT INTO public.rate_limit_configs (action, max_attempts, window_seconds, block_duration_seconds)
VALUES
    ('auth_provision', 5, 900, 900),
    ('recovery_challenge', 10, 3600, 3600),
    ('recovery_proof', 5, 3600, 3600),
    ('password_reset', 5, 3600, 3600),
    ('vault_sync', 60, 60, 120),
    ('account_deletion', 3, 86400, 86400),
    ('verify_captcha', 20, 60, 300)
ON CONFLICT (action) DO UPDATE
SET max_attempts = EXCLUDED.max_attempts,
    window_seconds = EXCLUDED.window_seconds,
    block_duration_seconds = EXCLUDED.block_duration_seconds;

ALTER TABLE public.rate_limit_configs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.rate_limit_configs FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.rate_limit_configs TO service_role;

DROP POLICY IF EXISTS "deny_all_client_rate_limit_configs" ON public.rate_limit_configs;
CREATE POLICY "deny_all_client_rate_limit_configs"
    ON public.rate_limit_configs
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

CREATE TABLE IF NOT EXISTS public.rate_limit_buckets (
    bucket_key TEXT NOT NULL,
    action TEXT NOT NULL REFERENCES public.rate_limit_configs(action) ON DELETE CASCADE,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    window_start TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    blocked_until TIMESTAMPTZ NULL,
    last_attempt_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (bucket_key, action)
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_last_attempt
    ON public.rate_limit_buckets (last_attempt_at);

ALTER TABLE public.rate_limit_buckets ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.rate_limit_buckets FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.rate_limit_buckets TO service_role;

DROP POLICY IF EXISTS "deny_all_client_rate_limit_buckets" ON public.rate_limit_buckets;
CREATE POLICY "deny_all_client_rate_limit_buckets"
    ON public.rate_limit_buckets
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

CREATE OR REPLACE FUNCTION public.check_rate_limit(
    p_bucket_key TEXT,
    p_action TEXT
)
RETURNS TABLE (
    allowed BOOLEAN,
    remaining INTEGER,
    retry_after_seconds INTEGER,
    current_count INTEGER
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_max_attempts INTEGER;
    v_window_seconds INTEGER;
    v_block_duration_seconds INTEGER;
    v_now TIMESTAMPTZ := clock_timestamp();
    v_attempt_count INTEGER;
    v_window_start TIMESTAMPTZ;
    v_blocked_until TIMESTAMPTZ;
    v_is_allowed BOOLEAN;
    v_remaining INTEGER;
    v_retry_after INTEGER;
BEGIN
    -- Fail closed on invalid arguments without leaking configuration state
    IF p_bucket_key IS NULL OR length(trim(p_bucket_key)) = 0 OR length(p_bucket_key) > 256 THEN
        RETURN QUERY SELECT FALSE, 0, 3600, 0;
        RETURN;
    END IF;

    IF p_action IS NULL OR length(trim(p_action)) = 0 OR length(p_action) > 64 THEN
        RETURN QUERY SELECT FALSE, 0, 3600, 0;
        RETURN;
    END IF;

    -- Load configuration; fail closed if missing
    SELECT c.max_attempts, c.window_seconds, c.block_duration_seconds
    INTO v_max_attempts, v_window_seconds, v_block_duration_seconds
    FROM public.rate_limit_configs AS c
    WHERE c.action = p_action;

    IF NOT FOUND OR v_max_attempts <= 0 OR v_window_seconds <= 0 OR v_block_duration_seconds <= 0 THEN
        RETURN QUERY SELECT FALSE, 0, 3600, 0;
        RETURN;
    END IF;

    -- Single atomic UPSERT acquires PK row lock during conflict handling,
    -- serializing parallel requests so concurrent bursts cannot bypass limits.
    INSERT INTO public.rate_limit_buckets AS b (
        bucket_key,
        action,
        attempt_count,
        window_start,
        blocked_until,
        last_attempt_at
    )
    VALUES (
        p_bucket_key,
        p_action,
        1,
        v_now,
        NULL,
        v_now
    )
    ON CONFLICT (bucket_key, action) DO UPDATE
    SET
        attempt_count = CASE
            WHEN b.blocked_until IS NOT NULL AND b.blocked_until > v_now THEN
                LEAST(b.attempt_count + 1, 2147483647)
            WHEN b.window_start + make_interval(secs => v_window_seconds) <= v_now THEN
                1
            ELSE
                LEAST(b.attempt_count + 1, 2147483647)
        END,
        window_start = CASE
            WHEN b.blocked_until IS NOT NULL AND b.blocked_until > v_now THEN
                b.window_start
            WHEN b.window_start + make_interval(secs => v_window_seconds) <= v_now THEN
                v_now
            ELSE
                b.window_start
        END,
        blocked_until = CASE
            WHEN b.blocked_until IS NOT NULL AND b.blocked_until > v_now THEN
                b.blocked_until
            WHEN b.window_start + make_interval(secs => v_window_seconds) <= v_now THEN
                NULL
            WHEN (b.attempt_count + 1) > v_max_attempts THEN
                v_now + make_interval(secs => v_block_duration_seconds)
            ELSE
                NULL
        END,
        last_attempt_at = v_now
    RETURNING
        b.attempt_count,
        b.window_start,
        b.blocked_until
    INTO
        v_attempt_count,
        v_window_start,
        v_blocked_until;

    IF v_blocked_until IS NOT NULL AND v_blocked_until > v_now THEN
        v_is_allowed := FALSE;
        v_remaining := 0;
        v_retry_after := GREATEST(1, CEIL(EXTRACT(EPOCH FROM (v_blocked_until - v_now)))::INTEGER);
    ELSIF v_attempt_count > v_max_attempts THEN
        v_is_allowed := FALSE;
        v_remaining := 0;
        v_retry_after := v_block_duration_seconds;
    ELSE
        v_is_allowed := TRUE;
        v_remaining := GREATEST(0, v_max_attempts - v_attempt_count);
        v_retry_after := 0;
    END IF;

    RETURN QUERY SELECT v_is_allowed, v_remaining, v_retry_after, v_attempt_count;

EXCEPTION
    WHEN OTHERS THEN
        -- Fail closed on any database error; emit zero internal details
        RETURN QUERY SELECT FALSE, 0, 3600, 0;
END;
$$;

REVOKE ALL ON FUNCTION public.check_rate_limit(TEXT, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.check_rate_limit(TEXT, TEXT) TO service_role;

-- =============================================================================
-- 9. PRIVACY-PRESERVING AUDIT EVENTS & DATABASE BOUNDARY TRIGGER
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.audit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NULL REFERENCES auth.users(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    device_fingerprint_hash TEXT NULL CHECK (device_fingerprint_hash ~ '^[0-9a-f]{64}$'),
    ip_hash TEXT NULL CHECK (ip_hash ~ '^[0-9a-f]{64}$'),
    status TEXT NOT NULL CHECK (status IN ('success', 'failure', 'blocked')),
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc'::text, now()),
    CONSTRAINT chk_audit_details_is_object CHECK (jsonb_typeof(details) = 'object'),
    CONSTRAINT chk_audit_details_size CHECK (octet_length(details::text) <= 4096)
);

CREATE INDEX IF NOT EXISTS idx_audit_events_created_at
    ON public.audit_events (created_at DESC);

ALTER TABLE public.audit_events ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.audit_events FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.audit_events TO service_role;

DROP POLICY IF EXISTS "deny_all_client_audit_events" ON public.audit_events;
CREATE POLICY "deny_all_client_audit_events"
    ON public.audit_events
    FOR ALL TO anon, authenticated
    USING (false)
    WITH CHECK (false);

CREATE OR REPLACE FUNCTION public.jsonb_contains_forbidden_audit_content(
    p_val JSONB,
    p_depth INTEGER DEFAULT 0
)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_key TEXT;
    v_child JSONB;
    v_text TEXT;
    v_elem JSONB;
BEGIN
    IF p_val IS NULL THEN
        RETURN FALSE;
    END IF;

    IF p_depth > 8 THEN
        RETURN TRUE;
    END IF;

    IF jsonb_typeof(p_val) = 'object' THEN
        FOR v_key, v_child IN SELECT * FROM jsonb_each(p_val) LOOP
            IF lower(v_key) = ANY (ARRAY[
                'recovery_phrase', 'phrase', 'mnemonic', 'passphrase', 'password',
                'recovery_verifier', 'recovery_auth_secret', 'recovery_salt', 'recovery_kek',
                'kek', 'dek', 'wrapped_dek', 'encrypted_recovery_envelope',
                'raw_ip', 'client_ip', 'ip', 'ip_address', 'tag_uid', 'uid',
                'email', 'jwt', 'access_token', 'refresh_token',
                'service_role_key', 'authorization', 'cookie', 'secret_key'
            ]) THEN
                RETURN TRUE;
            END IF;
            IF public.jsonb_contains_forbidden_audit_content(v_child, p_depth + 1) THEN
                RETURN TRUE;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(p_val) = 'array' THEN
        FOR v_elem IN SELECT * FROM jsonb_array_elements(p_val) LOOP
            IF public.jsonb_contains_forbidden_audit_content(v_elem, p_depth + 1) THEN
                RETURN TRUE;
            END IF;
        END LOOP;
    ELSIF jsonb_typeof(p_val) = 'string' THEN
        v_text := p_val #>> '{}';
        -- Reject raw IPv4 addresses
        IF v_text ~ '(^|[^0-9])([0-9]{1,3}\.){3}[0-9]{1,3}($|[^0-9])' THEN
            RETURN TRUE;
        END IF;
        -- Reject JWT tokens
        IF v_text ~ '^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' THEN
            RETURN TRUE;
        END IF;
        -- Reject PEM private/key blocks
        IF v_text ~ '-----BEGIN ' THEN
            RETURN TRUE;
        END IF;
        -- Reject raw 64+ hex secrets embedded in details
        IF v_text ~ '(^|[^0-9a-fA-F])[0-9a-fA-F]{64,}($|[^0-9a-fA-F])' THEN
            RETURN TRUE;
        END IF;
        -- Reject 12+ space-separated lowercase words (mnemonic phrase leak guard)
        IF v_text ~ '^[a-z]+(\s+[a-z]+){11,}$' THEN
            RETURN TRUE;
        END IF;
    END IF;

    RETURN FALSE;
END;
$$;

REVOKE ALL ON FUNCTION public.jsonb_contains_forbidden_audit_content(JSONB, INTEGER) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.jsonb_contains_forbidden_audit_content(JSONB, INTEGER) TO service_role;

CREATE OR REPLACE FUNCTION public.validate_audit_event_details()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    v_key TEXT;
BEGIN
    IF NEW.details IS NULL THEN
        NEW.details := '{}'::jsonb;
    END IF;

    IF jsonb_typeof(NEW.details) <> 'object' THEN
        RAISE EXCEPTION 'AUDIT_PAYLOAD_REJECTED: details must be a JSON object';
    END IF;

    IF octet_length(NEW.details::text) > 4096 THEN
        RAISE EXCEPTION 'AUDIT_PAYLOAD_REJECTED: details exceeds 4096 bytes';
    END IF;

    FOR v_key IN SELECT jsonb_object_keys(NEW.details) LOOP
        IF v_key <> ALL (ARRAY[
            'error_code', 'reason', 'action', 'challenge_outcome',
            'grace_hours', 'kdf_version', 'attempt_bucket',
            'http_status', 'retry_attempt'
        ]) THEN
            RAISE EXCEPTION 'AUDIT_PAYLOAD_REJECTED: disallowed details key';
        END IF;
    END LOOP;

    IF public.jsonb_contains_forbidden_audit_content(NEW.details, 0) THEN
        RAISE EXCEPTION 'AUDIT_PAYLOAD_REJECTED: forbidden secret or PII detected';
    END IF;

    RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION public.validate_audit_event_details() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.validate_audit_event_details() TO service_role;

DROP TRIGGER IF EXISTS trg_validate_audit_event_details ON public.audit_events;
CREATE TRIGGER trg_validate_audit_event_details
    BEFORE INSERT OR UPDATE ON public.audit_events
    FOR EACH ROW
    EXECUTE FUNCTION public.validate_audit_event_details();
