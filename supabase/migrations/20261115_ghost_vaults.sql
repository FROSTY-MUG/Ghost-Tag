-- Ghost-Tag v2.0.5: Hardened Encrypted Vault Metadata Schema for Supabase
-- Zero-Knowledge Guarantee: NEVER stores passphrases, recovery phrases, KEKs, DEKs,
-- plaintext entries, files, NFC contents, or scanned chunks.
--
-- Security Hardening:
-- Recovery requires BOTH account_id (valid RFC 4122 UUID) and an authenticated recovery_verifier.
-- Ownership reassignment and encrypted metadata retrieval are handled exclusively
-- by the recover-vault Edge Function via constant-time verification.

create table if not exists ghost_vaults (
  account_id uuid primary key,
  owner_user_id uuid not null,
  recovery_verifier bytea not null,
  recovery_salt bytea not null,
  recovery_kdf_version integer not null default 1,
  encrypted_vault_blob bytea not null,
  vault_version integer not null default 2,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Enable Row Level Security (RLS) on ghost_vaults
alter table ghost_vaults enable row level security;

-- Policy: Only authenticated owner can directly read, update, or delete their vault
drop policy if exists "owner_full_access" on ghost_vaults;
create policy "owner_full_access"
on ghost_vaults
for all
to authenticated
using (auth.uid() = owner_user_id)
with check (auth.uid() = owner_user_id);

-- Explicitly deny anon direct access to vaults
drop policy if exists "deny_anon_vaults" on ghost_vaults;
create policy "deny_anon_vaults"
on ghost_vaults
for all
to anon
using (false)
with check (false);

-- Indices on ghost_vaults
create index if not exists idx_ghost_vaults_owner_user_id
on ghost_vaults(owner_user_id);

create index if not exists idx_ghost_vaults_account_id
on ghost_vaults(account_id);

-- Layered Rate Limiting & Attempt Logging Table
-- IP addresses are strictly hashed (SHA-256) before insertion; raw IPs are never stored.
create table if not exists ghost_recovery_attempts (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null,
  user_id uuid,
  ip_hash text not null,
  success boolean not null default false,
  attempted_at timestamptz not null default now()
);

-- Enable Row Level Security (RLS) on ghost_recovery_attempts
alter table ghost_recovery_attempts enable row level security;

-- Explicit denial policies for anon and authenticated users.
-- Direct client access (SELECT, INSERT, UPDATE, DELETE) is strictly prohibited.
-- Only the recover-vault Edge Function using the server-side service_role key can read/write.
drop policy if exists "deny_anon_recovery_attempts" on ghost_recovery_attempts;
create policy "deny_anon_recovery_attempts"
on ghost_recovery_attempts
for all
to anon
using (false)
with check (false);

drop policy if exists "deny_authenticated_recovery_attempts" on ghost_recovery_attempts;
create policy "deny_authenticated_recovery_attempts"
on ghost_recovery_attempts
for all
to authenticated
using (false)
with check (false);

-- Composite indices optimized for window-based rate limiting queries
create index if not exists idx_recovery_attempts_account_window
on ghost_recovery_attempts (account_id, success, attempted_at);

create index if not exists idx_recovery_attempts_user_window
on ghost_recovery_attempts (user_id, success, attempted_at);

create index if not exists idx_recovery_attempts_ip_window
on ghost_recovery_attempts (ip_hash, success, attempted_at);

create index if not exists idx_recovery_attempts_global_window
on ghost_recovery_attempts (success, attempted_at);

-- ---------------------------------------------------------------------------
-- Atomic Transactional Rate-Limiting Function
-- ---------------------------------------------------------------------------
-- Prevents parallel race condition bypasses using transaction-level advisory locks.
-- Serializes concurrent requests per account_id so parallel callers cannot exceed limits.

create or replace function check_and_record_recovery_attempt(
  p_account_id uuid,
  p_user_id uuid,
  p_ip_hash text,
  p_max_account int default 25,
  p_max_user int default 20,
  p_max_ip int default 100,
  p_window_interval interval default interval '15 minutes'
)
returns table (
  allowed boolean,
  account_failures bigint,
  user_failures bigint,
  ip_failures bigint
)
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  v_window_start timestamptz := now() - p_window_interval;
  v_account_cnt bigint;
  v_user_cnt bigint;
  v_ip_cnt bigint;
begin
  -- 1. Atomic transaction-level advisory lock on account_id hash
  -- Serializes concurrent requests targeting the same account until transaction completes
  perform pg_advisory_xact_lock(hashtext(p_account_id::text));

  -- 2. Count ONLY failed attempts in the sliding window
  select count(*) into v_account_cnt
  from public.ghost_recovery_attempts
  where account_id = p_account_id and success = false and attempted_at >= v_window_start;

  if p_user_id is not null then
    select count(*) into v_user_cnt
    from public.ghost_recovery_attempts
    where user_id = p_user_id and success = false and attempted_at >= v_window_start;
  else
    v_user_cnt := 0;
  end if;

  select count(*) into v_ip_cnt
  from public.ghost_recovery_attempts
  where ip_hash = p_ip_hash and success = false and attempted_at >= v_window_start;

  -- 3. Evaluate limits atomically
  if v_account_cnt >= p_max_account or (p_user_id is not null and v_user_cnt >= p_max_user) or v_ip_cnt >= p_max_ip then
    return query select false, v_account_cnt, v_user_cnt, v_ip_cnt;
  else
    return query select true, v_account_cnt, v_user_cnt, v_ip_cnt;
  end if;
end;
$$;

-- Lock down execution privileges: callable ONLY by service_role
revoke execute on function public.check_and_record_recovery_attempt(uuid, uuid, text, int, int, int, interval)
from anon, authenticated, public;

grant execute on function public.check_and_record_recovery_attempt(uuid, uuid, text, int, int, int, interval)
to service_role;
