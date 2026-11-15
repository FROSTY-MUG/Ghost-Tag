-- Ghost-Tag v2.0.5: Encrypted Vault Metadata Schema for Supabase
-- Stores exclusively encrypted vault metadata blobs for cross-device account recovery.
-- Zero-Knowledge Guarantee: NEVER stores passphrases, recovery phrases, KEKs, DEKs,
-- plaintext entries, files, NFC contents, or scanned chunks.

create table if not exists ghost_vaults (
  account_id uuid primary key,
  user_id uuid not null,
  encrypted_vault_blob bytea not null,
  vault_version integer not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Enable Row Level Security (RLS)
alter table ghost_vaults enable row level security;

-- Policy: Only authenticated owner can read and write their own vault
create policy "owner_read_write" on ghost_vaults
  for all to authenticated
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Performance index for user_id lookups
create index if not exists idx_ghost_vaults_user_id on ghost_vaults(user_id);
