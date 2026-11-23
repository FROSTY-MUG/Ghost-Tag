# Ghost-Tag Supabase Cloud Relay

## Overview
Ghost-Tag provides an optional, zero-knowledge cloud synchronization and recovery relay using Supabase. It stores strictly encrypted vault metadata and enforces zero-knowledge ownership proofs for cross-device recovery.

---

## 1. Deployment Status

> [!CAUTION]
> **NOT DEPLOYED TO PRODUCTION**: Database migrations and Edge Functions are verified locally and covered by automated test suites. They have **not** been pushed to a live Supabase production instance.

---

## 2. Security Invariants & Zero-Knowledge Architecture

1. **Zero Secret Persistence**:
   The cloud database never receives, processes, or stores master passphrases, 12-word recovery phrases, Key Encryption Keys (KEKs), Data Encryption Keys (DEKs), plaintext file contents, or NFC tag payloads.
2. **Zero-Session Recovery**:
   A brand-new device with zero prior authentication sessions can initiate recovery using solely the public anon key and the 12-word recovery phrase.
3. **Owner Reassignment Policy**:
   - Requests authenticated with an anon key verify the Argon2id verifier and return the encrypted blob **without modifying `owner_user_id`**.
   - Requests authenticated with a valid user JWT reassign `owner_user_id = user.id` **only if** the caller proves ownership by supplying the matching 256-bit `recovery_verifier`.
4. **Atomic Legacy Migration**:
   Legacy web records (`recovery_kdf_version = 1`) are upgraded to canonical Argon2id (`recovery_kdf_version = 2`) atomically via the `migrate_recovery_verifier_atomic` PostgreSQL RPC. Row-level exclusive locking (`FOR UPDATE`) prevents concurrent migration races, enforces one-way version upgrade, and eliminates partial update risks.

---

## 3. Edge Functions

| Endpoint | Method | Purpose | Authentication |
|---|---|---|---|
| `/functions/v1/recover-vault` | `POST` | Fetches encrypted vault blob | Bearer Anon Key or User JWT + 256-bit `recovery_verifier` |
| `/functions/v1/migrate-recovery-verifier` | `POST` | Upgrades legacy PBKDF2 verifier to Argon2id | Bearer Anon Key or User JWT + legacy verifier proof |
