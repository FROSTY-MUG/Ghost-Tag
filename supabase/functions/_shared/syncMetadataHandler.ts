/**
 * Ghost-Tag v2.1.0 - Authenticated Vault Metadata Sync Handler (sync-vault-metadata)
 *
 * Security Invariants:
 * - Strict CORS allowlist enforcement
 * - Verified Supabase Auth Bearer JWT (rejects unauthenticated or deletion_pending/purging users)
 * - Rate limited via partitioned vault_sync (60/min)
 * - Validates canonical 78-byte wrapped_dek whose first 16 bytes match key_id
 * - Rejects raw secrets / invalid payload sizes before DB write
 */

import { hashAuditIdentifier, sanitizeAuditEvent } from './audit.ts';
import { CorsPolicyOptions, evaluateCorsRequest } from './cors.ts';
import { base64ToBytes, constantTimeEqualBytes } from './recoveryCrypto.ts';

export interface SyncVaultMetadataDeps {
  corsOptions: CorsPolicyOptions;
  auditHmacSalt: string | undefined;
  authenticateUser(authHeader: string | null): Promise<{ id: string } | null>;
  getAccountStatus(userId: string): Promise<'active' | 'deletion_pending' | 'purging' | 'deleted' | null>;
  checkRateLimit(
    bucketKey: string,
    action: 'vault_sync'
  ): Promise<{ allowed: boolean; retryAfterSeconds: number }>;
  upsertVaultMetadata(record: {
    userId: string;
    vaultIdBytes: Uint8Array;
    encryptedVaultNameBytes: Uint8Array;
    encryptedVaultManifestBytes: Uint8Array;
    wrappedDekBytes: Uint8Array;
    keyIdBytes: Uint8Array;
    totalChunkCount: number;
    erasureParamsBytes: Uint8Array;
    integrityHashBytes: Uint8Array;
  }): Promise<void>;
  recordAudit(event: ReturnType<typeof sanitizeAuditEvent>): Promise<void>;
}

export async function handleSyncVaultMetadata(
  req: Request,
  deps: SyncVaultMetadataDeps,
  clientIp = '0.0.0.0'
): Promise<Response> {
  const origin = req.headers.get('Origin');
  const cors = evaluateCorsRequest(origin, deps.corsOptions);
  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: 'SYNC_FAILED' }), {
      status: 403,
      headers: { ...cors.headers, 'Content-Type': 'application/json' },
    });
  }
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: cors.headers });
  }
  const headers = { ...cors.headers, 'Content-Type': 'application/json' };
  if (req.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'METHOD_NOT_ALLOWED' }), {
      status: 405,
      headers,
    });
  }

  if (!deps.auditHmacSalt || deps.auditHmacSalt.length < 16) {
    return new Response(JSON.stringify({ error: 'SYNC_FAILED' }), {
      status: 500,
      headers,
    });
  }
  const ipHash = await hashAuditIdentifier(clientIp, deps.auditHmacSalt);

  const user = await deps.authenticateUser(req.headers.get('Authorization'));
  if (!user) {
    return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
      status: 401,
      headers,
    });
  }

  const rlBucket = await hashAuditIdentifier(`sync:${user.id}`, deps.auditHmacSalt);
  const rl = await deps.checkRateLimit(rlBucket, 'vault_sync');
  if (!rl.allowed) {
    return new Response(
      JSON.stringify({ error: 'RATE_LIMITED', retry_after_seconds: rl.retryAfterSeconds }),
      { status: 429, headers }
    );
  }

  const acctStatus = await deps.getAccountStatus(user.id);
  if (acctStatus !== 'active') {
    return new Response(JSON.stringify({ error: 'ACCOUNT_NOT_ACTIVE' }), {
      status: 403,
      headers,
    });
  }

  let body: Record<string, unknown>;
  try {
    const parsed = await req.json();
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('invalid body');
    }
    body = parsed as Record<string, unknown>;
  } catch {
    return new Response(JSON.stringify({ error: 'INVALID_PAYLOAD' }), {
      status: 400,
      headers,
    });
  }

  if (
    typeof body.vault_id !== 'string' ||
    typeof body.encrypted_vault_name !== 'string' ||
    typeof body.encrypted_vault_manifest !== 'string' ||
    typeof body.wrapped_dek !== 'string' ||
    typeof body.key_id !== 'string' ||
    typeof body.erasure_params !== 'string' ||
    typeof body.integrity_hash !== 'string' ||
    typeof body.total_chunk_count !== 'number' ||
    !Number.isInteger(body.total_chunk_count) ||
    body.total_chunk_count <= 0
  ) {
    return new Response(JSON.stringify({ error: 'INVALID_METADATA_FIELDS' }), {
      status: 400,
      headers,
    });
  }

  try {
    const vaultIdBytes = base64ToBytes(body.vault_id);
    const encryptedVaultNameBytes = base64ToBytes(body.encrypted_vault_name);
    const encryptedVaultManifestBytes = base64ToBytes(body.encrypted_vault_manifest);
    const wrappedDekBytes = base64ToBytes(body.wrapped_dek);
    const keyIdBytes = base64ToBytes(body.key_id);
    const erasureParamsBytes = base64ToBytes(body.erasure_params);
    const integrityHashBytes = base64ToBytes(body.integrity_hash);

    if (
      vaultIdBytes.length !== 16 ||
      wrappedDekBytes.length !== 78 ||
      keyIdBytes.length !== 16 ||
      integrityHashBytes.length !== 32 ||
      encryptedVaultNameBytes.length < 16 ||
      encryptedVaultManifestBytes.length < 16 ||
      erasureParamsBytes.length < 1 ||
      !constantTimeEqualBytes(wrappedDekBytes.slice(0, 16), keyIdBytes)
    ) {
      await deps.recordAudit(
        sanitizeAuditEvent({
          userId: user.id,
          eventType: 'vault_metadata_sync_rejected',
          ipHash,
          status: 'failure',
          details: { error_code: 'INVALID_WRAPPED_DEK_OR_LENGTH', http_status: 400 },
        })
      );
      return new Response(JSON.stringify({ error: 'INVALID_WRAPPED_DEK_OR_LENGTH' }), {
        status: 400,
        headers,
      });
    }

    await deps.upsertVaultMetadata({
      userId: user.id,
      vaultIdBytes,
      encryptedVaultNameBytes,
      encryptedVaultManifestBytes,
      wrappedDekBytes,
      keyIdBytes,
      totalChunkCount: body.total_chunk_count,
      erasureParamsBytes,
      integrityHashBytes,
    });

    await deps.recordAudit(
      sanitizeAuditEvent({
        userId: user.id,
        eventType: 'vault_metadata_synced',
        ipHash,
        status: 'success',
        details: { action: 'vault_metadata_sync', http_status: 200 },
      })
    );

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers,
    });
  } catch {
    return new Response(JSON.stringify({ error: 'INVALID_METADATA_FIELDS' }), {
      status: 400,
      headers,
    });
  }
}
