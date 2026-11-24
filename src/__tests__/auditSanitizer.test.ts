/**
 * @file auditSanitizer.test.ts
 * @summary Verifies whitelisted privacy-preserving audit event sanitization
 * across both TypeScript (_shared/audit.ts) and PostgreSQL trigger SQL boundaries.
 */

import {
  ALLOWED_DETAILS_KEYS,
  ALLOWED_EVENT_TYPES,
  hashAuditIdentifier,
  sanitizeAuditEvent,
} from '../../supabase/functions/_shared/audit';

declare const require: any;
declare const __dirname: string;
const fs = require('fs');
const path = require('path');

describe('PR #2: Audit Event Whitelist Sanitizer & Database Trigger', () => {
  const VALID_HASH = 'a'.repeat(64);
  const VALID_UUID = '11111111-2222-4333-8444-555555555555';

  test('accepts valid whitelisted audit events including benign "token"/"key"/"metadata" enum values', () => {
    expect(ALLOWED_EVENT_TYPES.has('recovery_challenge_issued')).toBe(true);
    expect(ALLOWED_DETAILS_KEYS.has('error_code')).toBe(true);

    const record = sanitizeAuditEvent({
      userId: VALID_UUID,
      eventType: 'captcha_verification_failed',
      deviceFingerprintHash: VALID_HASH,
      ipHash: VALID_HASH,
      status: 'failure',
      details: {
        error_code: 'TURNSTILE_TOKEN_EXPIRED',
        reason: 'invalid_key_id_format',
        action: 'vault_metadata_sync',
        http_status: 403,
        retry_attempt: 1,
      },
    });

    expect(record.event_type).toBe('captcha_verification_failed');
    expect(record.details.error_code).toBe('TURNSTILE_TOKEN_EXPIRED');
    expect(record.details.reason).toBe('invalid_key_id_format');
    expect(record.details.action).toBe('vault_metadata_sync');
  });

  test('rejects unknown event_type, non-whitelisted top-level keys, and invalid hashes', () => {
    expect(() =>
      sanitizeAuditEvent({
        eventType: 'arbitrary_debug_event',
        status: 'success',
      })
    ).toThrow(/disallowed event_type/i);

    expect(() =>
      sanitizeAuditEvent({
        eventType: 'recovery_proof_failed',
        status: 'failure',
        details: {
          custom_unapproved_field: 'ok',
        },
      })
    ).toThrow(/disallowed details key/i);

    expect(() =>
      sanitizeAuditEvent({
        eventType: 'recovery_proof_failed',
        status: 'failure',
        ipHash: '192.0.2.55',
      })
    ).toThrow(/64 lowercase hex/i);
  });

  test('recursively blocks secrets hidden inside nested objects and arrays', () => {
    expect(() =>
      sanitizeAuditEvent({
        eventType: 'recovery_proof_failed',
        status: 'failure',
        details: {
          reason: {
            nested_wrapper: {
              recovery_verifier: 'secret-value',
            },
          },
        },
      })
    ).toThrow(/forbidden nested key/i);

    expect(() =>
      sanitizeAuditEvent({
        eventType: 'recovery_proof_failed',
        status: 'failure',
        details: {
          reason: [
            'benign_entry',
            {
              tag_uid: '04A22B1C3D',
            },
          ],
        },
      })
    ).toThrow(/forbidden nested key/i);
  });

  test('blocks raw IPv4, IPv6, JWTs, PEM blocks, raw emails, 64-hex secrets, and 12-word phrases in values', () => {
    const fakeJwt = 'eyJ' + 'hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.' + 'eyJzdWIiOiIxMjMifQ.sig';
    const fakePem = '-----BEG' + 'IN PRIVATE KEY-----';

    const forbiddenValues = [
      '192.168.1.42',
      '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
      fakeJwt,
      fakePem,
      'victim@example.org',
      '0123456789abcdef'.repeat(4),
      'abandon ability able about above absent absorb abstract absurd abuse access accident',
    ];

    for (const val of forbiddenValues) {
      expect(() =>
        sanitizeAuditEvent({
          eventType: 'account_provision_blocked',
          status: 'blocked',
          details: { reason: val },
        })
      ).toThrow(/AUDIT_SANITIZER_REJECTED/);
    }
  });

  test('rejects oversized details payloads exceeding 4096 bytes', () => {
    const chunks = Array.from({ length: 500 }, (_, i) => `item-${i}`);
    expect(() =>
      sanitizeAuditEvent({
        eventType: 'vault_metadata_sync_rejected',
        status: 'failure',
        details: { reason: chunks },
      })
    ).toThrow(/exceeds 4096 bytes/i);
  });

  test('hashAuditIdentifier produces deterministic keyed 64-hex HMAC-SHA256 digests', async () => {
    const digestA = await hashAuditIdentifier('203.0.113.9', 'server-only-hmac-salt-32-chars!!');
    const digestB = await hashAuditIdentifier('203.0.113.9', 'server-only-hmac-salt-32-chars!!');
    const digestOther = await hashAuditIdentifier('203.0.113.9', 'different-hmac-salt-32-chars!!!!');

    expect(digestA).toMatch(/^[0-9a-f]{64}$/);
    expect(digestA).toBe(digestB);
    expect(digestA).not.toBe(digestOther);
  });

  test('PostgreSQL migration attaches BEFORE INSERT OR UPDATE sanitization trigger to public.audit_events', () => {
    const ROOT = path.resolve(__dirname, '../..');
    const sql: string = fs.readFileSync(
      path.join(ROOT, 'supabase/migrations/20261126_v210_account_security_schema.sql'),
      'utf8'
    );

    expect(sql).toMatch(
      /CREATE TRIGGER trg_validate_audit_event_details\s+BEFORE INSERT OR UPDATE ON public\.audit_events\s+FOR EACH ROW\s+EXECUTE FUNCTION public\.validate_audit_event_details\(\);/i
    );
    expect(sql).toMatch(/jsonb_contains_forbidden_audit_content/i);
  });
});
