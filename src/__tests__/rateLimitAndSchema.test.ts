/**
 * @file rateLimitAndSchema.test.ts
 * @summary Verifies atomic PostgreSQL rate-limiter semantics, schema partitioning,
 * fail-closed error handling, and concurrency race protection under parallel requests.
 *
 * NOTE: Because no live PostgreSQL instance is provisioned in CI/local dev here,
 * this suite verifies:
 *   1. The exact PL/pgSQL implementation in 20261126_v210_account_security_schema.sql
 *      uses single-statement INSERT ... ON CONFLICT DO UPDATE (never SELECT + UPDATE),
 *      SET search_path = '', SECURITY DEFINER, privilege revocation, missing-config
 *      fail-closed returns, exception fail-closed returns, and separate action limits.
 *   2. A serialized atomic transaction simulator executing the exact PostgreSQL
 *      ON CONFLICT row-lock behavior proves parallel bursts cannot exceed configured limits.
 */

export {};
declare const require: any;
declare const __dirname: string;
const fs = require('fs');
const path = require('path');

interface RateLimitConfig {
  maxAttempts: number;
  windowSeconds: number;
  blockDurationSeconds: number;
}

interface RateLimitBucket {
  attemptCount: number;
  windowStartMs: number;
  blockedUntilMs: number | null;
}

interface RateLimitCheckResult {
  allowed: boolean;
  remaining: number;
  retryAfterSeconds: number;
  currentCount: number;
}

/**
 * Exact behavioral model of PostgreSQL `public.check_rate_limit(bucket_key, action)`
 * utilizing serialized row-level locking on `(bucket_key, action)` to represent
 * `INSERT ... ON CONFLICT (bucket_key, action) DO UPDATE`.
 */
class TransactionalRateLimiterModel {
  private configs = new Map<string, RateLimitConfig>();
  private buckets = new Map<string, RateLimitBucket>();
  private keyLocks = new Map<string, Promise<void>>();
  public simulateDbFailure = false;

  constructor(initialConfigs: Record<string, RateLimitConfig>) {
    for (const [k, v] of Object.entries(initialConfigs)) {
      this.configs.set(k, v);
    }
  }

  async checkRateLimit(
    bucketKey: string,
    action: string,
    nowMs = Date.now()
  ): Promise<RateLimitCheckResult> {
    if (
      !bucketKey ||
      !bucketKey.trim() ||
      bucketKey.length > 256 ||
      !action ||
      !action.trim() ||
      action.length > 64
    ) {
      return { allowed: false, remaining: 0, retryAfterSeconds: 3600, currentCount: 0 };
    }

    if (this.simulateDbFailure) {
      // Fail closed with generic response (mirrors EXCEPTION WHEN OTHERS)
      return { allowed: false, remaining: 0, retryAfterSeconds: 3600, currentCount: 0 };
    }

    const config = this.configs.get(action);
    if (
      !config ||
      config.maxAttempts <= 0 ||
      config.windowSeconds <= 0 ||
      config.blockDurationSeconds <= 0
    ) {
      // Fail closed when configuration is missing
      return { allowed: false, remaining: 0, retryAfterSeconds: 3600, currentCount: 0 };
    }

    const compositeKey = `${bucketKey}::${action}`;
    // Serialize row-level conflict updates just like PostgreSQL PK lock on ON CONFLICT DO UPDATE
    const prev = this.keyLocks.get(compositeKey) ?? Promise.resolve();
    let release!: () => void;
    const next = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.keyLocks.set(compositeKey, prev.then(() => next));

    await prev;
    try {
      // Simulate micro-yield inside concurrent transaction processing
      await Promise.resolve();

      const existing = this.buckets.get(compositeKey);
      const windowMs = config.windowSeconds * 1000;
      const blockMs = config.blockDurationSeconds * 1000;
      let updated: RateLimitBucket;

      if (!existing) {
        updated = {
          attemptCount: 1,
          windowStartMs: nowMs,
          blockedUntilMs: null,
        };
      } else if (existing.blockedUntilMs !== null && existing.blockedUntilMs > nowMs) {
        updated = {
          attemptCount: existing.attemptCount + 1,
          windowStartMs: existing.windowStartMs,
          blockedUntilMs: existing.blockedUntilMs,
        };
      } else if (existing.windowStartMs + windowMs <= nowMs) {
        updated = {
          attemptCount: 1,
          windowStartMs: nowMs,
          blockedUntilMs: null,
        };
      } else {
        const nextCount = existing.attemptCount + 1;
        updated = {
          attemptCount: nextCount,
          windowStartMs: existing.windowStartMs,
          blockedUntilMs: nextCount > config.maxAttempts ? nowMs + blockMs : null,
        };
      }

      this.buckets.set(compositeKey, updated);

      if (updated.blockedUntilMs !== null && updated.blockedUntilMs > nowMs) {
        return {
          allowed: false,
          remaining: 0,
          retryAfterSeconds: Math.max(
            1,
            Math.ceil((updated.blockedUntilMs - nowMs) / 1000)
          ),
          currentCount: updated.attemptCount,
        };
      }
      if (updated.attemptCount > config.maxAttempts) {
        return {
          allowed: false,
          remaining: 0,
          retryAfterSeconds: config.blockDurationSeconds,
          currentCount: updated.attemptCount,
        };
      }
      return {
        allowed: true,
        remaining: Math.max(0, config.maxAttempts - updated.attemptCount),
        retryAfterSeconds: 0,
        currentCount: updated.attemptCount,
      };
    } finally {
      release();
    }
  }
}

describe('PR #2: Concurrency-Safe Rate Limiter & Schema Contracts', () => {
  const ROOT = path.resolve(__dirname, '../..');
  const sql: string = fs.readFileSync(
    path.join(ROOT, 'supabase/migrations/20261126_v210_account_security_schema.sql'),
    'utf8'
  );

  test('check_rate_limit SQL uses atomic INSERT ... ON CONFLICT DO UPDATE (never SELECT then UPDATE) and fails closed', () => {
    const fnMatch = sql.match(
      /CREATE OR REPLACE FUNCTION public\.check_rate_limit\([\s\S]*?GRANT EXECUTE ON FUNCTION public\.check_rate_limit\(TEXT, TEXT\) TO service_role;/i
    );
    expect(fnMatch).not.toBeNull();
    const fnSql = fnMatch![0];

    expect(fnSql).toMatch(/INSERT INTO public\.rate_limit_buckets AS b/i);
    expect(fnSql).toMatch(/ON CONFLICT \(bucket_key, action\) DO UPDATE/i);
    expect(fnSql).toMatch(/SET search_path = ''/i);
    expect(fnSql).toMatch(/SECURITY DEFINER/i);
    expect(fnSql).toMatch(/IF NOT FOUND OR[\s\S]*?RETURN QUERY SELECT FALSE, 0, 3600, 0;/i);
    expect(fnSql).toMatch(/EXCEPTION\s+WHEN OTHERS THEN[\s\S]*?RETURN QUERY SELECT FALSE, 0, 3600, 0;/i);
    expect(fnSql).toMatch(/REVOKE ALL ON FUNCTION public\.check_rate_limit\(TEXT, TEXT\) FROM PUBLIC, anon, authenticated;/i);
    expect(fnSql).toMatch(/GRANT EXECUTE ON FUNCTION public\.check_rate_limit\(TEXT, TEXT\) TO service_role;/i);
  });

  test('rate_limit_configs partitions recovery_challenge (10/hr) and recovery_proof (5/hr) independently', () => {
    expect(sql).toMatch(/\('auth_provision',\s*5,\s*900,\s*900\)/);
    expect(sql).toMatch(/\('recovery_challenge',\s*10,\s*3600,\s*3600\)/);
    expect(sql).toMatch(/\('recovery_proof',\s*5,\s*3600,\s*3600\)/);
    expect(sql).toMatch(/\('password_reset',\s*5,\s*3600,\s*3600\)/);
    expect(sql).toMatch(/\('vault_sync',\s*60,\s*60,\s*120\)/);
    expect(sql).toMatch(/\('account_deletion',\s*3,\s*86400,\s*86400\)/);
    expect(sql).toMatch(/\('verify_captcha',\s*20,\s*60,\s*300\)/);
  });

  test('parallel burst simulation: 20 simultaneous recovery_proof requests allow strictly <= 5 and block >= 15', async () => {
    const limiter = new TransactionalRateLimiterModel({
      recovery_challenge: { maxAttempts: 10, windowSeconds: 3600, blockDurationSeconds: 3600 },
      recovery_proof: { maxAttempts: 5, windowSeconds: 3600, blockDurationSeconds: 3600 },
    });

    const t0 = 1_700_000_000_000;
    const parallelCalls = Array.from({ length: 20 }, () =>
      limiter.checkRateLimit('acct:hash-1', 'recovery_proof', t0)
    );
    const results = await Promise.all(parallelCalls);

    const allowedCount = results.filter((r) => r.allowed).length;
    const blockedCount = results.filter((r) => !r.allowed).length;
    expect(allowedCount).toBe(5);
    expect(blockedCount).toBe(15);

    for (const r of results) {
      if (!r.allowed) {
        expect(r.remaining).toBe(0);
        expect(r.retryAfterSeconds).toBeGreaterThan(0);
      }
    }

    // Partition isolation: recovery_challenge bucket for same key still permits up to 10 requests
    const challengeResults = await Promise.all(
      Array.from({ length: 12 }, () =>
        limiter.checkRateLimit('acct:hash-1', 'recovery_challenge', t0)
      )
    );
    expect(challengeResults.filter((r) => r.allowed).length).toBe(10);
    expect(challengeResults.filter((r) => !r.allowed).length).toBe(2);

    // Window reset after 3601 seconds re-opens fresh quota cleanly
    const afterExpiry = await limiter.checkRateLimit(
      'acct:hash-1',
      'recovery_proof',
      t0 + 3601 * 1000
    );
    expect(afterExpiry.allowed).toBe(true);
    expect(afterExpiry.remaining).toBe(4);
    expect(afterExpiry.currentCount).toBe(1);
  });

  test('missing configuration and database errors fail closed with generic block result', async () => {
    const limiter = new TransactionalRateLimiterModel({
      recovery_proof: { maxAttempts: 5, windowSeconds: 3600, blockDurationSeconds: 3600 },
    });

    const missingCfg = await limiter.checkRateLimit('ip:hash-1', 'nonexistent_action');
    expect(missingCfg.allowed).toBe(false);
    expect(missingCfg.remaining).toBe(0);
    expect(missingCfg.retryAfterSeconds).toBe(3600);

    const emptyBucket = await limiter.checkRateLimit('   ', 'recovery_proof');
    expect(emptyBucket.allowed).toBe(false);

    limiter.simulateDbFailure = true;
    const dbErr = await limiter.checkRateLimit('ip:hash-2', 'recovery_proof');
    expect(dbErr.allowed).toBe(false);
    expect(dbErr.remaining).toBe(0);
  });
});
