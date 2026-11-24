/**
 * @file corsValidation.test.ts
 * @summary Verifies Correction #2: Strict explicit CORS allowlist enforcement,
 * rejection of unknown/wildcard/reflected origins, development-only localhost gating,
 * and Desktop Bridge HTTP + WebSocket origin protection.
 */

import {
  PRODUCTION_ALLOWED_ORIGINS,
  parseApprovedProductionOrigins,
  isValidLoopbackOrigin,
  isAllowedCorsOrigin,
  evaluateCorsRequest,
} from '../../supabase/functions/_shared/cors';

declare const require: any;
declare const __dirname: string;
const fs = require('fs');
const path = require('path');
const http = require('http');

const {
  GhostBridgeServer,
  isBridgeOriginAllowed,
  HOST,
} = require('../../desktop/src/server');

describe('Correction #2: Strict CORS Allowlist & Origin Enforcement', () => {
  const ROOT = path.resolve(__dirname, '../..');

  test('1. Allows https://frosty-mug.github.io in production mode', () => {
    expect(PRODUCTION_ALLOWED_ORIGINS).toContain('https://frosty-mug.github.io');

    const res = evaluateCorsRequest('https://frosty-mug.github.io', {
      environment: 'production',
      allowLocalhostCors: false,
    });

    expect(res.allowed).toBe(true);
    expect(res.headers['Access-Control-Allow-Origin']).toBe(
      'https://frosty-mug.github.io'
    );
    expect(res.headers.Vary).toBe('Origin');
  });

  test('2. Supports explicitly configured HTTPS production domains while ignoring wildcards or HTTP', () => {
    const allowed = parseApprovedProductionOrigins(
      'https://vault.ghost-tag.org, *, http://insecure.example.com, https://app.example.com/path'
    );
    expect(allowed.has('https://frosty-mug.github.io')).toBe(true);
    expect(allowed.has('https://vault.ghost-tag.org')).toBe(true);
    expect(allowed.has('*')).toBe(false);
    expect(allowed.has('http://insecure.example.com')).toBe(false);
    expect(allowed.has('https://app.example.com/path')).toBe(false);

    expect(
      isAllowedCorsOrigin('https://vault.ghost-tag.org', {
        environment: 'production',
        approvedProductionOrigins: 'https://vault.ghost-tag.org,*',
      })
    ).toBe(true);
  });

  test('3. Rejects localhost origins in production and permits them strictly in development mode', () => {
    const devOrigins = [
      'http://localhost:3000',
      'http://localhost:8080',
      'http://127.0.0.1:5173',
    ];

    for (const origin of devOrigins) {
      expect(isValidLoopbackOrigin(origin)).toBe(true);

      // Rejected in production
      const prodRes = evaluateCorsRequest(origin, {
        environment: 'production',
        allowLocalhostCors: false,
      });
      expect(prodRes.allowed).toBe(false);
      expect(prodRes.headers['Access-Control-Allow-Origin']).toBeUndefined();

      // Allowed in development
      const devRes = evaluateCorsRequest(origin, {
        environment: 'development',
      });
      expect(devRes.allowed).toBe(true);
      expect(devRes.headers['Access-Control-Allow-Origin']).toBe(origin);
    }
  });

  test('4. Rejects unknown, spoofed, wildcard, null, or HTTP origins and never reflects arbitrary Origin', () => {
    const untrustedOrigins = [
      'https://evil.example.com',
      'https://frosty-mug.github.io.attacker.com',
      'http://frosty-mug.github.io',
      'http://localhost.attacker.com:3000',
      'http://localhost',
      '*',
      'null',
      '',
    ];

    for (const origin of untrustedOrigins) {
      const res = evaluateCorsRequest(origin, {
        environment: 'development',
        allowLocalhostCors: true,
      });
      expect(res.allowed).toBe(false);
      expect(res.headers['Access-Control-Allow-Origin']).toBeUndefined();
      expect(res.headers['Access-Control-Allow-Origin']).not.toBe('*');
      expect(res.headers['Access-Control-Allow-Origin']).not.toBe(origin);
      expect(res.headers.Vary).toBe('Origin');
    }
  });

  test('5. Allows requests without an Origin header (native mobile/CLI) without setting wildcard ACAO', () => {
    const res = evaluateCorsRequest(null, { environment: 'production' });
    expect(res.allowed).toBe(true);
    expect(res.headers['Access-Control-Allow-Origin']).toBeUndefined();
    expect(res.headers.Vary).toBe('Origin');
  });

  test('6. Source scan confirms zero Access-Control-Allow-Origin: * wildcard anywhere in codebase', () => {
    const scanDirs = [
      path.join(ROOT, 'supabase/functions'),
      path.join(ROOT, 'desktop/src'),
      path.join(ROOT, 'src'),
    ];

    for (const dir of scanDirs) {
      const walk = (p: string) => {
        for (const entry of fs.readdirSync(p, { withFileTypes: true })) {
          const full = path.join(p, entry.name);
          if (entry.isDirectory()) {
            walk(full);
          } else if (/\.(ts|tsx|js)$/.test(entry.name) && !entry.name.endsWith('.test.ts')) {
            const raw = fs.readFileSync(full, 'utf8');
            const stripped = raw
              .replace(/\/\/[^\n]*/g, '')
              .replace(/\/\*[\s\S]*?\*\//g, '');
            expect(stripped).not.toMatch(/Access-Control-Allow-Origin['"`:\s=]+\*/i);
          }
        }
      };
      walk(dir);
    }

    expect(fs.existsSync(path.join(ROOT, 'docs/cors-policy.md'))).toBe(true);
  });

  test('7. Desktop Ghost Bridge enforces allowlist over live HTTP requests and blocks unauthorized origins', async () => {
    expect(
      isBridgeOriginAllowed('https://evil.example.com', { environment: 'development' })
    ).toBe(false);
    expect(
      isBridgeOriginAllowed('http://localhost:8080', { environment: 'production' })
    ).toBe(false);
    expect(
      isBridgeOriginAllowed('https://frosty-mug.github.io', { environment: 'production' })
    ).toBe(true);

    const bridge = new GhostBridgeServer();
    bridge.initHttpServer(0);
    bridge.initWebSocketServer();
    await new Promise<void>((resolve) => {
      if (bridge.server.listening) return resolve();
      bridge.server.once('listening', () => resolve());
    });
    const boundPort = bridge.server.address().port;
    try {
      // Allowed origin
      const okResp = await new Promise<{ status: number; acao?: string }>((resolve, reject) => {
        const req = http.get(
          {
            host: HOST,
            port: boundPort,
            path: '/status',
            headers: { Origin: 'https://frosty-mug.github.io' },
          },
          (res: any) => {
            res.resume();
            resolve({
              status: res.statusCode || 0,
              acao: res.headers['access-control-allow-origin'] as string | undefined,
            });
          }
        );
        req.on('error', reject);
      });
      expect(okResp.status).toBe(200);
      expect(okResp.acao).toBe('https://frosty-mug.github.io');

      // Rejected origin over HTTP
      const badResp = await new Promise<{ status: number; acao?: string }>((resolve, reject) => {
        const req = http.get(
          {
            host: HOST,
            port: boundPort,
            path: '/status',
            headers: { Origin: 'https://malicious.attacker.invalid' },
          },
          (res: any) => {
            res.resume();
            resolve({
              status: res.statusCode || 0,
              acao: res.headers['access-control-allow-origin'] as string | undefined,
            });
          }
        );
        req.on('error', reject);
      });
      expect(badResp.status).toBe(403);
      expect(badResp.acao).toBeUndefined();

      // Rejected origin over WebSocket upgrade
      const wsBadStatus = await new Promise<number>((resolve, reject) => {
        const req = http.request({
          host: HOST,
          port: boundPort,
          path: '/',
          method: 'GET',
          headers: {
            Connection: 'Upgrade',
            Upgrade: 'websocket',
            'Sec-WebSocket-Version': '13',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            Origin: 'https://malicious.attacker.invalid',
          },
        });
        req.on('response', (res: any) => {
          res.resume();
          resolve(res.statusCode || 0);
        });
        req.on('upgrade', (_res: any, socket: any) => {
          socket.destroy();
          resolve(101);
        });
        req.on('error', reject);
        req.end();
      });
      expect(wsBadStatus).toBe(403);
    } finally {
      bridge.stop();
    }
  });

  test('8. Edge Functions importing ../_shared/cors.ts reference real exported symbol evaluateCorsRequest', () => {
    const fnNames = ['recover-vault', 'migrate-recovery-verifier'];
    for (const fn of fnNames) {
      const src = fs.readFileSync(
        path.join(ROOT, 'supabase/functions', fn, 'index.ts'),
        'utf8'
      );
      expect(src).toMatch(/import\s*\{[^}]*\bevaluateCorsRequest\b[^}]*\}\s*from\s*["']\.\.\/_shared\/cors\.ts["']/);
      expect(src).toMatch(/\bevaluateCorsRequest\(/);
      expect(src).not.toMatch(/\bevaluateCors\(/);
    }
  });
});
