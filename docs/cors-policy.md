# Ghost-Tag CORS Policy

Ghost-Tag enforces a strict, fail-closed Cross-Origin Resource Sharing (CORS) allowlist across all Supabase Edge Functions (`supabase/functions/*`) and the local Ghost Bridge Desktop service (`desktop/src/server.js`).

## 1. Allowed Origins

| Environment | Allowed Origins | Enforcement |
|---|---|---|
| **Production** | `https://frosty-mug.github.io` and any validated HTTPS origin explicitly configured via `APPROVED_CORS_ORIGINS` | Exact origin match against `parseApprovedProductionOrigins()` |
| **Development Only** | `http://localhost:<port>` and `http://127.0.0.1:<port>` (ports `1..65535`) | Permitted **only** when `GHOST_ENV=development` or `ALLOW_LOCALHOST_CORS=true` |

## 2. Security Rules

1. **No Wildcards**: `Access-Control-Allow-Origin: *` is strictly prohibited and never emitted. Any `*` entry passed into `APPROVED_CORS_ORIGINS` is discarded.
2. **No Origin Reflection**: The server never echoes back an untrusted `Origin` header.
3. **Reject Unknown Origins**: Requests carrying an `Origin` outside the allowlist are rejected immediately with `HTTP 403` and no `Access-Control-Allow-Origin` header. Non-browser native mobile/CLI requests without an `Origin` header proceed under Edge Function authentication controls.
4. **Loopback Isolation**: Development localhost ports are rejected with `HTTP 403` whenever Edge Functions run with default production settings.
5. **Cache Safety**: `Vary: Origin` is included on all CORS responses.
6. **Desktop Ghost Bridge WebSocket Guard**: In `desktop/src/server.js`, both HTTP endpoints (`/status`) and WebSocket upgrade requests (`verifyClient`) enforce the same allowlist against the loopback binding (`127.0.0.1:41789`), while allowing desktop production testing only for approved origins.

## 3. Shared Implementation & Verification

- Shared allowlist implementation: `supabase/functions/_shared/cors.ts`
- Wired Edge Functions: `recover-vault`, `migrate-recovery-verifier`, and all v2.1.0 endpoints
- Automated verification suite: `src/__tests__/corsValidation.test.ts`
