// Ghost-Tag v2.0.5 - Hardened Vault Recovery Edge Function
// Deno TypeScript environment for Supabase Edge Functions

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.8";
import { timingSafeEqual } from "node:crypto";

// Layered Rate Limiting Constants (15-minute sliding window)
const MAX_FAILED_PER_ACCOUNT = 5;
const MAX_FAILED_PER_USER = 20;
const MAX_FAILED_PER_IP = 100;
const GLOBAL_ALERT_THRESHOLD = 500; // Alert-only monitoring threshold (non-blocking)

// Strict RFC 4122 Variant 1 UUID validation regex (no hex64 fallback)
const RFC4122_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_REGEX = /^[0-9a-fA-F]{64}$/;

// Restricted CORS whitelist: Only production GitHub Pages and trusted local development
const ALLOWED_ORIGINS = new Set([
  "https://frosty-mug.github.io",
  "http://localhost:8080",
  "http://localhost:3000",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:3000",
]);

function getCorsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin");
  const headers: Record<string, string> = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
    "Vary": "Origin",
  };

  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }
  return headers;
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Extracts client IP using Cloudflare/Supabase platform-provided headers.
 * Relies primarily on cf-connecting-ip which cannot be forged by clients.
 */
function getClientIp(req: Request): string {
  const cfIp = req.headers.get("cf-connecting-ip");
  if (cfIp) return cfIp.trim();

  const realIp = req.headers.get("x-real-ip");
  if (realIp) return realIp.trim();

  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
    // In a multi-proxy setup, take the client IP (first or trusted edge hop)
    const ips = forwarded.split(",").map((s) => s.trim()).filter(Boolean);
    if (ips.length > 0) return ips[0];
  }

  return "127.0.0.1";
}

async function hashIp(clientIp: string, salt: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(clientIp + ":" + salt);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

serve(async (req: Request) => {
  const corsHeaders = getCorsHeaders(req);

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const responseHeaders = {
    ...corsHeaders,
    "Content-Type": "application/json",
  };

  try {
    // 1. Fail closed if IP_HASH_SALT environment secret is missing
    const ipSalt = Deno.env.get("IP_HASH_SALT");
    if (!ipSalt) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 500, headers: responseHeaders }
      );
    }

    const clientIp = getClientIp(req);
    const clientIpHash = await hashIp(clientIp, ipSalt);

    // 2. Require valid Supabase user JWT
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 401, headers: responseHeaders }
      );
    }

    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

    if (!supabaseUrl || !supabaseServiceKey) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 500, headers: responseHeaders }
      );
    }

    const authClient = createClient(supabaseUrl, supabaseAnonKey, {
      global: { headers: { Authorization: authHeader } },
    });
    const { data: { user }, error: authError } = await authClient.auth.getUser();

    if (authError || !user) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 401, headers: responseHeaders }
      );
    }

    const authenticatedUserId = user.id;

    // 3. Parse and strictly validate input types and RFC 4122 UUID format
    let body: any;
    try {
      body = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 400, headers: responseHeaders }
      );
    }

    const { account_id, recovery_verifier } = body;

    // Strictly validate: account_id must be an RFC 4122 UUID, recovery_verifier must be 64 hex characters (32 bytes)
    const isValidAccountId = typeof account_id === "string" && RFC4122_UUID_REGEX.test(account_id);
    const isValidVerifier = typeof recovery_verifier === "string" && HEX64_REGEX.test(recovery_verifier);

    if (!isValidAccountId || !isValidVerifier) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 400, headers: responseHeaders }
      );
    }

    const adminClient = createClient(supabaseUrl, supabaseServiceKey);

    // 4. Atomic PostgreSQL Transactional Rate-Limit Check
    // Serializes concurrent requests per account_id to eliminate race condition bypasses
    const { data: rateCheckRows, error: rateRpcError } = await adminClient.rpc(
      "check_and_record_recovery_attempt",
      {
        p_account_id: account_id,
        p_user_id: authenticatedUserId,
        p_ip_hash: clientIpHash,
        p_max_account: MAX_FAILED_PER_ACCOUNT,
        p_max_user: MAX_FAILED_PER_USER,
        p_max_ip: MAX_FAILED_PER_IP,
      }
    );

    const rateResult = Array.isArray(rateCheckRows) && rateCheckRows.length > 0
      ? rateCheckRows[0]
      : null;

    if (rateRpcError || (rateResult && rateResult.allowed === false)) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 429, headers: responseHeaders }
      );
    }

    // 5. Global Monitoring Check (Alert-Only, Non-Blocking to Prevent Denial of Service)
    const windowStart = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const { count: globalFailures } = await adminClient
      .from("ghost_recovery_attempts")
      .select("*", { count: "exact", head: true })
      .eq("success", false)
      .gte("attempted_at", windowStart);

    if (globalFailures !== null && globalFailures >= GLOBAL_ALERT_THRESHOLD) {
      // Log security anomaly warning for administrative monitoring without blocking user requests
      console.warn(`[GHOST_MONITOR_ALERT] Global recovery failures exceeded threshold: ${globalFailures}`);
    }

    // 6. Look up target vault
    const { data: vault, error: fetchError } = await adminClient
      .from("ghost_vaults")
      .select("account_id, owner_user_id, recovery_verifier, recovery_salt, recovery_kdf_version, encrypted_vault_blob, vault_version")
      .eq("account_id", account_id)
      .maybeSingle();

    const candidateVerifierBytes = hexToBytes(recovery_verifier);
    const dummyVerifierBytes = new Uint8Array(32); // Constant 32-byte dummy

    if (fetchError || !vault) {
      // Execute maintained constant-time comparison to prevent timing account enumeration
      timingSafeEqual(Buffer.from(candidateVerifierBytes), Buffer.from(dummyVerifierBytes));

      await adminClient.from("ghost_recovery_attempts").insert({
        account_id,
        user_id: authenticatedUserId,
        ip_hash: clientIpHash,
        success: false,
      });

      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 403, headers: responseHeaders }
      );
    }

    // 7. Maintained Constant-Time Comparison via node:crypto
    const storedVerifierBytes = typeof vault.recovery_verifier === "string"
      ? hexToBytes(vault.recovery_verifier)
      : new Uint8Array(vault.recovery_verifier);

    let isMatch = false;
    if (candidateVerifierBytes.length === storedVerifierBytes.length) {
      isMatch = timingSafeEqual(
        Buffer.from(candidateVerifierBytes),
        Buffer.from(storedVerifierBytes)
      );
    } else {
      timingSafeEqual(Buffer.from(candidateVerifierBytes), Buffer.from(dummyVerifierBytes));
    }

    if (!isMatch) {
      await adminClient.from("ghost_recovery_attempts").insert({
        account_id,
        user_id: authenticatedUserId,
        ip_hash: clientIpHash,
        success: false,
      });

      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 403, headers: responseHeaders }
      );
    }

    // 8. Verification Succeeded: Reassign owner_user_id and log success
    await adminClient
      .from("ghost_vaults")
      .update({
        owner_user_id: authenticatedUserId,
        updated_at: new Date().toISOString(),
      })
      .eq("account_id", account_id);

    await adminClient.from("ghost_recovery_attempts").insert({
      account_id,
      user_id: authenticatedUserId,
      ip_hash: clientIpHash,
      success: true,
    });

    // 9. Return encrypted_vault_blob only after successful verification
    return new Response(
      JSON.stringify({
        success: true,
        account_id: vault.account_id,
        encrypted_vault_blob: vault.encrypted_vault_blob,
        vault_version: vault.vault_version,
      }),
      { status: 200, headers: responseHeaders }
    );
  } catch (_err) {
    return new Response(
      JSON.stringify({ error: "RECOVERY_FAILED" }),
      { status: 500, headers: responseHeaders }
    );
  }
});
