// Ghost-Tag v2.1.0 - Zero-Knowledge Legacy Recovery Migration Edge Function
// Deno TypeScript environment for Supabase Edge Functions

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.8";
import { timingSafeEqual } from "node:crypto";
import { evaluateCorsRequest } from "../_shared/cors.ts";

const MAX_FAILED_PER_ACCOUNT = 25;
const MAX_FAILED_PER_USER = 20;
const MAX_FAILED_PER_IP = 100;

const RFC4122_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_REGEX = /^[0-9a-fA-F]{64}$/;

function getCorsOptions() {
  return {
    environment: Deno.env.get("GHOST_ENV") ?? "production",
    allowLocalhostCors: Deno.env.get("ALLOW_LOCALHOST_CORS") === "true",
    approvedProductionOrigins: Deno.env.get("APPROVED_CORS_ORIGINS") ?? "",
  };
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substr(i, 2), 16);
  }
  return bytes;
}

function getClientIp(req: Request): string {
  const cfIp = req.headers.get("cf-connecting-ip");
  if (cfIp) return cfIp.trim();
  const realIp = req.headers.get("x-real-ip");
  if (realIp) return realIp.trim();
  const forwarded = req.headers.get("x-forwarded-for");
  if (forwarded) {
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
  const origin = req.headers.get("Origin");
  const cors = evaluateCorsRequest(origin, getCorsOptions());
  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
      status: 403,
      headers: { ...cors.headers, "Content-Type": "application/json" },
    });
  }

  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: cors.headers });
  }

  const responseHeaders = {
    ...cors.headers,
    "Content-Type": "application/json",
  };

  try {
    const ipSalt = Deno.env.get("IP_HASH_SALT");
    if (!ipSalt) {
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 500,
        headers: responseHeaders,
      });
    }

    const clientIp = getClientIp(req);
    const clientIpHash = await hashIp(clientIp, ipSalt);

    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

    if (!supabaseUrl || !supabaseServiceKey) {
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 500,
        headers: responseHeaders,
      });
    }

    // Zero-Knowledge Migration: Does NOT require an authenticated owner session.
    // The legacy recovery verifier is the proof of ownership.
    let authenticatedUserId: string | null = null;
    const authHeader = req.headers.get("Authorization");
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.replace("Bearer ", "").trim();
      if (token && token !== supabaseAnonKey) {
        try {
          const authClient = createClient(supabaseUrl, supabaseAnonKey, {
            global: { headers: { Authorization: authHeader } },
          });
          const { data: { user } } = await authClient.auth.getUser();
          if (user?.id) {
            authenticatedUserId = user.id;
          }
        } catch {
          // Continue migration without user ID
        }
      }
    }

    // Parse request body
    let body: any;
    try {
      body = await req.json();
    } catch {
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 400,
        headers: responseHeaders,
      });
    }

    const {
      account_id,
      legacy_recovery_verifier,
      new_recovery_verifier,
      recovery_salt,
    } = body;

    const isValidAccountId = typeof account_id === "string" && RFC4122_UUID_REGEX.test(account_id);
    const isValidLegacyVerifier = typeof legacy_recovery_verifier === "string" && HEX64_REGEX.test(legacy_recovery_verifier);
    const isValidNewVerifier = typeof new_recovery_verifier === "string" && HEX64_REGEX.test(new_recovery_verifier);
    const isValidRecoverySalt = typeof recovery_salt === "string" && HEX64_REGEX.test(recovery_salt);

    if (!isValidAccountId || !isValidLegacyVerifier || !isValidNewVerifier || !isValidRecoverySalt) {
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 400,
        headers: responseHeaders,
      });
    }

    const adminClient = createClient(supabaseUrl, supabaseServiceKey);

    // Atomic Rate-Limiting Check
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

    const rateResult = Array.isArray(rateCheckRows) && rateCheckRows.length > 0 ? rateCheckRows[0] : null;
    if (rateRpcError || (rateResult && rateResult.allowed === false)) {
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 429,
        headers: responseHeaders,
      });
    }

    const currentAttemptId = rateResult ? rateResult.attempt_id : null;

    // Atomic Transactional Verification and Migration via Postgres RPC
    const { data: migrationRows, error: migrationRpcError } = await adminClient.rpc(
      "migrate_recovery_verifier_atomic",
      {
        p_account_id: account_id,
        p_legacy_verifier: `\\x${legacy_recovery_verifier.toLowerCase()}`,
        p_new_verifier: `\\x${new_recovery_verifier.toLowerCase()}`,
        p_new_salt: `\\x${recovery_salt.toLowerCase()}`,
        p_new_owner_user_id: authenticatedUserId,
      }
    );

    const migrationResult = Array.isArray(migrationRows) && migrationRows.length > 0 ? migrationRows[0] : null;

    if (migrationRpcError || !migrationResult || migrationResult.migrated !== true) {
      const candidateLegacyBytes = hexToBytes(legacy_recovery_verifier);
      const dummyVerifierBytes = new Uint8Array(candidateLegacyBytes.length > 0 ? candidateLegacyBytes.length : 32);
      timingSafeEqual(Buffer.from(candidateLegacyBytes), Buffer.from(dummyVerifierBytes));

      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 403,
        headers: responseHeaders,
      });
    }

    // Verification and Migration Succeeded: Mark attempt success = true
    if (currentAttemptId) {
      await adminClient
        .from("ghost_recovery_attempts")
        .update({ success: true })
        .eq("id", currentAttemptId);
    }

    return new Response(
      JSON.stringify({
        success: true,
        recovery_kdf_version: 2,
      }),
      { status: 200, headers: responseHeaders }
    );
  } catch (_err) {
    return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
      status: 500,
      headers: responseHeaders,
    });
  }
});
