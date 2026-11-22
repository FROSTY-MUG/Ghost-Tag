// Ghost-Tag v2.1.0 - Zero-Knowledge Legacy Recovery Migration Edge Function
// Deno TypeScript environment for Supabase Edge Functions

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.8";
import { timingSafeEqual } from "node:crypto";

const MAX_FAILED_PER_ACCOUNT = 25;
const MAX_FAILED_PER_USER = 20;
const MAX_FAILED_PER_IP = 100;

const RFC4122_UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const HEX64_REGEX = /^[0-9a-fA-F]{64}$/;

const ALLOWED_ORIGINS = new Set([
  "https://frosty-mug.github.io",
  "http://localhost:8080",
  "http://localhost:3000",
  "http://127.0.0.1:8080",
  "http://127.0.0.1:3000",
]);

function getCorsHeaders(origin: string | null): Record<string, string> {
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
  if (origin && !ALLOWED_ORIGINS.has(origin)) {
    return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
      status: 403,
      headers: { "Content-Type": "application/json" },
    });
  }

  const corsHeaders = getCorsHeaders(origin);
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const responseHeaders = {
    ...corsHeaders,
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

    // Fetch vault record
    const { data: vault, error: fetchError } = await adminClient
      .from("ghost_vaults")
      .select("account_id, owner_user_id, recovery_verifier, recovery_salt, recovery_kdf_version, encrypted_vault_blob, vault_version")
      .eq("account_id", account_id)
      .maybeSingle();

    const candidateLegacyBytes = hexToBytes(legacy_recovery_verifier);
    const dummyVerifierBytes = new Uint8Array(candidateLegacyBytes.length > 0 ? candidateLegacyBytes.length : 32);

    if (fetchError || !vault) {
      timingSafeEqual(Buffer.from(candidateLegacyBytes), Buffer.from(dummyVerifierBytes));
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 403,
        headers: responseHeaders,
      });
    }

    // Require recovery_kdf_version to be EXACTLY 1
    // Rejects already-migrated vaults (kdf_version >= 2) and unknown kdf_versions
    const currentKdfVersion = Number(vault.recovery_kdf_version);
    if (currentKdfVersion !== 1) {
      timingSafeEqual(Buffer.from(candidateLegacyBytes), Buffer.from(dummyVerifierBytes));
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 403,
        headers: responseHeaders,
      });
    }

    // Verify legacy_recovery_verifier against stored verifier using timingSafeEqual
    const storedVerifierBytes = typeof vault.recovery_verifier === "string"
      ? (vault.recovery_verifier.startsWith("\\x")
          ? hexToBytes(vault.recovery_verifier.slice(2))
          : hexToBytes(vault.recovery_verifier))
      : new Uint8Array(vault.recovery_verifier);

    let isMatch = false;
    if (candidateLegacyBytes.length === storedVerifierBytes.length) {
      isMatch = timingSafeEqual(
        Buffer.from(candidateLegacyBytes),
        Buffer.from(storedVerifierBytes)
      );
    } else {
      timingSafeEqual(Buffer.from(candidateLegacyBytes), Buffer.from(dummyVerifierBytes));
    }

    if (!isMatch) {
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 403,
        headers: responseHeaders,
      });
    }

    // Verification Succeeded: Mark attempt success = true
    if (currentAttemptId) {
      await adminClient
        .from("ghost_recovery_attempts")
        .update({ success: true })
        .eq("id", currentAttemptId);
    }

    // Update vault to canonical Argon2id verifier with submitted canonical phrase-derived recovery_salt
    // Ownership is proven via legacy PBKDF2 verifier verification.
    // Preserves encrypted_vault_blob and vault_version intact.
    const updatePayload: Record<string, any> = {
      recovery_verifier: `\\x${new_recovery_verifier.toLowerCase()}`,
      recovery_salt: `\\x${recovery_salt.toLowerCase()}`,
      recovery_kdf_version: 2,
      updated_at: new Date().toISOString(),
    };

    if (authenticatedUserId && authenticatedUserId !== vault.owner_user_id) {
      updatePayload.owner_user_id = authenticatedUserId;
    }

    const { error: updateError } = await adminClient
      .from("ghost_vaults")
      .update(updatePayload)
      .eq("account_id", account_id);

    if (updateError) {
      return new Response(JSON.stringify({ error: "MIGRATION_FAILED" }), {
        status: 500,
        headers: responseHeaders,
      });
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
