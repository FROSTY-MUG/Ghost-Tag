// Ghost-Tag v2.1.0 - Zero-Knowledge Vault Recovery Edge Function
// Deno TypeScript environment for Supabase Edge Functions

import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.8";
import { timingSafeEqual } from "node:crypto";
import { evaluateCors } from "../_shared/cors.ts";

// Layered Rate Limiting Constants (15-minute sliding window)
const MAX_FAILED_PER_ACCOUNT = 25;
const MAX_FAILED_PER_USER = 20;
const MAX_FAILED_PER_IP = 100;
const GLOBAL_ALERT_THRESHOLD = 500;

// Strict RFC 4122 Variant 1 UUID validation regex
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
  const cors = evaluateCorsRequestCompat(origin);

  if (!cors.allowed) {
    return new Response(JSON.stringify({ error: "RECOVERY_FAILED" }), {
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
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 500, headers: responseHeaders }
      );
    }

    const clientIp = getClientIp(req);
    const clientIpHash = await hashIp(clientIp, ipSalt);

    const supabaseUrl = Deno.env.get("SUPABASE_URL") ?? "";
    const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const supabaseAnonKey = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

    if (!supabaseUrl || !supabaseServiceKey) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 500, headers: responseHeaders }
      );
    }

    // Optional authenticated user resolution
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
          // Continue recovery without user ID
        }
      }
    }

    // Parse and strictly validate input types
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

    const isValidAccountId = typeof account_id === "string" && RFC4122_UUID_REGEX.test(account_id);
    const isValidVerifier = typeof recovery_verifier === "string" && HEX64_REGEX.test(recovery_verifier);

    if (!isValidAccountId || !isValidVerifier) {
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 400, headers: responseHeaders }
      );
    }

    const adminClient = createClient(supabaseUrl, supabaseServiceKey);

    // Atomic PostgreSQL Transactional Rate-Limit Check
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

    const currentAttemptId = rateResult ? rateResult.attempt_id : null;

    // Global Non-Blocking Monitoring Check
    const windowStart = new Date(Date.now() - 15 * 60 * 1000).toISOString();
    const { count: globalFailures } = await adminClient
      .from("ghost_recovery_attempts")
      .select("*", { count: "exact", head: true })
      .eq("success", false)
      .gte("attempted_at", windowStart);

    if (globalFailures !== null && globalFailures >= GLOBAL_ALERT_THRESHOLD) {
      console.warn(`[GHOST_MONITOR_ALERT] Global recovery failures exceeded threshold: ${globalFailures}`);
    }

    // Look up target vault row via service_role (bypasses locked-down client RLS)
    const { data: vault, error: fetchError } = await adminClient
      .from("ghost_vaults")
      .select("account_id, owner_user_id, recovery_verifier, recovery_salt, recovery_kdf_version, encrypted_vault_blob, vault_version")
      .eq("account_id", account_id)
      .maybeSingle();

    const candidateVerifierBytes = hexToBytes(recovery_verifier);
    const dummyVerifierBytes = new Uint8Array(32);

    if (fetchError || !vault) {
      timingSafeEqual(Buffer.from(candidateVerifierBytes), Buffer.from(dummyVerifierBytes));

      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 403, headers: responseHeaders }
      );
    }

    // Constant-Time Comparison
    const storedVerifierBytes = typeof vault.recovery_verifier === "string"
      ? (vault.recovery_verifier.startsWith("\\x")
          ? hexToBytes(vault.recovery_verifier.slice(2))
          : hexToBytes(vault.recovery_verifier))
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
      return new Response(
        JSON.stringify({ error: "RECOVERY_FAILED" }),
        { status: 403, headers: responseHeaders }
      );
    }

    // Verification Succeeded: Mark attempt success = true
    if (currentAttemptId) {
      await adminClient
        .from("ghost_recovery_attempts")
        .update({ success: true })
        .eq("id", currentAttemptId);
    }

    // Reassign owner_user_id only if an authenticated user session was provided
    if (authenticatedUserId && authenticatedUserId !== vault.owner_user_id) {
      await adminClient
        .from("ghost_vaults")
        .update({
          owner_user_id: authenticatedUserId,
          updated_at: new Date().toISOString(),
        })
        .eq("account_id", account_id);
    }

    // Encode bytea encrypted_vault_blob to base64
    let encryptedBlobBase64 = "";
    if (typeof vault.encrypted_vault_blob === "string") {
      if (vault.encrypted_vault_blob.startsWith("\\x")) {
        const hex = vault.encrypted_vault_blob.slice(2);
        encryptedBlobBase64 = Buffer.from(hexToBytes(hex)).toString("base64");
      } else {
        encryptedBlobBase64 = vault.encrypted_vault_blob;
      }
    } else if (vault.encrypted_vault_blob instanceof Uint8Array || Buffer.isBuffer(vault.encrypted_vault_blob)) {
      encryptedBlobBase64 = Buffer.from(vault.encrypted_vault_blob).toString("base64");
    }

    return new Response(
      JSON.stringify({
        success: true,
        account_id: vault.account_id,
        encrypted_vault_blob: encryptedBlobBase64,
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

function evaluateCorsRequestCompat(origin: string | null) {
  return evaluateCors(origin, getCorsOptions());
}
