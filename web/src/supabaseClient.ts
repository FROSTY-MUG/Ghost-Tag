import { createClient, type SupabaseClient } from '@supabase/supabase-js';

export type CloudMode = 'offline' | 'supabase';

export interface CloudConfig {
  mode: CloudMode;
  url?: string;
  publishableKey?: string;
}

export function getCloudConfig(): CloudConfig {
  const url = import.meta.env.VITE_SUPABASE_URL;
  const key = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;
  const enabled = import.meta.env.VITE_GHOST_CLOUD_SYNC_ENABLED === 'true';

  if (enabled && url && key) {
    return {
      mode: 'supabase',
      url,
      publishableKey: key,
    };
  }

  return { mode: 'offline' };
}

export function createSupabaseClient(config: CloudConfig): SupabaseClient {
  if (config.mode !== 'supabase') {
    throw new Error('Cloud sync is not configured.');
  }

  return createClient(config.url!, config.publishableKey!, {
    auth: {
      autoRefreshToken: true,
      persistSession: true,
      detectSessionInUrl: false,
    },
  });
}
