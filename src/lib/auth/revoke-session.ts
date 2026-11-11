import 'server-only';
import { createClient } from '@supabase/supabase-js';
import { getPublicEnv } from '@/lib/env';

/**
 * Ends one session at Supabase from its own tokens, without touching the browser's cookies.
 * Used when a confirmed link replaced someone else's session in this browser: the old session
 * is gone from the cookies already, and this makes sure it cannot be used from a copy either.
 * Uses the public key and the session's own tokens (no service-role key). Returns whether the
 * revoke went through; the caller logs nothing sensitive and carries on either way.
 */
export async function revokeSessionTokens(tokens: {
  access_token: string;
  refresh_token: string;
}): Promise<boolean> {
  try {
    const env = getPublicEnv();
    const client = createClient(
      env.NEXT_PUBLIC_SUPABASE_URL,
      env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY,
      { auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false } },
    );
    const set = await client.auth.setSession(tokens);
    if (set.error) return false;
    const out = await client.auth.signOut({ scope: 'local' });
    return !out.error;
  } catch {
    return false;
  }
}
