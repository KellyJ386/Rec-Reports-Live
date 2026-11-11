import 'server-only';
// Server-side halves of the idle timeout: stamping the cookie from an action, clearing it, and
// the re-check that requireUser runs even when the proxy was bypassed.
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/lib/supabase/database.types';
import { getSessionSecret } from '@/lib/env';
import {
  ACTIVITY_COOKIE,
  IDLE_SIGN_IN_PATH,
  activityCookieOptions,
  classifyActivity,
  idleVerdict,
  needsAdminTierLookup,
  signActivity,
} from './activity';
import { loadAdminTier } from './admin-tier-loader';

/** Stamp "active now" for this user. Call from Server Actions after a session is created. */
export async function stampActivity(userId: string): Promise<void> {
  const value = signActivity(userId, Math.floor(Date.now() / 1000), getSessionSecret());
  (await cookies()).set(ACTIVITY_COOKIE, value, activityCookieOptions());
}

export async function clearActivity(): Promise<void> {
  try {
    (await cookies()).delete(ACTIVITY_COOKIE);
  } catch {
    // Read-only context (a Server Component): the cookie is harmless without a session.
  }
}

/**
 * The second line of the idle timeout. The proxy has normally already decided; this catches a
 * request the proxy did not cover. Admin-tier session with a stale, missing or invalid stamp:
 * end the session and go to /sign-in. Not a stamp refresher: the proxy does that.
 */
export async function enforceIdleTimeout(
  supabase: SupabaseClient<Database>,
  userId: string,
): Promise<void> {
  const jar = await cookies();
  const state = classifyActivity(
    jar.get(ACTIVITY_COOKIE)?.value,
    userId,
    getSessionSecret(),
    Math.floor(Date.now() / 1000),
  );
  if (!needsAdminTierLookup(state)) return;
  const adminTier = await loadAdminTier(supabase, userId);
  if (idleVerdict(state, adminTier) !== 'sign_out') return;
  // Revokes the session at Supabase. Cookie deletion may be refused in a Server Component;
  // the revoked session is rejected by getUser() on the next request either way.
  await supabase.auth.signOut({ scope: 'local' });
  await clearActivity();
  redirect(IDLE_SIGN_IN_PATH);
}
