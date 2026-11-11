import { NextResponse, type NextRequest } from 'next/server';
import { updateSession } from '@/lib/supabase/proxy';
import { proxyRedirect } from '@/lib/auth/proxy-rules';
import {
  ACTIVITY_COOKIE,
  IDLE_SIGN_IN_PATH,
  activityCookieOptions,
  classifyActivity,
  idleVerdict,
  needsAdminTierLookup,
  signActivity,
} from '@/lib/auth/activity';
import { loadAdminTier } from '@/lib/auth/admin-tier-loader';
import { getSessionSecret } from '@/lib/env';

/**
 * Refreshes the session, applies the admin idle timeout and convenience redirects. It is NOT
 * the access control: every page and action calls a require* helper (src/lib/auth), and
 * requireUser re-checks the idle timeout.
 *
 * Idle timeout: a signed-in request carries a signed last-activity cookie. Fresh: re-stamp and
 * go on, no lookup. Stale, missing or invalid: look up whether the session holds admin-tier
 * access; if so sign out and send the person to /sign-in, otherwise re-stamp. Every matched
 * request counts as activity, including page prefetches.
 */
export async function proxy(request: NextRequest) {
  const session = await updateSession(request);
  const { pathname, search } = request.nextUrl;

  let stamp: string | null = null;
  if (session.userId) {
    const secret = getSessionSecret();
    const now = Math.floor(Date.now() / 1000);
    const state = classifyActivity(
      request.cookies.get(ACTIVITY_COOKIE)?.value,
      session.userId,
      secret,
      now,
    );
    if (needsAdminTierLookup(state)) {
      const adminTier = await loadAdminTier(session.supabase, session.userId);
      if (idleVerdict(state, adminTier) === 'sign_out') {
        // Revokes this session at Supabase and writes the cookie deletions to the response.
        await session.supabase.auth.signOut({ scope: 'local' });
        const redirect = NextResponse.redirect(new URL(IDLE_SIGN_IN_PATH, request.url));
        session.response.cookies.getAll().forEach((c) => redirect.cookies.set(c));
        redirect.cookies.delete(ACTIVITY_COOKIE);
        return redirect;
      }
    }
    stamp = signActivity(session.userId, now, secret);
  }

  const target = proxyRedirect(pathname, search, session.signedIn);
  if (!target) {
    if (stamp) session.response.cookies.set(ACTIVITY_COOKIE, stamp, activityCookieOptions());
    return session.response;
  }

  const redirect = NextResponse.redirect(new URL(target, request.url));
  // Keep any refreshed session cookies on the redirect.
  session.response.cookies.getAll().forEach((c) => redirect.cookies.set(c));
  if (stamp) redirect.cookies.set(ACTIVITY_COOKIE, stamp, activityCookieOptions());
  return redirect;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp|ico)$).*)',
  ],
};
