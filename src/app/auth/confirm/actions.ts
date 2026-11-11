'use server';

import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { parseConfirmRequest, sessionSwitch } from '@/lib/auth/confirm';
import { revokeSessionTokens } from '@/lib/auth/revoke-session';
import { stampActivity } from '@/lib/auth/activity-server';
import { rateLimited } from '@/lib/rate-limit';

/**
 * Runs when the person presses the button on /auth/confirm (POST). This is the only place a
 * token is verified: a GET (an email link scanner, a prefetch, a cross-site image tag) never
 * consumes it or signs anyone in. Failure goes to /sign-in?error=link with no detail.
 *
 * Login CSRF: a link can be planted to sign someone into an account that is not theirs. The
 * token's owner is unknown until it is verified, so this notes who (if anyone) is signed in in
 * this browser first. If verifying the link signs in a different person, that earlier session is
 * revoked at Supabase (the new session has already replaced it in the cookies) and the person is
 * sent through a page that says so. A failed link leaves the existing session alone.
 */
export async function confirmLink(formData: FormData): Promise<void> {
  const request = parseConfirmRequest({
    token_hash: formData.get('token_hash'),
    type: formData.get('type'),
    code: formData.get('code'),
    next: formData.get('next'),
  });
  if (!request) redirect('/sign-in?error=link');

  // Per client IP only (the token is the secret). Fails open: see rate-limit-constants.ts.
  if (await rateLimited('confirmLink')) redirect('/sign-in?error=limit');

  const supabase = await createClient();
  const before = await supabase.auth.getUser();
  const previousUserId = before.data.user?.id ?? null;
  const previousSession = previousUserId ? (await supabase.auth.getSession()).data.session : null;
  const { data, error } =
    request.kind === 'otp'
      ? await supabase.auth.verifyOtp({ type: request.type, token_hash: request.tokenHash })
      : await supabase.auth.exchangeCodeForSession(request.code);
  if (error) redirect('/sign-in?error=link');
  // A link signs the person in, so start their idle clock. Invite and recovery links give an
  // aal1 session: an admin still has to pass the second step before reaching admin screens.
  if (data.user) await stampActivity(data.user.id);
  if (sessionSwitch(previousUserId, data.user?.id) === 'switched') {
    if (previousSession) {
      const revoked = await revokeSessionTokens({
        access_token: previousSession.access_token,
        refresh_token: previousSession.refresh_token,
      });
      if (!revoked) console.error('confirm: could not revoke the replaced session');
    }
    redirect(`/auth/confirm/switched?next=${encodeURIComponent(request.next)}`);
  }
  redirect(request.next);
}
