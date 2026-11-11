'use server';

import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { parseConfirmRequest } from '@/lib/auth/confirm';
import { stampActivity } from '@/lib/auth/activity-server';
import { rateLimited } from '@/lib/rate-limit';

/**
 * Runs when the person presses the button on /auth/confirm (POST). This is the only place a
 * token is verified: a GET (an email link scanner, a prefetch, a cross-site image tag) never
 * consumes it or signs anyone in. Failure goes to /sign-in?error=link with no detail.
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
  const { data, error } =
    request.kind === 'otp'
      ? await supabase.auth.verifyOtp({ type: request.type, token_hash: request.tokenHash })
      : await supabase.auth.exchangeCodeForSession(request.code);
  if (error) redirect('/sign-in?error=link');
  // A link signs the person in, so start their idle clock. Invite and recovery links give an
  // aal1 session: an admin still has to pass the second step before reaching admin screens.
  if (data.user) await stampActivity(data.user.id);
  redirect(request.next);
}
