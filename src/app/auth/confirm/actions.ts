'use server';

import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { parseConfirmRequest } from '@/lib/auth/confirm';

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

  const supabase = await createClient();
  const { error } =
    request.kind === 'otp'
      ? await supabase.auth.verifyOtp({ type: request.type, token_hash: request.tokenHash })
      : await supabase.auth.exchangeCodeForSession(request.code);
  redirect(error ? '/sign-in?error=link' : request.next);
}
