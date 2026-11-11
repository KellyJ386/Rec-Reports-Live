'use server';

import { createClient } from '@/lib/supabase/server';
import { getSiteUrl } from '@/lib/env';
import { rateLimited } from '@/lib/rate-limit';
import { firstIssue, forgotPasswordSchema, type FormState } from '@/lib/auth/schemas';

// Same message whether or not the email exists, and whether or not sending worked.
const NEUTRAL = 'If that email has an account, we sent a link to reset the password.';

export async function requestPasswordReset(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = forgotPasswordSchema.safeParse({ email: formData.get('email') });
  if (!parsed.success) return { message: firstIssue(parsed.error) };

  // Limited per email and per IP. Limited, or a limiter fault (fails closed), gets the same
  // neutral message and no email, so the response never shows the limit or the account.
  if (await rateLimited('forgotPassword', { email: parsed.data.email })) {
    return { ok: true, message: NEUTRAL };
  }

  // The link target comes from the configured SITE_URL only, never from request headers.
  // /auth/confirm defaults `next` to /reset-password. Supabase also only honours redirect
  // URLs on its allow-list. A missing or invalid SITE_URL is a deployment error: it is
  // logged and the neutral message is still returned.
  const supabase = await createClient();
  try {
    await supabase.auth.resetPasswordForEmail(parsed.data.email, {
      redirectTo: `${getSiteUrl()}/auth/confirm`,
    });
  } catch (error) {
    // Swallowed on purpose: the response must not depend on the outcome.
    console.error(
      'forgot-password: could not request reset',
      error instanceof Error ? error.name : '',
    );
  }
  return { ok: true, message: NEUTRAL };
}
