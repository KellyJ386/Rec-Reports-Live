'use server';

import { headers } from 'next/headers';
import { createClient } from '@/lib/supabase/server';
import { firstIssue, forgotPasswordSchema, type FormState } from '@/lib/auth/schemas';

// Same message whether or not the email exists, and whether or not sending worked.
const NEUTRAL = 'If that email has an account, we sent a link to reset the password.';

export async function requestPasswordReset(
  _prev: FormState,
  formData: FormData,
): Promise<FormState> {
  const parsed = forgotPasswordSchema.safeParse({ email: formData.get('email') });
  if (!parsed.success) return { message: firstIssue(parsed.error) };

  // The link target is built from the server's own view of its host. Supabase
  // additionally only honours redirect URLs on its allow-list.
  const h = await headers();
  const host = h.get('x-forwarded-host') ?? h.get('host');
  const proto =
    h.get('x-forwarded-proto') ?? (process.env.NODE_ENV === 'production' ? 'https' : 'http');
  const supabase = await createClient();
  try {
    await supabase.auth.resetPasswordForEmail(parsed.data.email, {
      redirectTo: host ? `${proto}://${host}/auth/confirm?next=/reset-password` : undefined,
    });
  } catch {
    // Swallowed on purpose: the response must not depend on the outcome.
  }
  return { ok: true, message: NEUTRAL };
}
