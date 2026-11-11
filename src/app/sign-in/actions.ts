'use server';

import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { firstIssue, signInSchema, type FormState } from '@/lib/auth/schemas';
import { safeNextPath } from '@/lib/auth/redirect';
import { stampActivity } from '@/lib/auth/activity-server';
import { resolveMfaState } from '@/lib/auth/mfa-server';
import { mfaStepPath } from '@/lib/auth/mfa';
import { rateLimited } from '@/lib/rate-limit';
import { RATE_LIMITED_MESSAGE } from '@/lib/rate-limit-constants';

// One message for every credential failure, so the response never says
// whether the email exists, is unconfirmed or is disabled.
const BAD_CREDENTIALS = 'Email or password is incorrect.';

export async function signIn(_prev: FormState, formData: FormData): Promise<FormState> {
  const parsed = signInSchema.safeParse({
    email: formData.get('email'),
    password: formData.get('password'),
    next: formData.get('next') ?? undefined,
  });
  if (!parsed.success) return { message: firstIssue(parsed.error) };

  // Counted before the password is checked, so the answer is the same whether or not the
  // account exists. The tight limit is per (email, client IP) pair, with looser per-email and
  // per-IP ceilings, so knowing someone's email does not let you lock them out
  // (see rate-limit-constants.ts). Fails closed.
  if (await rateLimited('signIn', { email: parsed.data.email })) {
    return { message: RATE_LIMITED_MESSAGE };
  }

  const supabase = await createClient();
  const { data, error } = await supabase.auth.signInWithPassword({
    email: parsed.data.email,
    password: parsed.data.password,
  });
  if (error || !data.user) {
    return {
      message:
        error?.status !== undefined && error.status >= 500
          ? 'Sign-in is unavailable right now. Try again in a moment.'
          : BAD_CREDENTIALS,
    };
  }

  // Start the idle clock, then send admins (and anyone who turned it on) to the second step.
  await stampActivity(data.user.id);
  const next = safeNextPath(parsed.data.next);
  const state = await resolveMfaState(supabase);
  redirect(mfaStepPath(state.step, next) ?? next);
}
