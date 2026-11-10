'use server';

import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { firstIssue, signInSchema, type FormState } from '@/lib/auth/schemas';
import { safeNextPath } from '@/lib/auth/redirect';

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

  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithPassword({
    email: parsed.data.email,
    password: parsed.data.password,
  });
  if (error) {
    return {
      message:
        error.status !== undefined && error.status >= 500
          ? 'Sign-in is unavailable right now. Try again in a moment.'
          : BAD_CREDENTIALS,
    };
  }
  redirect(safeNextPath(parsed.data.next));
}
