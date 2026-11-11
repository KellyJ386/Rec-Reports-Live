'use server';

import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { requireRecentAuthentication } from '@/lib/auth/session';
import { firstIssue, resetPasswordSchema, type FormState } from '@/lib/auth/schemas';

export async function resetPassword(_prev: FormState, formData: FormData): Promise<FormState> {
  await requireRecentAuthentication();
  const parsed = resetPasswordSchema.safeParse({
    password: formData.get('password'),
    confirmPassword: formData.get('confirmPassword'),
  });
  if (!parsed.success) return { message: firstIssue(parsed.error) };

  const supabase = await createClient();
  const { error } = await supabase.auth.updateUser({ password: parsed.data.password });
  if (error) {
    return {
      message:
        error.status === 422
          ? 'That password was not accepted. Choose a different one.'
          : 'Could not change the password. Try again, or request a new link.',
    };
  }
  // Sign out every other session that still holds the old password.
  await supabase.auth.signOut({ scope: 'others' });
  redirect('/app');
}
