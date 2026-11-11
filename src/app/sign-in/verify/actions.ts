'use server';

import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { firstIssue, verifyCodeSchema, type FormState } from '@/lib/auth/schemas';
import { safeNextPath } from '@/lib/auth/redirect';
import { requireUser } from '@/lib/auth/session';
import { resolveMfaState, verifyFactorCode } from '@/lib/auth/mfa-server';
import { stampActivity } from '@/lib/auth/activity-server';
import { rateLimited } from '@/lib/rate-limit';
import { RATE_LIMITED_MESSAGE } from '@/lib/rate-limit-constants';

export async function verifySignInCode(_prev: FormState, formData: FormData): Promise<FormState> {
  const user = await requireUser();
  const parsed = verifyCodeSchema.safeParse({
    code: formData.get('code'),
    next: formData.get('next') ?? undefined,
  });
  if (!parsed.success) return { message: firstIssue(parsed.error) };

  // Per account email and per IP; fails closed, because this is a 6-digit code.
  if (await rateLimited('verifyCode', { email: user.email ?? user.id })) {
    return { message: RATE_LIMITED_MESSAGE };
  }

  const supabase = await createClient();
  const state = await resolveMfaState(supabase);
  if (state.aal === 'aal2') redirect(safeNextPath(parsed.data.next));
  const factors = await supabase.auth.mfa.listFactors();
  const factor = factors.data?.totp[0];
  if (factors.error || !factor) redirect('/app/security');

  const result = await verifyFactorCode(supabase, factor.id, parsed.data.code);
  if (!result.ok) return { message: result.message };
  await stampActivity(user.id);
  redirect(safeNextPath(parsed.data.next));
}
