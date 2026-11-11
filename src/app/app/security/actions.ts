'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { createClient } from '@/lib/supabase/server';
import {
  confirmEnrollSchema,
  firstIssue,
  removeFactorSchema,
  type FormState,
} from '@/lib/auth/schemas';
import { safeNextPath } from '@/lib/auth/redirect';
import { requireUser } from '@/lib/auth/session';
import { verifyFactorCode } from '@/lib/auth/mfa-server';
import { MFA_UNAVAILABLE } from '@/lib/auth/mfa-errors';
import { stampActivity } from '@/lib/auth/activity-server';
import { rateLimited } from '@/lib/rate-limit';
import { RATE_LIMITED_MESSAGE } from '@/lib/rate-limit-constants';

export type EnrollState = FormState & {
  factorId?: string;
  /** SVG data URI from Supabase, only when it has the expected shape. */
  qrCode?: string;
  secret?: string;
  uri?: string;
};

/** Only an SVG data URI is rendered as an image. Anything else falls back to the text secret. */
function safeQrCode(value: unknown): string | undefined {
  return typeof value === 'string' && /^data:image\/svg\+xml[;,]/i.test(value) ? value : undefined;
}

/** Step 1: ask Supabase for a new TOTP factor. It is not active until a code is verified. */
export async function startEnrollment(): Promise<EnrollState> {
  await requireUser();
  const supabase = await createClient();

  // A half-finished earlier attempt would block a new one (and clutter the list): drop it.
  const existing = await supabase.auth.mfa.listFactors();
  if (existing.error) return { message: MFA_UNAVAILABLE };
  if (existing.data.totp.length > 0) return { message: 'Two-step sign-in is already on.' };
  for (const factor of existing.data.all) {
    if (factor.status === 'unverified') await supabase.auth.mfa.unenroll({ factorId: factor.id });
  }

  const { data, error } = await supabase.auth.mfa.enroll({
    factorType: 'totp',
    issuer: 'Rec Reports',
    friendlyName: `Authenticator app ${new Date().toISOString().slice(0, 10)} ${crypto.randomUUID().slice(0, 8)}`,
  });
  if (error || !data) {
    console.error('mfa: enroll failed', error?.code ?? '');
    return { message: MFA_UNAVAILABLE };
  }
  return {
    ok: true,
    factorId: data.id,
    qrCode: safeQrCode(data.totp.qr_code),
    secret: data.totp.secret,
    uri: data.totp.uri,
  };
}

/** Step 2: the person types a code from the app. A right code turns two-step sign-in on. */
export async function confirmEnrollment(
  _prev: EnrollState,
  formData: FormData,
): Promise<EnrollState> {
  const user = await requireUser();
  const parsed = confirmEnrollSchema.safeParse({
    factorId: formData.get('factorId'),
    code: formData.get('code'),
  });
  const echo = { factorId: String(formData.get('factorId') ?? '') };
  if (!parsed.success) return { ...echo, message: firstIssue(parsed.error) };

  if (await rateLimited('verifyCode', { email: user.email ?? user.id })) {
    return { ...echo, message: RATE_LIMITED_MESSAGE };
  }

  const supabase = await createClient();
  const result = await verifyFactorCode(supabase, parsed.data.factorId, parsed.data.code);
  if (!result.ok) return { ...echo, message: result.message };
  await stampActivity(user.id);
  revalidatePath('/app/security');
  const next = safeNextPath(
    typeof formData.get('next') === 'string' ? (formData.get('next') as string) : null,
    '/app/security?on=1',
  );
  redirect(next);
}

/** Remove a device. The person must enter a current code from it first. */
export async function removeFactor(_prev: FormState, formData: FormData): Promise<FormState> {
  const user = await requireUser();
  const parsed = removeFactorSchema.safeParse({
    factorId: formData.get('factorId'),
    code: formData.get('code'),
  });
  if (!parsed.success) return { message: firstIssue(parsed.error) };

  if (await rateLimited('verifyCode', { email: user.email ?? user.id })) {
    return { message: RATE_LIMITED_MESSAGE };
  }

  const supabase = await createClient();
  const check = await verifyFactorCode(supabase, parsed.data.factorId, parsed.data.code);
  if (!check.ok) return { message: check.message };

  const { error } = await supabase.auth.mfa.unenroll({ factorId: parsed.data.factorId });
  if (error) {
    console.error('mfa: unenroll failed', error.code ?? '');
    return { message: 'Could not remove that device. Try again.' };
  }
  // Best effort: get fresh tokens so the session no longer claims aal2 for a removed factor.
  await supabase.auth.refreshSession();
  revalidatePath('/app/security');
  redirect('/app/security?removed=1');
}
