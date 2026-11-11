import 'server-only';
// Server-side two-step sign-in helpers. Everything here acts through the caller's own session.
import { cache } from 'react';
import { redirect } from 'next/navigation';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/lib/supabase/database.types';
import { createClient } from '@/lib/supabase/server';
import { mfaErrorMessage } from './mfa-errors';
import { decideMfaStep, mfaStepPath, normalizeAal, type Aal, type MfaStep } from './mfa';

export type MfaState = {
  aal: Aal | null;
  /**
   * The database's answer (session_needs_mfa()): the session is not aal2 and the person holds
   * admin-tier access or a verified factor, so the database is giving it no access yet.
   */
  needsMfa: boolean;
  step: MfaStep;
};

/** Reads the aal claim (verified), session_needs_mfa(), and the verified factors when needed. */
export async function resolveMfaState(supabase: SupabaseClient<Database>): Promise<MfaState> {
  const [claimsRes, needsRes] = await Promise.all([
    supabase.auth.getClaims(),
    supabase.rpc('session_needs_mfa'),
  ]);
  if (claimsRes.error) throw new Error('auth: getClaims failed');
  if (needsRes.error) {
    console.error('auth: session_needs_mfa failed', needsRes.error.code ?? '');
    throw new Error('auth: session_needs_mfa failed');
  }
  const aal = normalizeAal(claimsRes.data?.claims?.aal);
  const needsMfa = needsRes.data === true;

  let hasVerifiedFactor = false;
  if (aal !== 'aal2') {
    const factors = await supabase.auth.mfa.listFactors();
    if (factors.error) {
      console.error('auth: listFactors failed', factors.error.code ?? '');
      throw new Error('auth: listFactors failed');
    }
    // `totp` holds verified TOTP factors only; half-finished enrolments are not in it.
    hasVerifiedFactor = factors.data.totp.length > 0;
  }
  return { aal, needsMfa, step: decideMfaStep({ aal, needsMfa, hasVerifiedFactor }) };
}

/** Per-request cached version for pages and guards. */
export const getMfaState = cache(async (): Promise<MfaState> => {
  return resolveMfaState(await createClient());
});

/** Sends the person to the second step (code or set-up) unless the session is already done. */
export async function redirectIfMfaPending(next?: string | null): Promise<void> {
  const target = mfaStepPath((await getMfaState()).step, next);
  if (target) redirect(target);
}

export type FactorCheck = { ok: true } | { ok: false; message: string };

/**
 * Challenge + verify one factor with a code. On success Supabase issues new tokens with
 * `aal: aal2`, which the client writes to the session cookies (so call this from a Server
 * Action or Route Handler, where cookies are writable).
 */
export async function verifyFactorCode(
  supabase: SupabaseClient<Database>,
  factorId: string,
  code: string,
): Promise<FactorCheck> {
  const challenge = await supabase.auth.mfa.challenge({ factorId });
  if (challenge.error) {
    console.error('mfa: challenge failed', challenge.error.code ?? '');
    return { ok: false, message: mfaErrorMessage(challenge.error) };
  }
  const verified = await supabase.auth.mfa.verify({
    factorId,
    challengeId: challenge.data.id,
    code,
  });
  if (verified.error) {
    console.error('mfa: verify failed', verified.error.code ?? '');
    return { ok: false, message: mfaErrorMessage(verified.error) };
  }
  return { ok: true };
}
