// Pure routing for two-step sign-in (TOTP). The database decides who needs it
// (session_needs_mfa()); this decides which screen the person sees next.
import { safeNextPath, DEFAULT_AFTER_SIGN_IN } from './redirect';

export type Aal = 'aal1' | 'aal2';
export type MfaStep = 'none' | 'verify' | 'enroll';

export const VERIFY_PATH = '/sign-in/verify';
export const SECURITY_PATH = '/app/security';

/** The `aal` claim, or null when absent or unrecognised (treated as not aal2). */
export function normalizeAal(value: unknown): Aal | null {
  return value === 'aal1' || value === 'aal2' ? value : null;
}

/**
 * The database's rule: a session that is not aal2 gets no access at all when the person holds
 * admin-tier access or has any verified factor (session_needs_mfa() is true for either). This
 * is the app's half, and it does not depend on that flag for the code screen:
 * - aal2: nothing more to do.
 * - Otherwise, a verified factor means "enter the code" for everyone, admin or not (a person who
 *   turned two-step sign-in on must not be able to skip it with just a password). `needsMfa` is
 *   true for these people too, so it cannot be read as "this person is an admin".
 * - No verified factor but the database says the session needs one: only admin-tier access can
 *   cause that, so set a device up first.
 */
export function decideMfaStep(input: {
  aal: Aal | null;
  needsMfa: boolean;
  hasVerifiedFactor: boolean;
}): MfaStep {
  if (input.aal === 'aal2') return 'none';
  if (input.hasVerifiedFactor) return 'verify';
  if (input.needsMfa) return 'enroll';
  return 'none';
}

/** Where to send the person for this step; null when there is nothing to do. */
export function mfaStepPath(step: MfaStep, next?: string | null): string | null {
  if (step === 'none') return null;
  const base = step === 'verify' ? VERIFY_PATH : SECURITY_PATH;
  const safe = safeNextPath(next ?? null);
  return safe === DEFAULT_AFTER_SIGN_IN ? base : `${base}?next=${encodeURIComponent(safe)}`;
}
