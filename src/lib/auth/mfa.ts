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
 * - aal2: nothing more to do.
 * - Otherwise, a verified factor means "enter the code" for everyone, admin or not (a person who
 *   turned two-step sign-in on must not be able to skip it with just a password).
 * - No verified factor but the database says the session needs one: set it up first.
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
