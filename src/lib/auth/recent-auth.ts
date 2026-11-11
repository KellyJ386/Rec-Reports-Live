// Pure check for "this session came from a recovery link or a recent sign-in". Used by
// /reset-password so a stale or unrelated session cannot set a new password there.
import { z } from 'zod';

/** How recent the sign-in or link must be. */
export const RECENT_AUTH_SECONDS = 15 * 60;

/** Methods that prove the person just clicked an emailed link or typed their password. */
const FRESH_METHODS = new Set([
  'recovery',
  'otp',
  'magiclink',
  'password',
  // An accepted invite (GoTrue amr method `invite`; `email/signup` for the sign-up variant).
  'invite',
  'email/signup',
]);

const amrSchema = z.array(z.object({ method: z.string(), timestamp: z.number().finite() }).loose());

/**
 * True when the JWT's `amr` claim has a recovery/invite/otp/magiclink/password entry whose
 * timestamp (seconds since epoch) is within `maxAgeSeconds` of `nowSeconds` and not in the
 * future (a small allowance for clock skew). Anything malformed is false.
 */
export function hasRecentAuthentication(
  claims: { amr?: unknown } | null | undefined,
  nowSeconds: number,
  maxAgeSeconds: number = RECENT_AUTH_SECONDS,
): boolean {
  const parsed = amrSchema.safeParse(claims?.amr);
  if (!parsed.success) return false;
  return parsed.data.some((entry) => {
    if (!FRESH_METHODS.has(entry.method)) return false;
    const age = nowSeconds - entry.timestamp;
    return age >= -60 && age <= maxAgeSeconds;
  });
}

export type RecentAuthDecision = 'ok' | 'verify' | 'restart';

/**
 * Whether /reset-password may show or accept the password form.
 *
 * - `verify`: the account has two-step sign-in (a verified factor) and this session has not
 *   passed it. A password, or a recovery link, alone must not change the password of such an
 *   account, so the person is sent to enter their code first (and comes back here).
 * - `ok`: the session came from a recent recovery link or sign-in (and any second step is done).
 * - `restart`: nothing recent enough; ask for a new link.
 * An admin who has no device yet (step `enroll`) has no second step to pass, so they are not
 * held up here; their email link is the proof.
 */
export function decideRecentAuthentication(input: {
  claims: { amr?: unknown } | null | undefined;
  mfaStep: 'none' | 'verify' | 'enroll';
  nowSeconds: number;
}): RecentAuthDecision {
  if (input.mfaStep === 'verify') return 'verify';
  return hasRecentAuthentication(input.claims, input.nowSeconds) ? 'ok' : 'restart';
}
