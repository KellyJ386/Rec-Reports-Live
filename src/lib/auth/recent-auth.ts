// Pure check for "this session came from a recovery link or a recent sign-in". Used by
// /reset-password so a stale or unrelated session cannot set a new password there.
import { z } from 'zod';

/** How recent the sign-in or link must be. */
export const RECENT_AUTH_SECONDS = 15 * 60;

/** Methods that prove the person just clicked an emailed link or typed their password. */
const FRESH_METHODS = new Set(['recovery', 'otp', 'magiclink', 'password']);

const amrSchema = z.array(z.object({ method: z.string(), timestamp: z.number().finite() }).loose());

/**
 * True when the JWT's `amr` claim has a recovery/otp/magiclink/password entry whose
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
