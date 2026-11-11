// Every rate-limit number in one place. Each limit is `max` attempts per `windowSeconds`,
// counted by the database (consume_rate_limit). An attempt counts whether or not it succeeds.
//
// Three kinds of counter, from tight to loose (see planKeys / runPlan in rate-limit-keys.ts):
//   pair  email + client IP together. The tight, password-guessing limit.
//   email the account alone, a much looser ceiling.
//   ip    the network alone, sized for a shared facility network.
//
// Why: a limit keyed on the email alone lets anyone who knows an address burn the owner's
// attempts and lock them out (of sign-in and of password reset). Keying the tight limit on
// email + IP means an attacker's attempts only use up the attacker's own pair; the owner
// signing in from another address has a fresh pair. A limit keyed on the IP alone, counted on
// successes too, trips a whole shared network at shift change, so it is loose (100).
//
// Counters are consumed tight first, and the loose ones are NOT consumed once the tight one
// has refused. Otherwise an attacker hammering from one address would keep pushing the
// owner's email ceiling up after being blocked, and lock them out anyway.
//
// Remaining trade-off: successful sign-ins still count (there is no "refund" primitive in
// the database), and an attacker who can rotate IPs (a botnet, or many IPv6 /64s) can spend
// up to 30 attempts per 15 minutes on one email, which both lets them guess 30 times and, once
// used, blocks the owner for the rest of that window. The real per-account control is Supabase
// Auth's own "password verification attempt" hook and CAPTCHA (supabase/config.toml notes).
// Without a trusted client IP (not on Vercel) only the email ceiling applies.
export const FIFTEEN_MINUTES = 15 * 60;

export type Limit = { readonly max: number; readonly windowSeconds: number };
export type LimitSet = { pair?: Limit; email?: Limit; ip?: Limit };

export const RATE_LIMITS = {
  signIn: {
    pair: { max: 5, windowSeconds: FIFTEEN_MINUTES },
    email: { max: 30, windowSeconds: FIFTEEN_MINUTES },
    ip: { max: 100, windowSeconds: FIFTEEN_MINUTES },
  },
  // Mail is the abuse here, so the per-email limit stays tight. The response is the same
  // neutral text whether or not it is hit, and it does not touch sign-in's counters, so
  // nobody is locked out of signing in by it. The worst an attacker can do is delay a reset
  // email for the owner by 15 minutes (they can still sign in, or use an older email link).
  forgotPassword: {
    email: { max: 5, windowSeconds: FIFTEEN_MINUTES },
    ip: { max: 100, windowSeconds: FIFTEEN_MINUTES },
  },
  // The one-time code screen and the "remove a device" check. Six digits, so keep it tight.
  // These need a signed-in (password-verified) session, so an outsider cannot burn them.
  verifyCode: {
    email: { max: 5, windowSeconds: FIFTEEN_MINUTES },
    ip: { max: 100, windowSeconds: FIFTEEN_MINUTES },
  },
  // The email-link button. There is no email to key on (the token is the secret), so IP only.
  confirmLink: {
    ip: { max: 100, windowSeconds: FIFTEEN_MINUTES },
  },
} as const satisfies Record<string, LimitSet>;

export type RateBucket = keyof typeof RATE_LIMITS;

/**
 * What to do when the limiter itself fails (database error), decided per endpoint:
 * - signIn, verifyCode: closed. These guard guessing of passwords and 6-digit codes, so an
 *   unavailable limiter must not turn into unlimited guesses. The limiter lives in the same
 *   database Supabase Auth uses, so when it is down sign-in is mostly down anyway.
 * - forgotPassword: closed. The response is the same neutral text either way, and no email is
 *   sent, so a limiter outage cannot be used to flood a mailbox.
 * - confirmLink: open. The token is long and random, so guessing it is not the threat; being
 *   locked out of an invite or reset link because of a limiter fault is the worse outcome.
 */
export const FAIL_MODE: Record<RateBucket, 'open' | 'closed'> = {
  signIn: 'closed',
  verifyCode: 'closed',
  forgotPassword: 'closed',
  confirmLink: 'open',
};

export const RATE_LIMITED_MESSAGE = 'Too many attempts. Try again in a few minutes.';
