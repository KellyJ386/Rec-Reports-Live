// Every rate-limit number in one place. Each limit is `max` attempts per `windowSeconds`,
// counted by the database (consume_rate_limit). An attempt counts whether or not it succeeds.
export const FIFTEEN_MINUTES = 15 * 60;

export type Limit = { readonly max: number; readonly windowSeconds: number };

export const RATE_LIMITS = {
  signIn: {
    email: { max: 5, windowSeconds: FIFTEEN_MINUTES },
    ip: { max: 20, windowSeconds: FIFTEEN_MINUTES },
  },
  forgotPassword: {
    email: { max: 5, windowSeconds: FIFTEEN_MINUTES },
    ip: { max: 20, windowSeconds: FIFTEEN_MINUTES },
  },
  // The one-time code screen and the "remove a device" check. Six digits, so keep it tight.
  verifyCode: {
    email: { max: 5, windowSeconds: FIFTEEN_MINUTES },
    ip: { max: 20, windowSeconds: FIFTEEN_MINUTES },
  },
  // The email-link button. There is no email to key on (the token is the secret), so IP only.
  confirmLink: {
    ip: { max: 20, windowSeconds: FIFTEEN_MINUTES },
  },
} as const satisfies Record<string, { email?: Limit; ip?: Limit }>;

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
