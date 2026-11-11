// Idle sign-out for admin-tier sessions (docs/SECURITY.md: 30 minutes). Pure and unit tested.
//
// How it works: every request from a signed-in browser re-stamps a cookie holding the time of
// the last request, signed with a server secret and bound to the user id. A session that holds
// admin-tier access and arrives with a stale, missing, tampered or other-user cookie is signed
// out. The cookie is httpOnly, so scripts cannot read it, and it is signed, so the browser's
// owner cannot write a newer time into it. Replaying an old cookie gains nothing: its time is
// its time.
import { createHmac, timingSafeEqual } from 'node:crypto';

export const ACTIVITY_COOKIE = 'rr_activity';
export const IDLE_TIMEOUT_SECONDS = 30 * 60;
/** Browser-side lifetime of the cookie. Longer than the timeout so "stale" and "missing" differ. */
export const ACTIVITY_COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60;
/** A stamp from the future (clock skew between hosts) is tolerated up to this much. */
const FUTURE_SKEW_SECONDS = 60;

export type ActivityState = 'fresh' | 'stale' | 'missing' | 'invalid';

function mac(secret: string, userId: string, issuedAt: number): string {
  return createHmac('sha256', secret)
    .update(`rr-activity|v1|${userId.toLowerCase()}|${issuedAt}`)
    .digest('base64url');
}

/** The cookie value for "this user made a request at `issuedAtSeconds`". */
export function signActivity(userId: string, issuedAtSeconds: number, secret: string): string {
  const issuedAt = Math.floor(issuedAtSeconds);
  return `${issuedAt}.${mac(secret, userId, issuedAt)}`;
}

/**
 * Reads a cookie value. `missing` = no cookie; `invalid` = malformed, wrong signature, signed
 * for another user, or dated in the future; `stale` = genuine but older than the timeout;
 * `fresh` = genuine and recent.
 */
export function classifyActivity(
  value: string | null | undefined,
  userId: string,
  secret: string,
  nowSeconds: number,
  timeoutSeconds: number = IDLE_TIMEOUT_SECONDS,
): ActivityState {
  if (value === undefined || value === null || value === '') return 'missing';
  const match = /^(\d{1,12})\.([A-Za-z0-9_-]{43})$/.exec(value);
  if (!match) return 'invalid';
  const issuedAt = Number(match[1]);
  const given = Buffer.from(match[2]!);
  const expected = Buffer.from(mac(secret, userId, issuedAt));
  if (given.length !== expected.length || !timingSafeEqual(given, expected)) return 'invalid';
  const age = nowSeconds - issuedAt;
  if (age < -FUTURE_SKEW_SECONDS) return 'invalid';
  return age > timeoutSeconds ? 'stale' : 'fresh';
}

/** Only a `fresh` stamp skips the "does this session hold admin-tier access?" lookup. */
export function needsAdminTierLookup(state: ActivityState): boolean {
  return state !== 'fresh';
}

/**
 * The decision. Non-admin sessions are never signed out for idleness. An admin-tier session
 * is signed out unless its stamp is fresh. When the lookup could not be made, pass
 * `adminTier = true`: failing closed signs an idle person out rather than keeping an
 * admin session alive.
 */
export function idleVerdict(state: ActivityState, adminTier: boolean): 'allow' | 'sign_out' {
  if (state === 'fresh') return 'allow';
  return adminTier ? 'sign_out' : 'allow';
}

export function activityCookieOptions(
  isProduction: boolean = process.env.NODE_ENV === 'production',
) {
  return {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax' as const,
    path: '/',
    maxAge: ACTIVITY_COOKIE_MAX_AGE_SECONDS,
  };
}

export const IDLE_SIGN_IN_PATH = '/sign-in?reason=idle';
export const IDLE_NOTE = 'You were signed out after 30 minutes without activity. Sign in again.';
