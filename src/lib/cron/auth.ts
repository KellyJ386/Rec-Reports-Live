import { createHash, timingSafeEqual } from 'node:crypto';

/** A cron secret shorter than this is treated as not configured. */
export const MIN_CRON_SECRET_LENGTH = 32;

/**
 * Checks `Authorization: Bearer <CRON_SECRET>` (what Vercel Cron sends when the CRON_SECRET
 * environment variable is set). Fails closed: an unset, empty or short (under 32 characters) secret refuses everything.
 * Both sides are hashed to a fixed length first so the comparison is constant time whatever the
 * length of what the caller sent.
 */
export function verifyCronAuth(authorization: string | null, secret: string | undefined): boolean {
  if (!secret || secret.length < MIN_CRON_SECRET_LENGTH) return false;
  if (!authorization) return false;
  const match = /^Bearer (.+)$/.exec(authorization);
  if (!match || match[1] === undefined) return false;
  const given = createHash('sha256').update(match[1]).digest();
  const wanted = createHash('sha256').update(secret).digest();
  return timingSafeEqual(given, wanted);
}
