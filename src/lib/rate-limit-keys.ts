// Pure: how rate-limit keys are made. No I/O, so it is unit tested.
import { createHmac } from 'node:crypto';

/**
 * The client IP, taken only from headers the hosting platform sets itself.
 *
 * Not `x-forwarded-for`: its first hop is whatever the client sent on hosts that append to it
 * instead of overwriting it, so an attacker could pick a fresh "IP" per request and never hit
 * a limit. Vercel (this app's host, see CLAUDE.md) sets `x-vercel-forwarded-for` and
 * `x-real-ip` to the connecting client and drops client-supplied copies. If neither is present
 * (local development, or a host that does not set them) this returns null and the caller
 * skips the per-IP limit: a shared "unknown" bucket would let one client lock everyone out.
 */
export const TRUSTED_IP_HEADERS = ['x-vercel-forwarded-for', 'x-real-ip'] as const;

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/** Expands "::" and returns the first four groups of an IPv6 address, or null if not IPv6. */
function ipv6Prefix64(ip: string): string | null {
  if (!/^[0-9a-f:.]+$/i.test(ip) || !ip.includes(':')) return null;
  const lower = ip.toLowerCase();
  // IPv4-mapped (::ffff:1.2.3.4): the IPv4 part is the identity.
  const mapped = /^::ffff:((?:\d{1,3}\.){3}\d{1,3})$/.exec(lower);
  if (mapped) return null;
  const halves = lower.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 0) return null;
  const groups = [...head, ...Array<string>(halves.length === 2 ? missing : 0).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some((g) => !/^[0-9a-f]{1,4}$/.test(g))) return null;
  return groups
    .slice(0, 4)
    .map((g) => g.padStart(4, '0'))
    .join(':');
}

/**
 * One value per client network: an IPv4 address as is, an IPv6 address reduced to its /64 (a
 * single subscriber usually holds a whole /64, so full addresses would be free to rotate).
 * Null for anything that does not look like an IP.
 */
export function normalizeIp(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const ip = raw.trim();
  if (ip.length === 0 || ip.length > 45) return null;
  const mapped = /^::ffff:((?:\d{1,3}\.){3}\d{1,3})$/i.exec(ip);
  const v4 = mapped ? mapped[1]! : ip;
  if (IPV4.test(v4)) {
    const parts = v4.split('.').map(Number);
    return parts.every((n) => n <= 255) ? parts.join('.') : null;
  }
  const prefix = ipv6Prefix64(ip);
  return prefix ? `${prefix}::/64` : null;
}

export function clientIp(headers: { get(name: string): string | null }): string | null {
  for (const name of TRUSTED_IP_HEADERS) {
    const value = headers.get(name);
    if (!value) continue;
    // These headers hold a single address. If a comma list shows up, the platform did not set
    // it: ignore the header rather than guess a hop.
    if (value.includes(',')) continue;
    const ip = normalizeIp(value);
    if (ip) return ip;
  }
  return null;
}

function digest(secret: string, purpose: string, value: string): string {
  return createHmac('sha256', secret).update(`rr-rate|${purpose}|${value}`).digest('hex');
}

/** Keyed hash of an email, so the limiter table never holds addresses. Case and spaces ignored. */
export function emailKey(email: string, secret: string): string {
  return digest(secret, 'email', email.trim().toLowerCase());
}

/** Keyed hash of a normalised IP. */
export function ipKey(ip: string, secret: string): string {
  return digest(secret, 'ip', ip);
}

export type KeyPlan = { bucket: string; key: string; max: number; windowSeconds: number };

/** The rows to count for one attempt: one per email, one per IP (when known). */
export function planKeys(input: {
  bucket: string;
  limits: {
    email?: { max: number; windowSeconds: number };
    ip?: { max: number; windowSeconds: number };
  };
  email?: string | null;
  ip?: string | null;
  secret: string;
}): KeyPlan[] {
  const plan: KeyPlan[] = [];
  if (input.limits.email && input.email) {
    plan.push({
      bucket: `${input.bucket}:email`,
      key: emailKey(input.email, input.secret),
      ...input.limits.email,
    });
  }
  if (input.limits.ip && input.ip) {
    plan.push({
      bucket: `${input.bucket}:ip`,
      key: ipKey(input.ip, input.secret),
      ...input.limits.ip,
    });
  }
  return plan;
}

export type LimitOutcome = 'allowed' | 'limited' | 'error';

/** Any "limited" wins; then any error; else allowed. */
export function combineOutcomes(outcomes: readonly LimitOutcome[]): LimitOutcome {
  if (outcomes.includes('limited')) return 'limited';
  if (outcomes.includes('error')) return 'error';
  return 'allowed';
}

/** True when the request must be refused, given the outcome and the endpoint's fail mode. */
export function shouldBlock(outcome: LimitOutcome, failMode: 'open' | 'closed'): boolean {
  if (outcome === 'limited') return true;
  if (outcome === 'error') return failMode === 'closed';
  return false;
}
