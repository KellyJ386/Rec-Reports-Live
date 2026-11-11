// Pure: how rate-limit keys are made. No I/O, so it is unit tested.
import { createHmac } from 'node:crypto';

/**
 * The client IP, taken only from headers the hosting platform sets itself, and only when this
 * app is running on that platform.
 *
 * Not `x-forwarded-for`: its first hop is whatever the client sent on hosts that append to it
 * instead of overwriting it, so an attacker could pick a fresh "IP" per request and never hit
 * a limit. On Vercel (this app's host, see CLAUDE.md, detected by `process.env.VERCEL`) the
 * edge sets `x-vercel-forwarded-for` and `x-real-ip` to the connecting client and drops
 * client-supplied copies. Anywhere else (local development, `next start` behind some other
 * proxy, a preview on another host) nothing sets those headers for us, so a client could send
 * them itself: they are ignored and there is no IP bucket. (A shared "unknown" bucket would let
 * one client lock everyone out.) The caller then relies on the email-based limits only.
 * The `@vercel/functions` helper (`ipAddress`) is not installed and not needed: it reads the
 * same header.
 */
export const TRUSTED_IP_HEADERS = ['x-vercel-forwarded-for', 'x-real-ip'] as const;

/** True only on Vercel's platform (it sets VERCEL=1 at build and run time). */
export function runningOnVercel(env: Record<string, string | undefined> = process.env): boolean {
  return env.VERCEL === '1' || env.VERCEL === 'true';
}

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

export function clientIp(
  headers: { get(name: string): string | null },
  onVercel: boolean = runningOnVercel(),
): string | null {
  if (!onVercel) return null;
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

/** Keyed hash of an email and a normalised IP together: one counter per (account, network). */
export function pairKey(email: string, ip: string, secret: string): string {
  return digest(secret, 'pair', `${email.trim().toLowerCase()}|${ip}`);
}

/**
 * The database accepts bucket names matching ^[a-z][a-z0-9_.:-]{0,62}$ (consume_rate_limit), so
 * `signIn` is sent as `sign-in`.
 */
export function bucketName(bucket: string, kind: 'pair' | 'email' | 'ip'): string {
  const kebab = bucket.replace(/[A-Z]/g, (c) => `-${c.toLowerCase()}`);
  return `${kebab}:${kind}`;
}

export type KeyPlan = { bucket: string; key: string; max: number; windowSeconds: number };

/**
 * The counters to consume for one attempt, tightest first: one per (email, IP) pair, then one
 * per email, then one per IP. A counter is left out when its limit is not configured or the
 * value it needs (the email, the IP) is unknown. Order matters: see runPlan.
 */
export function planKeys(input: {
  bucket: string;
  limits: {
    pair?: { max: number; windowSeconds: number };
    email?: { max: number; windowSeconds: number };
    ip?: { max: number; windowSeconds: number };
  };
  email?: string | null;
  ip?: string | null;
  secret: string;
}): KeyPlan[] {
  const plan: KeyPlan[] = [];
  const { limits, email, ip, secret } = input;
  if (limits.pair && email && ip) {
    plan.push({
      bucket: bucketName(input.bucket, 'pair'),
      key: pairKey(email, ip, secret),
      ...limits.pair,
    });
  }
  if (limits.email && email) {
    plan.push({
      bucket: bucketName(input.bucket, 'email'),
      key: emailKey(email, secret),
      ...limits.email,
    });
  }
  if (limits.ip && ip) {
    plan.push({ bucket: bucketName(input.bucket, 'ip'), key: ipKey(ip, secret), ...limits.ip });
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

/**
 * Consumes the plan in order and stops at the first "limited": the looser counters after it are
 * not touched. This is what keeps an attacker who is already blocked on their own (email, IP)
 * pair from also pushing up the account-wide and network-wide counters and locking out the real
 * owner. An "error" does not stop the walk (the other counters still guard the endpoint).
 */
export async function runPlan(
  plan: readonly KeyPlan[],
  consume: (step: KeyPlan) => Promise<LimitOutcome>,
): Promise<LimitOutcome> {
  const outcomes: LimitOutcome[] = [];
  for (const step of plan) {
    const outcome = await consume(step);
    outcomes.push(outcome);
    if (outcome === 'limited') break;
  }
  return combineOutcomes(outcomes);
}
