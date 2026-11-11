import { describe, expect, it } from 'vitest';
import {
  bucketName,
  clientIp,
  combineOutcomes,
  pairKey,
  runPlan,
  runningOnVercel,
  emailKey,
  ipKey,
  normalizeIp,
  planKeys,
  shouldBlock,
} from './rate-limit-keys';
import { FAIL_MODE, RATE_LIMITS } from './rate-limit-constants';

const SECRET = 'unit-test-secret-that-is-long-enough-1234';
const h = (init: Record<string, string>) => ({
  get: (name: string) => init[name.toLowerCase()] ?? null,
});

describe('clientIp', () => {
  it('on Vercel uses the platform headers and ignores x-forwarded-for entirely', () => {
    expect(clientIp(h({ 'x-vercel-forwarded-for': '203.0.113.7' }), true)).toBe('203.0.113.7');
    expect(clientIp(h({ 'x-real-ip': '203.0.113.8' }), true)).toBe('203.0.113.8');
    expect(clientIp(h({ 'x-forwarded-for': '198.51.100.1, 203.0.113.9' }), true)).toBeNull();
    expect(
      clientIp(h({ 'x-forwarded-for': '1.1.1.1', 'x-vercel-forwarded-for': '203.0.113.7' }), true),
    ).toBe('203.0.113.7');
  });
  it('off Vercel trusts no header at all, so a client cannot choose its own bucket', () => {
    expect(clientIp(h({ 'x-vercel-forwarded-for': '203.0.113.7' }), false)).toBeNull();
    expect(clientIp(h({ 'x-real-ip': '203.0.113.8' }), false)).toBeNull();
  });
  it('prefers x-vercel-forwarded-for over x-real-ip', () => {
    expect(
      clientIp(h({ 'x-vercel-forwarded-for': '203.0.113.1', 'x-real-ip': '203.0.113.2' }), true),
    ).toBe('203.0.113.1');
  });
  it('ignores a list or garbage in a trusted header', () => {
    expect(clientIp(h({ 'x-real-ip': '1.1.1.1, 2.2.2.2' }), true)).toBeNull();
    expect(clientIp(h({ 'x-real-ip': 'not an ip' }), true)).toBeNull();
    expect(clientIp(h({}), true)).toBeNull();
  });
});

describe('runningOnVercel', () => {
  it('is true only when VERCEL is set by the platform', () => {
    expect(runningOnVercel({ VERCEL: '1' })).toBe(true);
    expect(runningOnVercel({})).toBe(false);
    expect(runningOnVercel({ VERCEL: '' })).toBe(false);
  });
});

describe('normalizeIp', () => {
  it('keeps IPv4 and rejects out-of-range octets', () => {
    expect(normalizeIp(' 203.0.113.7 ')).toBe('203.0.113.7');
    expect(normalizeIp('999.1.1.1')).toBeNull();
  });
  it('reduces IPv6 to its /64 so rotating the low bits does not dodge the limit', () => {
    const a = normalizeIp('2001:db8:1:2:aaaa:bbbb:cccc:dddd');
    const b = normalizeIp('2001:DB8:1:2::1');
    expect(a).toBe('2001:0db8:0001:0002::/64');
    expect(b).toBe(a);
    expect(normalizeIp('2001:db8:1:3::1')).not.toBe(a);
  });
  it('treats an IPv4-mapped address as that IPv4', () => {
    expect(normalizeIp('::ffff:203.0.113.7')).toBe('203.0.113.7');
  });
  it('rejects junk', () => {
    expect(normalizeIp('')).toBeNull();
    expect(normalizeIp(null)).toBeNull();
    expect(normalizeIp('1:2:3')).toBeNull();
    expect(normalizeIp('x'.repeat(60))).toBeNull();
  });
});

describe('keys', () => {
  it('hashes emails case-insensitively and never contains the address', () => {
    const a = emailKey('Pat@Example.com ', SECRET);
    expect(a).toBe(emailKey('pat@example.com', SECRET));
    expect(a).toMatch(/^[0-9a-f]{64}$/);
    expect(a).not.toContain('pat');
  });
  it('depends on the secret and separates email from ip keys', () => {
    expect(emailKey('a@b.co', SECRET)).not.toBe(emailKey('a@b.co', SECRET + 'x'));
    expect(emailKey('1.2.3.4', SECRET)).not.toBe(ipKey('1.2.3.4', SECRET));
  });
});

describe('planKeys', () => {
  it('makes pair, email and ip counters, tightest first, with the configured numbers', () => {
    const plan = planKeys({
      bucket: 'signIn',
      limits: RATE_LIMITS.signIn,
      email: 'a@b.co',
      ip: '203.0.113.7',
      secret: SECRET,
    });
    expect(plan.map((p) => [p.bucket, p.max, p.windowSeconds])).toEqual([
      ['sign-in:pair', 5, 900],
      ['sign-in:email', 30, 900],
      ['sign-in:ip', 100, 900],
    ]);
  });
  it('bucket names satisfy the database check on consume_rate_limit', () => {
    const db = /^[a-z][a-z0-9_.:-]{0,62}$/;
    for (const bucket of Object.keys(RATE_LIMITS)) {
      for (const kind of ['pair', 'email', 'ip'] as const) {
        expect(bucketName(bucket, kind), bucket).toMatch(db);
      }
    }
    expect(bucketName('forgotPassword', 'email')).toBe('forgot-password:email');
  });
  it('skips the pair and ip counters when the ip is unknown, leaving the email ceiling', () => {
    expect(
      planKeys({
        bucket: 'signIn',
        limits: RATE_LIMITS.signIn,
        email: 'a@b.co',
        secret: SECRET,
      }).map((p) => p.bucket),
    ).toEqual(['sign-in:email']);
  });
  it('uses only the ip counter for ip-only buckets', () => {
    expect(
      planKeys({
        bucket: 'confirmLink',
        limits: RATE_LIMITS.confirmLink,
        email: 'a@b.co',
        ip: '203.0.113.7',
        secret: SECRET,
      }).map((p) => p.bucket),
    ).toEqual(['confirm-link:ip']);
  });
  it('the pair key differs per ip, so an attacker pair is not the owner pair', () => {
    const attacker = pairKey('Owner@Example.com', '198.51.100.9', SECRET);
    const owner = pairKey('owner@example.com ', '203.0.113.7', SECRET);
    expect(attacker).not.toBe(owner);
    expect(pairKey('Owner@Example.com', '203.0.113.7', SECRET)).toBe(owner);
    expect(attacker).not.toBe(emailKey('owner@example.com', SECRET));
  });
  it('sign-in numbers: tight pair, loose email ceiling, shared-network ip ceiling', () => {
    expect(RATE_LIMITS.signIn.pair.max).toBeLessThan(RATE_LIMITS.signIn.email.max);
    expect(RATE_LIMITS.signIn.email.max).toBeLessThan(RATE_LIMITS.signIn.ip.max);
    expect(RATE_LIMITS.signIn.ip.max).toBeGreaterThanOrEqual(100);
  });
});

describe('runPlan', () => {
  const plan = planKeys({
    bucket: 'signIn',
    limits: RATE_LIMITS.signIn,
    email: 'a@b.co',
    ip: '203.0.113.7',
    secret: SECRET,
  });
  it('consumes everything when nothing is limited', async () => {
    const seen: string[] = [];
    const outcome = await runPlan(plan, async (p) => {
      seen.push(p.bucket);
      return 'allowed';
    });
    expect(outcome).toBe('allowed');
    expect(seen).toEqual(['sign-in:pair', 'sign-in:email', 'sign-in:ip']);
  });
  it('stops at a limited pair so a blocked attacker cannot push up the email ceiling', async () => {
    const seen: string[] = [];
    const outcome = await runPlan(plan, async (p) => {
      seen.push(p.bucket);
      return p.bucket.endsWith(':pair') ? 'limited' : 'allowed';
    });
    expect(outcome).toBe('limited');
    expect(seen).toEqual(['sign-in:pair']);
  });
  it('keeps going after an error, and a later limit still wins', async () => {
    expect(
      await runPlan(plan, async (p) => (p.bucket.endsWith(':pair') ? 'error' : 'allowed')),
    ).toBe('error');
    expect(await runPlan(plan, async (p) => (p.bucket.endsWith(':ip') ? 'limited' : 'error'))).toBe(
      'limited',
    );
  });
});

describe('outcomes', () => {
  it('limited beats error beats allowed', () => {
    expect(combineOutcomes(['allowed', 'limited', 'error'])).toBe('limited');
    expect(combineOutcomes(['allowed', 'error'])).toBe('error');
    expect(combineOutcomes(['allowed', 'allowed'])).toBe('allowed');
  });
  it('blocks on error only for closed endpoints', () => {
    expect(shouldBlock('limited', 'open')).toBe(true);
    expect(shouldBlock('error', 'closed')).toBe(true);
    expect(shouldBlock('error', 'open')).toBe(false);
    expect(shouldBlock('allowed', 'closed')).toBe(false);
  });
  it('fails closed for password and code guessing, open only for the email-link button', () => {
    expect(FAIL_MODE).toEqual({
      signIn: 'closed',
      verifyCode: 'closed',
      forgotPassword: 'closed',
      confirmLink: 'open',
    });
  });
});
