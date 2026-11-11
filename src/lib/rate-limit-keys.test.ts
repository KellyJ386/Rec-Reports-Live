import { describe, expect, it } from 'vitest';
import {
  clientIp,
  combineOutcomes,
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
  it('uses the platform headers and ignores x-forwarded-for entirely', () => {
    expect(clientIp(h({ 'x-vercel-forwarded-for': '203.0.113.7' }))).toBe('203.0.113.7');
    expect(clientIp(h({ 'x-real-ip': '203.0.113.8' }))).toBe('203.0.113.8');
    expect(clientIp(h({ 'x-forwarded-for': '198.51.100.1, 203.0.113.9' }))).toBeNull();
    expect(
      clientIp(h({ 'x-forwarded-for': '1.1.1.1', 'x-vercel-forwarded-for': '203.0.113.7' })),
    ).toBe('203.0.113.7');
  });
  it('prefers x-vercel-forwarded-for over x-real-ip', () => {
    expect(
      clientIp(h({ 'x-vercel-forwarded-for': '203.0.113.1', 'x-real-ip': '203.0.113.2' })),
    ).toBe('203.0.113.1');
  });
  it('ignores a list or garbage in a trusted header', () => {
    expect(clientIp(h({ 'x-real-ip': '1.1.1.1, 2.2.2.2' }))).toBeNull();
    expect(clientIp(h({ 'x-real-ip': 'not an ip' }))).toBeNull();
    expect(clientIp(h({}))).toBeNull();
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
  it('makes one row per email and one per ip with the configured numbers', () => {
    const plan = planKeys({
      bucket: 'signIn',
      limits: RATE_LIMITS.signIn,
      email: 'a@b.co',
      ip: '203.0.113.7',
      secret: SECRET,
    });
    expect(plan.map((p) => [p.bucket, p.max, p.windowSeconds])).toEqual([
      ['signIn:email', 5, 900],
      ['signIn:ip', 20, 900],
    ]);
  });
  it('skips the ip row when the ip is unknown, and the email row for ip-only buckets', () => {
    expect(
      planKeys({ bucket: 'signIn', limits: RATE_LIMITS.signIn, email: 'a@b.co', secret: SECRET }),
    ).toHaveLength(1);
    expect(
      planKeys({
        bucket: 'confirmLink',
        limits: RATE_LIMITS.confirmLink,
        email: 'a@b.co',
        ip: '203.0.113.7',
        secret: SECRET,
      }).map((p) => p.bucket),
    ).toEqual(['confirmLink:ip']);
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
