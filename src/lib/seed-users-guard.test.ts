import { describe, expect, it } from 'vitest';
// @ts-expect-error -- plain .mjs script helper, no type declarations
import { canLinkExistingUser } from '../../scripts/seed-users-guard.mjs';

type Decision = { link: boolean; reason?: string };
const check = canLinkExistingUser as (u: unknown, flag: boolean) => Decision;

describe('canLinkExistingUser', () => {
  it('refuses without --link-existing, even for a confirmed user', () => {
    const d = check({ email_confirmed_at: '2026-01-01T00:00:00Z' }, false);
    expect(d.link).toBe(false);
    expect(d.reason).toMatch(/--link-existing/);
  });
  it('refuses an unconfirmed user even with the flag', () => {
    const d = check({ email_confirmed_at: null }, true);
    expect(d.link).toBe(false);
    expect(d.reason).toMatch(/not confirmed/);
  });
  it('links a confirmed user with the flag', () => {
    expect(check({ email_confirmed_at: '2026-01-01T00:00:00Z' }, true)).toEqual({ link: true });
  });
  it('refuses when there is no user', () => {
    expect(check(null, true).link).toBe(false);
  });
});
