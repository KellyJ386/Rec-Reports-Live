import { describe, expect, it } from 'vitest';
import { RECENT_AUTH_SECONDS, hasRecentAuthentication } from './recent-auth';

const NOW = 1_800_000_000;

describe('hasRecentAuthentication', () => {
  it('accepts a fresh recovery, otp, magiclink or password entry', () => {
    for (const method of ['recovery', 'otp', 'magiclink', 'password']) {
      expect(hasRecentAuthentication({ amr: [{ method, timestamp: NOW - 30 }] }, NOW), method).toBe(
        true,
      );
    }
  });
  it('rejects an old entry, at the boundary and beyond', () => {
    expect(
      hasRecentAuthentication(
        { amr: [{ method: 'otp', timestamp: NOW - RECENT_AUTH_SECONDS }] },
        NOW,
      ),
    ).toBe(true);
    expect(
      hasRecentAuthentication(
        { amr: [{ method: 'otp', timestamp: NOW - RECENT_AUTH_SECONDS - 1 }] },
        NOW,
      ),
    ).toBe(false);
  });
  it('rejects timestamps far in the future', () => {
    expect(hasRecentAuthentication({ amr: [{ method: 'otp', timestamp: NOW + 3600 }] }, NOW)).toBe(
      false,
    );
  });
  it('rejects other methods such as oauth or totp', () => {
    expect(hasRecentAuthentication({ amr: [{ method: 'totp', timestamp: NOW }] }, NOW)).toBe(false);
  });
  it('accepts when any one entry qualifies', () => {
    expect(
      hasRecentAuthentication(
        {
          amr: [
            { method: 'password', timestamp: NOW - 99999 },
            { method: 'recovery', timestamp: NOW - 5 },
          ],
        },
        NOW,
      ),
    ).toBe(true);
  });
  it('rejects missing or malformed claims', () => {
    for (const claims of [
      null,
      undefined,
      {},
      { amr: 'otp' },
      { amr: [{ method: 'otp' }] },
      { amr: [] },
    ]) {
      expect(hasRecentAuthentication(claims, NOW), JSON.stringify(claims)).toBe(false);
    }
  });
});
