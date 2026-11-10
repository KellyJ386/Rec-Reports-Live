import { describe, expect, it } from 'vitest';
import { parseConfirmRequest } from './confirm';

describe('parseConfirmRequest', () => {
  it('reads a token_hash link', () => {
    expect(
      parseConfirmRequest({ token_hash: 'abc', type: 'recovery', next: '/reset-password' }),
    ).toEqual({ kind: 'otp', tokenHash: 'abc', type: 'recovery', next: '/reset-password' });
  });
  it('reads a PKCE code and defaults next', () => {
    expect(parseConfirmRequest({ code: 'xyz' })).toEqual({
      kind: 'code',
      code: 'xyz',
      next: '/reset-password',
    });
  });
  it('rejects an unknown type and falls back to a code if there is one', () => {
    expect(parseConfirmRequest({ token_hash: 'abc', type: 'magiclink' })).toBeNull();
    expect(parseConfirmRequest({ token_hash: 'abc', type: 'nope', code: 'c' })?.kind).toBe('code');
  });
  it('replaces an unsafe next', () => {
    for (const next of ['https://evil.example', '//evil.example', '/\\evil']) {
      expect(parseConfirmRequest({ code: 'c', next })?.next, next).toBe('/reset-password');
    }
  });
  it('returns null for nothing, blanks and oversized tokens; uses the first array value', () => {
    expect(parseConfirmRequest({})).toBeNull();
    expect(parseConfirmRequest({ code: '  ' })).toBeNull();
    expect(parseConfirmRequest({ code: 'x'.repeat(513) })).toBeNull();
    expect(parseConfirmRequest({ code: ['a', 'b'] })).toMatchObject({ code: 'a' });
  });
});
