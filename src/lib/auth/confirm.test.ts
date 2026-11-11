import { describe, expect, it } from 'vitest';
import { describeConfirm, parseConfirmRequest, sessionSwitch } from './confirm';

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

describe('describeConfirm', () => {
  it('says what each kind of link does and never names an account', () => {
    const recovery = describeConfirm({ kind: 'otp', tokenHash: 't', type: 'recovery', next: '/x' });
    expect(recovery.heading).toMatch(/password/i);
    const invite = describeConfirm({ kind: 'otp', tokenHash: 't', type: 'invite', next: '/x' });
    expect(invite.button).toBe('Accept invite');
    const code = describeConfirm({ kind: 'code', code: 'c', next: '/x' });
    for (const d of [recovery, invite, code]) {
      expect(d.lines.join(' ')).toMatch(/account it was sent to|created for you/);
      expect(d.lines.join(' ')).toMatch(/cannot show which account/);
      expect(d.lines.join(' ')).not.toMatch(/@/);
    }
  });
});

describe('sessionSwitch', () => {
  it('is a switch only when a different person was signed in', () => {
    expect(sessionSwitch('a', 'b')).toBe('switched');
    expect(sessionSwitch('a', 'a')).toBe('none');
    expect(sessionSwitch(null, 'b')).toBe('none');
    expect(sessionSwitch(undefined, 'b')).toBe('none');
    expect(sessionSwitch('a', null)).toBe('none');
  });
});
