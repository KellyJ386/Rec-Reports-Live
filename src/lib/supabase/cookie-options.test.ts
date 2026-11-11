import { describe, expect, it } from 'vitest';
import { authCookieOptions } from './cookie-options';

describe('authCookieOptions', () => {
  it('is httpOnly, lax and secure in production', () => {
    expect(authCookieOptions(true)).toEqual({
      httpOnly: true,
      secure: true,
      sameSite: 'lax',
      path: '/',
    });
  });
  it('is httpOnly but not secure outside production (plain http on localhost)', () => {
    expect(authCookieOptions(false)).toMatchObject({ httpOnly: true, secure: false });
  });
});
