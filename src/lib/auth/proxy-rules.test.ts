import { describe, expect, it } from 'vitest';
import { proxyRedirect } from './proxy-rules';

describe('proxyRedirect', () => {
  it('sends signed-out users from /app to sign-in with next', () => {
    expect(proxyRedirect('/app', '', false)).toBe('/sign-in?next=%2Fapp');
    expect(proxyRedirect('/app/tasks', '?a=1', false)).toBe('/sign-in?next=%2Fapp%2Ftasks%3Fa%3D1');
  });
  it('sends signed-in users away from sign-in', () => {
    expect(proxyRedirect('/sign-in', '', true)).toBe('/app');
  });
  it('leaves everything else alone', () => {
    expect(proxyRedirect('/application', '', false)).toBeNull();
    expect(proxyRedirect('/sign-in', '', false)).toBeNull();
    expect(proxyRedirect('/reset-password', '', true)).toBeNull();
    expect(proxyRedirect('/app', '', true)).toBeNull();
  });
});
