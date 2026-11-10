import { describe, expect, it } from 'vitest';
import { selectActiveOrganization } from './active-org';

const a = { organizationId: 'a' };
const b = { organizationId: 'b' };

describe('selectActiveOrganization', () => {
  it('defaults to the only membership', () => {
    expect(selectActiveOrganization([a], undefined)).toBe(a);
  });
  it('ignores a cookie for an organization the user is not in', () => {
    expect(selectActiveOrganization([a], 'zzz')).toBe(a);
    expect(selectActiveOrganization([a, b], 'zzz')).toBeNull();
  });
  it('honours a cookie matching a real membership', () => {
    expect(selectActiveOrganization([a, b], 'b')).toBe(b);
  });
  it('returns null with no memberships or an ambiguous choice', () => {
    expect(selectActiveOrganization([], 'a')).toBeNull();
    expect(selectActiveOrganization([a, b], null)).toBeNull();
  });
});
