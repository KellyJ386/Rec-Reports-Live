import { describe, expect, it } from 'vitest';
import { buildSessionContext, type ContextRows } from './context';

const O1 = '10000000-0000-4000-8000-000000000001';
const O2 = '10000000-0000-4000-8000-000000000002';
const O3 = '10000000-0000-4000-8000-000000000003';
const ME1 = '20000000-0000-4000-8000-000000000001';
const ME2 = '20000000-0000-4000-8000-000000000002';
const OTHER = '20000000-0000-4000-8000-000000000009';
const ADMIN = '30000000-0000-4000-8000-000000000001';
const STAFF = '30000000-0000-4000-8000-000000000002';
const OLD = '30000000-0000-4000-8000-000000000003';
const L1 = '40000000-0000-4000-8000-000000000001';
const L2 = '40000000-0000-4000-8000-000000000002';

const base: ContextRows = {
  user: { id: 'u', email: 'a@b.co' },
  isPlatformAdmin: false,
  memberOrgIds: [O1, O2],
  organizations: [
    { id: O2, name: 'Zed Rec' },
    { id: O1, name: 'Alpha Rec' },
    { id: O3, name: 'Not mine' },
  ],
  accounts: [
    { organization_id: O1, person_id: ME1 },
    { organization_id: O2, person_id: ME2 },
  ],
  assignments: [
    { organization_id: O1, person_id: ME1, role_id: ADMIN, location_id: null },
    { organization_id: O1, person_id: ME1, role_id: STAFF, location_id: L1 },
    { organization_id: O1, person_id: ME1, role_id: OLD, location_id: L1 },
    { organization_id: O1, person_id: ME1, role_id: STAFF, location_id: L2 },
    { organization_id: O1, person_id: OTHER, role_id: ADMIN, location_id: null },
    { organization_id: O2, person_id: ME2, role_id: STAFF, location_id: L1 },
    { organization_id: O3, person_id: ME1, role_id: ADMIN, location_id: null },
  ],
  roles: [
    { id: ADMIN, key: 'admin', name: 'Admin', rank: 80, archived_at: null },
    { id: STAFF, key: 'staff', name: 'Staff', rank: 10, archived_at: null },
    { id: OLD, key: 'old', name: 'Old', rank: 5, archived_at: '2026-01-01' },
  ],
  locations: [
    { id: L1, name: 'Arena', archived_at: null },
    { id: L2, name: 'Closed rink', archived_at: '2026-01-01' },
  ],
};

describe('buildSessionContext', () => {
  const ctx = buildSessionContext(base);

  it('keeps only organizations the database listed as membership, sorted by name', () => {
    expect(ctx.memberships.map((m) => m.organizationName)).toEqual(['Alpha Rec', 'Zed Rec']);
    expect(ctx.memberships[0]?.personId).toBe(ME1);
  });
  it('keeps only own, non-archived assignments in member organizations', () => {
    expect(ctx.roleAssignments).toHaveLength(3);
    expect(ctx.roleAssignments.some((a) => a.personId === OTHER)).toBe(false);
    expect(ctx.roleAssignments.some((a) => a.organizationId === O3)).toBe(false);
    expect(ctx.roleAssignments.some((a) => a.roleKey === 'old')).toBe(false);
    expect(ctx.roleAssignments.some((a) => a.locationId === L2)).toBe(false);
  });
  it('adds 10 to the rank at organization scope and sorts highest first', () => {
    expect(ctx.roleAssignments[0]).toMatchObject({ roleKey: 'admin', rank: 90, locationId: null });
    expect(ctx.roleAssignments[1]?.rank).toBe(10);
  });
  it('grants nothing from an account without a database-listed membership', () => {
    const none = buildSessionContext({ ...base, memberOrgIds: [] });
    expect(none.memberships).toEqual([]);
    expect(none.roleAssignments).toEqual([]);
  });
  it('allows a platform admin member with no account (personId null)', () => {
    const pa = buildSessionContext({
      ...base,
      isPlatformAdmin: true,
      memberOrgIds: [O3],
      accounts: [],
    });
    expect(pa.isPlatformAdmin).toBe(true);
    expect(pa.memberships).toEqual([
      { organizationId: O3, organizationName: 'Not mine', personId: null },
    ]);
  });
});
