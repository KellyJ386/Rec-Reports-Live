import { describe, expect, it } from 'vitest';
import {
  assignableRoles,
  assignmentRank,
  computeEffectiveLevel,
  displayName,
  scopeProblem,
  type PermissionLevel,
} from './logic';

const LOC_A = 'loc-a';
const LOC_B = 'loc-b';
const defaults = {
  manager: { tasks: 'admin', people_roles: 'edit', audit_log: 'none' },
  staff: { tasks: 'edit', people_roles: 'none' },
  admin: { audit_log: 'admin', tasks: 'admin' },
} as const satisfies Record<string, Record<string, PermissionLevel>>;

describe('computeEffectiveLevel', () => {
  it('is none without an assignment covering the scope', () => {
    const data = {
      assignments: [{ roleId: 'manager', locationId: LOC_A }],
      overrides: [],
      defaults,
    };
    expect(computeEffectiveLevel(data, LOC_B, 'tasks')).toBe('none');
    // A location assignment does not cover organization scope.
    expect(computeEffectiveLevel(data, null, 'tasks')).toBe('none');
    expect(computeEffectiveLevel({ ...data, assignments: [] }, LOC_A, 'tasks')).toBe('none');
  });

  it('uses the highest default among covering roles', () => {
    const data = {
      assignments: [
        { roleId: 'staff', locationId: LOC_A },
        { roleId: 'manager', locationId: LOC_A },
        { roleId: 'manager', locationId: LOC_B },
      ],
      overrides: [],
      defaults,
    };
    expect(computeEffectiveLevel(data, LOC_A, 'tasks')).toBe('admin');
    expect(computeEffectiveLevel(data, LOC_A, 'people_roles')).toBe('edit');
    expect(computeEffectiveLevel(data, LOC_A, 'reports')).toBe('none');
  });

  it('an organization scoped assignment covers every location and organization scope', () => {
    const data = { assignments: [{ roleId: 'admin', locationId: null }], overrides: [], defaults };
    expect(computeEffectiveLevel(data, LOC_B, 'audit_log')).toBe('admin');
    expect(computeEffectiveLevel(data, null, 'audit_log')).toBe('admin');
  });

  it('prefers a location override, then an organization-wide override, over defaults, and can lower', () => {
    const base = { assignments: [{ roleId: 'manager', locationId: LOC_A }], defaults };
    const lowered = {
      ...base,
      overrides: [{ moduleKey: 'tasks', locationId: LOC_A, level: 'view' as const }],
    };
    expect(computeEffectiveLevel(lowered, LOC_A, 'tasks')).toBe('view');

    const orgWide = {
      ...base,
      overrides: [{ moduleKey: 'tasks', locationId: null, level: 'none' as const }],
    };
    expect(computeEffectiveLevel(orgWide, LOC_A, 'tasks')).toBe('none');

    const both = {
      ...base,
      overrides: [
        { moduleKey: 'tasks', locationId: null, level: 'none' as const },
        { moduleKey: 'tasks', locationId: LOC_A, level: 'edit' as const },
      ],
    };
    expect(computeEffectiveLevel(both, LOC_A, 'tasks')).toBe('edit');
  });

  it('an override alone grants nothing', () => {
    const data = {
      assignments: [],
      overrides: [{ moduleKey: 'tasks', locationId: LOC_A, level: 'admin' as const }],
      defaults,
    };
    expect(computeEffectiveLevel(data, LOC_A, 'tasks')).toBe('none');
  });
});

describe('role helpers', () => {
  it('adds 10 to the rank at organization scope', () => {
    expect(assignmentRank(80, null)).toBe(90);
    expect(assignmentRank(80, LOC_A)).toBe(80);
  });
  it('drops super_admin and archived roles from the picker', () => {
    const roles = [
      { key: 'super_admin', archived_at: null },
      { key: 'admin', archived_at: null },
      { key: 'x', archived_at: '2026-01-01' },
    ];
    expect(assignableRoles(roles).map((r) => r.key)).toEqual(['admin']);
  });
  it('only admin may be organization scoped', () => {
    expect(scopeProblem('admin', true, null)).toBeNull();
    expect(scopeProblem('manager', true, null)).not.toBeNull();
    expect(scopeProblem('admin', false, null)).not.toBeNull();
    expect(scopeProblem('manager', true, LOC_A)).toBeNull();
  });
  it('shows the preferred name first', () => {
    expect(displayName({ first_name: 'Robert', last_name: 'Lee', preferred_name: 'Bob' })).toBe(
      'Bob Lee',
    );
    expect(displayName({ first_name: 'Robert', last_name: 'Lee', preferred_name: ' ' })).toBe(
      'Robert Lee',
    );
  });
});
