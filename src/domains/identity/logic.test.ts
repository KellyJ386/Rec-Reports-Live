import { describe, expect, it } from 'vitest';
import {
  assignableRoles,
  assignmentRank,
  isLastActiveAssignment,
  levelExceeds,
  displayName,
  effectiveLevelKey,
  scopeProblem,
} from './logic';

const LOC_A = 'loc-a';

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

describe('isLastActiveAssignment', () => {
  const role = { archived_at: null };
  const first = { id: 'a', location_id: 'loc-a', role };
  const rows = [first, { id: 'b', location_id: 'loc-b', role }];
  it('is false while another active assignment remains', () => {
    expect(isLastActiveAssignment(rows, 'a', new Set())).toBe(false);
  });
  it('is true for the only assignment', () => {
    expect(isLastActiveAssignment([first], 'a', new Set())).toBe(true);
  });
  it('ignores assignments on archived roles or archived locations', () => {
    expect(isLastActiveAssignment(rows, 'a', new Set(['loc-b']))).toBe(true);
    expect(
      isLastActiveAssignment(
        [first, { id: 'c', location_id: null, role: { archived_at: '2026-01-01' } }],
        'a',
        new Set(),
      ),
    ).toBe(true);
  });
  it('is false when the assignment itself is not active (nothing left to lose)', () => {
    expect(isLastActiveAssignment(rows, 'a', new Set(['loc-a', 'loc-b']))).toBe(false);
  });
});

describe('effectiveLevelKey', () => {
  it('separates organization scope from locations', () => {
    expect(effectiveLevelKey(null, 'tasks')).toBe('org|tasks');
    expect(effectiveLevelKey('loc-a', 'tasks')).toBe('loc-a|tasks');
  });
});

describe('levelExceeds', () => {
  it('orders none < view < edit < admin', () => {
    expect(levelExceeds('admin', 'edit')).toBe(true);
    expect(levelExceeds('edit', 'edit')).toBe(false);
    expect(levelExceeds('view', 'admin')).toBe(false);
    expect(levelExceeds('view', 'none')).toBe(true);
  });
});
