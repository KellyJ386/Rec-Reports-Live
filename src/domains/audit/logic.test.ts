import { describe, expect, it } from 'vitest';
import { actionLabel, parseAuditQuery, tableLabel } from './logic';

const ORG = '00000000-0000-4000-8000-000000000001';
const LOC = '00000000-0000-4000-8000-000000000002';

describe('parseAuditQuery', () => {
  it('reads table, action and location', () => {
    const r = parseAuditQuery(
      { table: 'people', action: 'update', location: LOC, page: '2' },
      ORG,
      'UTC',
    );
    expect(r.page).toBe(2);
    expect(r.problem).toBeNull();
    expect(r.filter).toEqual({
      organization_id: ORG,
      location_id: LOC,
      table_name: 'people',
      action: 'update',
    });
  });

  it('reads the date range in the organization time zone, including the whole end day', () => {
    const r = parseAuditQuery({ from: '2026-01-15', to: '2026-01-15' }, ORG, 'America/New_York');
    expect(r.filter?.since).toBe('2026-01-15T05:00:00.000Z');
    expect(r.filter?.until).toBe('2026-01-16T05:00:00.000Z');
  });

  it('reports a plain problem for bad dates or an end before the start', () => {
    expect(parseAuditQuery({ from: 'yesterday' }, ORG, 'UTC').problem).toMatch(/year-month-day/);
    const r = parseAuditQuery({ from: '2026-02-10', to: '2026-02-01' }, ORG, 'UTC');
    expect(r.filter).toBeNull();
    expect(r.problem).toMatch(/end date is before/);
  });

  it('rejects an action or table name outside the allowed shape', () => {
    expect(parseAuditQuery({ action: 'truncate' }, ORG, 'UTC').filter).toBeNull();
    expect(parseAuditQuery({ table: 'x; drop table' }, ORG, 'UTC').filter).toBeNull();
    expect(parseAuditQuery({ location: 'not-a-uuid' }, ORG, 'UTC').filter).toBeNull();
  });

  it('has no filters by default', () => {
    expect(parseAuditQuery({}, ORG, 'UTC').filter).toEqual({ organization_id: ORG });
  });
});

describe('labels', () => {
  it('uses plain words', () => {
    expect(actionLabel('insert')).toBe('Added');
    expect(actionLabel('delete')).toBe('Removed');
    expect(tableLabel('role_assignments')).toBe('Role assignments');
    expect(tableLabel('mystery')).toBe('mystery');
  });
});
