import { describe, expect, it } from 'vitest';
import {
  checkParent,
  groupHoursByDay,
  groupSpaces,
  hoursTimes,
  overlapsExisting,
  parentChoices,
} from './logic';

const space = (
  id: string,
  name: string,
  parent: string | null = null,
  sort = 0,
  archived = false,
) => ({
  id,
  name,
  parent_space_id: parent,
  sort_order: sort,
  archived_at: archived ? '2026-01-01T00:00:00Z' : null,
});

describe('groupSpaces', () => {
  it('nests sub-spaces under their parent and sorts by order then name', () => {
    const groups = groupSpaces([
      space('c', 'Lane 2', 'p1'),
      space('p2', 'Gym', null, 2),
      space('p1', 'Pool', null, 1),
      space('b', 'Lane 1', 'p1'),
    ]);
    expect(groups.map((g) => g.space.name)).toEqual(['Pool', 'Gym']);
    expect(groups[0]?.children.map((c) => c.name)).toEqual(['Lane 1', 'Lane 2']);
    expect(groups[1]?.children).toEqual([]);
  });
  it('shows an orphaned sub-space at top level instead of dropping it', () => {
    const groups = groupSpaces([space('x', 'Orphan', 'missing')]);
    expect(groups).toHaveLength(1);
    expect(groups[0]?.space.name).toBe('Orphan');
  });
});

describe('parentChoices / checkParent', () => {
  it('offers only active top-level spaces, not the space itself', () => {
    const list = [
      space('a', 'A'),
      space('b', 'B', 'a'),
      space('c', 'C', null, 0, true),
      space('d', 'D'),
    ];
    expect(parentChoices(list, 'd').map((s) => s.id)).toEqual(['a']);
  });
  it('rejects a missing, nested, archived or self parent', () => {
    expect(checkParent(null).ok).toBe(false);
    expect(checkParent({ parent_space_id: 'x', archived_at: null }).ok).toBe(false);
    expect(checkParent({ parent_space_id: null, archived_at: '2026-01-01' }).ok).toBe(false);
    expect(checkParent({ parent_space_id: null, archived_at: null }, 'a', 'a').ok).toBe(false);
    expect(checkParent({ parent_space_id: null, archived_at: null }, 'a', 'b').ok).toBe(true);
  });
});

describe('groupHoursByDay', () => {
  const row = (id: string, day: number, o: string, c: string) => ({
    id,
    day_of_week: day,
    opens_at: o,
    closes_at: c,
    effective_from: null,
    effective_to: null,
  });
  it('returns seven days Monday first, rows ordered by opening time', () => {
    const days = groupHoursByDay([
      row('1', 7, '10:00:00', '14:00:00'),
      row('2', 1, '15:00:00', '21:00:00'),
      row('3', 1, '06:00:00', '12:00:00'),
    ]);
    expect(days.map((d) => d.label)).toEqual([
      'Monday',
      'Tuesday',
      'Wednesday',
      'Thursday',
      'Friday',
      'Saturday',
      'Sunday',
    ]);
    expect(days[0]?.rows.map((r) => r.id)).toEqual(['3', '2']);
    expect(days[6]?.rows.map((r) => r.id)).toEqual(['1']);
    expect(days[2]?.rows).toEqual([]);
  });
});

describe('hoursTimes', () => {
  it('uses 24:00 when closing at midnight', () => {
    expect(hoursTimes({ opens: '06:00', closes: null, closesAtMidnight: true })).toEqual({
      opens_at: '06:00',
      closes_at: '24:00',
    });
  });
  it('needs both times otherwise', () => {
    expect(hoursTimes({ opens: '06:00', closes: '21:00', closesAtMidnight: false })).toEqual({
      opens_at: '06:00',
      closes_at: '21:00',
    });
    expect(hoursTimes({ opens: '06:00', closes: null, closesAtMidnight: false })).toBeNull();
    expect(hoursTimes({ opens: null, closes: '21:00', closesAtMidnight: false })).toBeNull();
  });
});

describe('overlapsExisting', () => {
  const existing = [{ day_of_week: 1, opens_at: '09:00:00', closes_at: '12:00:00' }];
  it('detects overlap on the same weekday only', () => {
    expect(
      overlapsExisting(existing, { day_of_week: 1, opens_at: '11:00', closes_at: '14:00' }),
    ).toBe(true);
    expect(
      overlapsExisting(existing, { day_of_week: 2, opens_at: '11:00', closes_at: '14:00' }),
    ).toBe(false);
  });
  it('allows back-to-back intervals', () => {
    expect(
      overlapsExisting(existing, { day_of_week: 1, opens_at: '12:00', closes_at: '24:00' }),
    ).toBe(false);
  });
});
