import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { WORKFLOW_TRIGGER_TYPES } from './schemas';
import {
  EVENT_TYPE_OPTIONS,
  availableTaskActions,
  conditionFromForm,
  conditionToForm,
  describeAssignee,
  describeCondition,
  describeOffset,
  dueBucket,
  errorClass,
  eventTypeLabel,
  groupByDueBucket,
  localDateKey,
  myWorkFilter,
  offsetFromForm,
  offsetToForm,
  parseBoardFilters,
} from './logic';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';

describe('dueBucket', () => {
  const tz = 'America/New_York';

  it('puts no due date and a bad date in "none"', () => {
    expect(dueBucket(null, Date.now(), tz)).toBe('none');
    expect(dueBucket('not a date', Date.now(), tz)).toBe('none');
  });

  it('separates overdue, today and later by the location calendar day', () => {
    // 2026-11-10 15:00 New York (EST) = 20:00 UTC
    const now = Date.parse('2026-11-10T20:00:00Z');
    expect(dueBucket('2026-11-10T19:59:00Z', now, tz)).toBe('overdue');
    expect(dueBucket('2026-11-10T20:00:00Z', now, tz)).toBe('today');
    // 23:30 New York that evening = 04:30 UTC next day: still today there.
    expect(dueBucket('2026-11-11T04:30:00Z', now, tz)).toBe('today');
    // 00:30 New York tomorrow = 05:30 UTC: later.
    expect(dueBucket('2026-11-11T05:30:00Z', now, tz)).toBe('later');
  });

  it('depends on the zone: the same instant is today in one place and later in another', () => {
    const now = Date.parse('2026-11-10T20:00:00Z');
    const due = '2026-11-11T02:00:00Z';
    expect(dueBucket(due, now, 'America/New_York')).toBe('today'); // 9 PM on the 10th
    expect(dueBucket(due, now, 'Europe/London')).toBe('later'); // 2 AM on the 11th
  });

  it('handles the 25-hour day when clocks go back (2026-11-01, New York)', () => {
    // 00:30 EDT on Nov 1 = 04:30 UTC.
    const now = Date.parse('2026-11-01T04:30:00Z');
    // 23:30 EST (after the change) on Nov 1 = 04:30 UTC Nov 2: still Nov 1 locally.
    expect(dueBucket('2026-11-02T04:30:00Z', now, 'America/New_York')).toBe('today');
    // 00:30 EST on Nov 2 = 05:30 UTC: tomorrow.
    expect(dueBucket('2026-11-02T05:30:00Z', now, 'America/New_York')).toBe('later');
  });

  it('handles the 23-hour day when clocks go forward (2027-03-14, New York)', () => {
    // 01:00 EST on Mar 14 = 06:00 UTC.
    const now = Date.parse('2027-03-14T06:00:00Z');
    // 23:30 EDT Mar 14 = 03:30 UTC Mar 15.
    expect(dueBucket('2027-03-15T03:30:00Z', now, 'America/New_York')).toBe('today');
    // 00:30 EDT Mar 15 = 04:30 UTC.
    expect(dueBucket('2027-03-15T04:30:00Z', now, 'America/New_York')).toBe('later');
  });

  it('falls back to UTC for an unknown zone instead of throwing', () => {
    expect(localDateKey(Date.parse('2026-11-10T23:00:00Z'), 'Not/AZone')).toBe('2026-11-10');
  });
});

describe('groupByDueBucket', () => {
  it('orders groups overdue, today, later, none and drops empty ones', () => {
    const now = Date.parse('2026-11-10T20:00:00Z');
    const tasks = [
      { id: 'n', due: null },
      { id: 'l', due: '2026-11-20T12:00:00Z' },
      { id: 'o', due: '2026-11-09T12:00:00Z' },
      { id: 'o2', due: '2026-11-10T01:00:00Z' },
    ];
    const groups = groupByDueBucket(
      tasks,
      (t) => t.due,
      () => 'America/New_York',
      now,
    );
    expect(groups.map((g) => g.label)).toEqual(['Overdue', 'Later', 'No due date']);
    expect(groups[0]?.items.map((t) => t.id)).toEqual(['o', 'o2']);
  });

  it('uses each task location zone', () => {
    const now = Date.parse('2026-11-10T20:00:00Z');
    const due = '2026-11-11T02:00:00Z';
    const groups = groupByDueBucket(
      [
        { id: 'ny', tz: 'America/New_York' },
        { id: 'ldn', tz: 'Europe/London' },
      ],
      () => due,
      (t) => t.tz,
      now,
    );
    expect(groups.map((g) => [g.bucket, g.items[0]?.id])).toEqual([
      ['today', 'ny'],
      ['later', 'ldn'],
    ]);
  });
});

describe('myWorkFilter', () => {
  it('matches mine, unassigned and my job titles at their locations', () => {
    const f = myWorkFilter(A, [
      { job_title_id: B, location_id: null },
      { job_title_id: C, location_id: A },
    ]);
    expect(f).toBe(
      [
        `assigned_person_id.eq.${A}`,
        'and(assigned_person_id.is.null,assigned_job_title_id.is.null)',
        `and(assigned_person_id.is.null,assigned_job_title_id.eq.${B})`,
        `and(assigned_person_id.is.null,assigned_job_title_id.eq.${C},location_id.eq.${A})`,
      ].join(','),
    );
  });

  it('refuses a person id that is not a UUID and drops bad title ids', () => {
    expect(myWorkFilter('x,y', [])).toBeNull();
    const f = myWorkFilter(A, [{ job_title_id: 'a),b', location_id: null }]);
    expect(f).not.toContain('a),b');
  });
});

describe('availableTaskActions', () => {
  it('lets a view-only person do nothing', () => {
    expect(availableTaskActions('open', 'view')).toEqual({
      start: false,
      complete: false,
      reopen: false,
      comment: false,
      assign: false,
      cancel: false,
    });
  });
  it('lets an editor start, finish, comment and reopen done tasks', () => {
    expect(availableTaskActions('open', 'edit')).toMatchObject({ start: true, complete: true });
    expect(availableTaskActions('in_progress', 'edit')).toMatchObject({
      start: false,
      complete: true,
    });
    expect(availableTaskActions('done', 'edit')).toMatchObject({ reopen: true, complete: false });
    expect(availableTaskActions('cancelled', 'edit').reopen).toBe(false);
    expect(availableTaskActions('open', 'edit').assign).toBe(false);
  });
  it('lets a manager also assign, cancel and reopen cancelled tasks', () => {
    expect(availableTaskActions('open', 'admin')).toMatchObject({ assign: true, cancel: true });
    expect(availableTaskActions('cancelled', 'admin').reopen).toBe(true);
    expect(availableTaskActions('done', 'admin')).toMatchObject({ assign: false, cancel: false });
  });
});

describe('event types', () => {
  it('lists exactly the types the database allows', () => {
    const sql = readFileSync('supabase/migrations/20261112000300_tasks_and_workflows.sql', 'utf8');
    const body =
      /workflow_trigger_types\(\)[\s\S]*?select array\[([\s\S]*?)\]/.exec(sql)?.[1] ?? '';
    const types = [...body.matchAll(/'([a-z_.]+)'/g)].map((m) => m[1]);
    expect(types.length).toBeGreaterThan(5);
    expect(EVENT_TYPE_OPTIONS.map((o) => o.value).sort()).toEqual([...types].sort());
    expect([...WORKFLOW_TRIGGER_TYPES].sort()).toEqual([...types].sort());
  });
  it('has a plain label for each and falls back to the raw type', () => {
    for (const o of EVENT_TYPE_OPTIONS) expect(o.label).not.toMatch(/\./);
    expect(eventTypeLabel('booking.confirmed')).toBe('A booking is confirmed');
    expect(eventTypeLabel('x.y')).toBe('x.y');
  });
});

describe('condition form', () => {
  const row = (field: string, op: string, type: string, value: string) => ({
    field,
    op,
    type,
    value,
  });

  it('gives {} for no rows and skips blank rows', () => {
    expect(conditionFromForm([])).toEqual({ ok: true, condition: {} });
    expect(conditionFromForm([row('', 'eq', 'text', '  ')])).toEqual({ ok: true, condition: {} });
  });

  it('builds the stored shape for "is" and "is one of"', () => {
    const r = conditionFromForm([
      row('urgency', 'eq', 'text', ' critical '),
      row('priority', 'in', 'text', 'high, urgent ,'),
      row('attempts', 'eq', 'number', '3'),
      row('requires_acknowledgment', 'eq', 'boolean', 'Yes'),
    ]);
    expect(r).toEqual({
      ok: true,
      condition: {
        all: [
          { field: 'urgency', op: 'eq', value: 'critical' },
          { field: 'priority', op: 'in', value: ['high', 'urgent'] },
          { field: 'attempts', op: 'eq', value: 3 },
          { field: 'requires_acknowledgment', op: 'eq', value: true },
        ],
      },
    });
  });

  it('refuses what the database would refuse', () => {
    expect(conditionFromForm([row('Bad Field', 'eq', 'text', 'x')]).ok).toBe(false);
    expect(conditionFromForm([row('a', 'eq', 'text', '')]).ok).toBe(false);
    expect(conditionFromForm([row('a', 'eq', 'number', 'abc')]).ok).toBe(false);
    expect(conditionFromForm([row('a', 'eq', 'boolean', 'maybe')]).ok).toBe(false);
    expect(conditionFromForm([row('a', 'eq', 'text', 'x'.repeat(201))]).ok).toBe(false);
    expect(conditionFromForm([row('a', 'in', 'text', ',,')]).ok).toBe(false);
    expect(conditionFromForm([row('a', 'in', 'text', Array(51).fill('x').join(','))]).ok).toBe(
      false,
    );
    expect(conditionFromForm([row('a', 'like', 'text', 'x')]).ok).toBe(false);
    expect(
      conditionFromForm(Array.from({ length: 11 }, (_, i) => row(`f${i}`, 'eq', 'text', 'x'))).ok,
    ).toBe(false);
  });

  it('round-trips a stored condition back to the same rows', () => {
    const stored = {
      all: [
        { field: 'space_id', op: 'eq', value: 'abc' },
        { field: 'priority', op: 'in', value: ['high', 'urgent'] },
        { field: 'count', op: 'in', value: [1, 2] },
      ],
    };
    const rows = conditionToForm(stored);
    expect(rows).toEqual([
      row('space_id', 'eq', 'text', 'abc'),
      row('priority', 'in', 'text', 'high, urgent'),
      row('count', 'in', 'number', '1, 2'),
    ]);
    expect(conditionFromForm(rows ?? [])).toEqual({ ok: true, condition: stored });
    expect(conditionToForm({})).toEqual([]);
  });

  it('returns null for a condition the editor cannot show without changing it', () => {
    expect(
      conditionToForm({ all: [{ field: 'a', op: 'in', value: ['x', 1] }] }), // mixed types
    ).toBeNull();
    expect(conditionToForm({ all: [{ field: 'a', op: 'in', value: ['a,b'] }] })).toBeNull();
    expect(conditionToForm({ all: [{ field: 'a', op: 'eq', value: '' }] })).toBeNull();
    expect(conditionToForm({ all: [{ field: 'a', op: 'eq', value: ' x' }] })).toBeNull();
    expect(conditionToForm({ any: [] })).toBeNull();
    expect(conditionToForm(null)).toBeNull();
    expect(conditionToForm([])).toBeNull();
  });

  it('describes a condition in a sentence', () => {
    expect(describeCondition({})).toBe('Every time it happens');
    expect(
      describeCondition({
        all: [
          { field: 'urgency', op: 'eq', value: 'critical' },
          { field: 'kind', op: 'in', value: ['a', 'b'] },
        ],
      }),
    ).toBe('urgency is critical and kind is one of a, b');
  });
});

describe('due offsets', () => {
  it('blank means no due time', () => {
    expect(offsetFromForm({ amount: ' ', unit: 'hours', direction: 'before' })).toEqual({
      ok: true,
      minutes: null,
    });
  });
  it('converts to signed minutes', () => {
    expect(offsetFromForm({ amount: '2', unit: 'hours', direction: 'before' })).toEqual({
      ok: true,
      minutes: -120,
    });
    expect(offsetFromForm({ amount: '1', unit: 'days', direction: 'after' })).toEqual({
      ok: true,
      minutes: 1440,
    });
    expect(offsetFromForm({ amount: '0', unit: 'minutes', direction: 'before' })).toEqual({
      ok: true,
      minutes: 0,
    });
  });
  it('refuses nonsense and anything past 365 days', () => {
    expect(offsetFromForm({ amount: '-2', unit: 'hours', direction: 'before' }).ok).toBe(false);
    expect(offsetFromForm({ amount: '1.5', unit: 'hours', direction: 'before' }).ok).toBe(false);
    expect(offsetFromForm({ amount: '2', unit: 'weeks', direction: 'before' }).ok).toBe(false);
    expect(offsetFromForm({ amount: '2', unit: 'hours', direction: 'around' }).ok).toBe(false);
    expect(offsetFromForm({ amount: '366', unit: 'days', direction: 'after' }).ok).toBe(false);
    expect(offsetFromForm({ amount: '365', unit: 'days', direction: 'after' }).ok).toBe(true);
  });
  it('round-trips through the form and reads plainly', () => {
    for (const m of [null, 0, -120, 1440, -90, 525600, -525600]) {
      const form = offsetToForm(m);
      expect(offsetFromForm(form)).toEqual({ ok: true, minutes: m });
    }
    expect(describeOffset(-120)).toBe('Due 2 hours before the event time');
    expect(describeOffset(1440)).toBe('Due 1 day after the event time');
    expect(describeOffset(0)).toBe('Due at the event time');
    expect(describeOffset(null)).toBe('No due time');
  });
});

describe('describeAssignee', () => {
  it('reads plainly', () => {
    expect(describeAssignee('Sam Lee', null, 'open')).toBe('Sam Lee');
    expect(describeAssignee(null, 'Lifeguard', 'open')).toBe('Anyone with the job title Lifeguard');
    expect(describeAssignee(null, null, 'open')).toBe('Nobody yet');
    expect(describeAssignee(null, null, 'done')).toBe('Nobody');
  });
});

describe('parseBoardFilters', () => {
  it('defaults to unfinished tasks and ignores junk', () => {
    expect(parseBoardFilters({})).toEqual({
      status: 'active',
      assigneeSearch: '',
      assignee: 'any',
      jobTitleId: null,
      overdue: false,
    });
    expect(
      parseBoardFilters({ status: 'drop table', title: 'x', overdue: '1', assignee: 'nobody' }),
    ).toMatchObject({ status: 'active', jobTitleId: null, overdue: true, assignee: 'nobody' });
  });
  it('reads a status, a job title and a name search', () => {
    expect(parseBoardFilters({ status: 'done', title: A, aq: ' sam ' })).toMatchObject({
      status: 'done',
      jobTitleId: A,
      assignee: 'search',
      assigneeSearch: 'sam',
    });
  });
});

describe('errorClass', () => {
  it('keeps a short class and drops ids and details', () => {
    expect(errorClass('TypeError: cannot read x of person Sam')).toBe('TypeError');
    expect(errorClass(`handler failed for ${A} 12345678`)).toBe('handler failed for');
    expect(errorClass(null)).toBe('Unknown error');
    expect(errorClass('')).toBe('Unknown error');
    expect(errorClass(': only detail')).toBe('Unknown error');
    expect(errorClass('x'.repeat(200)).length).toBe(60);
  });
});
