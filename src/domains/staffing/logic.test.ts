import { describe, expect, it } from 'vitest';
import {
  assignRuleOf,
  canOfferOverride,
  dateRangeText,
  formatShiftRange,
  groupShiftsByDay,
  localDateOf,
  qualificationState,
  refusedText,
  shortShiftStart,
  weekDates,
  weekStartOf,
} from './logic';

describe('assignRuleOf', () => {
  it('reads the rule from DETAIL, then from the message, only for 23514', () => {
    expect(assignRuleOf({ code: '23514', message: 'x', details: 'time_off' })).toBe('time_off');
    expect(
      assignRuleOf({ code: '23514', message: 'that person already has a shift at that time' }),
    ).toBe('overlap');
    expect(
      assignRuleOf({ code: '23514', message: 'that person is missing a required qualification' }),
    ).toBe('qualification');
    expect(
      assignRuleOf({ code: '23514', message: 'that person cannot work at this location' }),
    ).toBe('not_member');
    expect(assignRuleOf({ code: '22023', message: 'x', details: 'time_off' })).toBeNull();
    expect(assignRuleOf({ code: '23514', message: 'x', details: 'stale' })).toBeNull();
  });
});

describe('canOfferOverride', () => {
  it('offers "assign anyway" only to a schedule admin, and only for time off and qualification', () => {
    expect(canOfferOverride('time_off', true)).toBe(true);
    expect(canOfferOverride('qualification', true)).toBe(true);
    expect(canOfferOverride('time_off', false)).toBe(false);
    expect(canOfferOverride('overlap', true)).toBe(false);
    expect(canOfferOverride('not_member', true)).toBe(false);
    expect(canOfferOverride(null, true)).toBe(false);
  });
});

describe('time zones', () => {
  it('names the local day in the location zone, not UTC', () => {
    // 02:30 UTC on Nov 17 is still Nov 16 in New York (UTC-5) and already Nov 17 in Sydney.
    expect(localDateOf('2026-11-17T02:30:00Z', 'America/New_York')).toBe('2026-11-16');
    expect(localDateOf('2026-11-17T02:30:00Z', 'Australia/Sydney')).toBe('2026-11-17');
  });

  it('always names the zone when it shows a range', () => {
    const text = formatShiftRange(
      '2026-11-16T14:00:00Z',
      '2026-11-16T22:00:00Z',
      'America/New_York',
    );
    expect(text).toBe('Mon, Nov 16, 9:00 AM to 5:00 PM EST (America/New_York)');
  });

  it('names the end day when a shift crosses midnight', () => {
    const text = formatShiftRange(
      '2026-11-17T03:00:00Z',
      '2026-11-17T09:00:00Z',
      'America/New_York',
    );
    expect(text).toContain('Mon, Nov 16, 10:00 PM to Tue, Nov 17, 4:00 AM');
    expect(text.endsWith('(America/New_York)')).toBe(true);
  });

  it('gives a short start for titles', () => {
    expect(shortShiftStart('2026-11-16T14:00:00Z', 'America/New_York')).toBe(
      'Mon, Nov 16, 9:00 AM',
    );
  });
});

describe('weeks', () => {
  it('lists seven dates and finds the week start for any week_starts_on', () => {
    expect(weekDates('2026-11-15')).toHaveLength(7);
    expect(weekDates('2026-11-15')[6]).toBe('2026-11-21');
    expect(weekStartOf('2026-11-18', 0)).toBe('2026-11-15'); // Sunday start
    expect(weekStartOf('2026-11-18', 1)).toBe('2026-11-16'); // Monday start
    expect(weekStartOf('2026-11-16', 1)).toBe('2026-11-16');
    expect(weekStartOf('bad', 1)).toBeNull();
  });

  it('groups shifts by the local day they start on', () => {
    const shifts = [
      { id: 'b', starts_at: '2026-11-16T20:00:00Z', ends_at: '2026-11-17T02:00:00Z' },
      { id: 'a', starts_at: '2026-11-16T14:00:00Z', ends_at: '2026-11-16T18:00:00Z' },
      { id: 'c', starts_at: '2026-11-17T01:30:00Z', ends_at: '2026-11-17T05:00:00Z' }, // Nov 16, 8:30 PM EST
      { id: 'out', starts_at: '2026-12-30T14:00:00Z', ends_at: '2026-12-30T18:00:00Z' },
    ];
    const days = groupShiftsByDay(shifts, 'America/New_York', '2026-11-16');
    expect(days).toHaveLength(7);
    expect(days[0]?.shifts.map((s) => s.id)).toEqual(['a', 'b', 'c']);
    expect(days.flatMap((d) => d.shifts).some((s) => s.id === 'out')).toBe(false);
  });
});

describe('wording', () => {
  it('says why a template item was left open', () => {
    expect(refusedText(null)).toBe('Assigned.');
    expect(refusedText('time_off')).toContain('approved time off');
    expect(refusedText('weird')).toBe('Left open.');
    expect(refusedText('time_change')).toContain('clock change');
    expect(refusedText('time_change')).toMatch(/^Not added/);
    expect(refusedText('position_unavailable')).toMatch(/^Not added/);
  });
  it('writes a date range', () => {
    expect(dateRangeText('2026-11-16', '2026-11-16')).toBe('Mon, Nov 16');
    expect(dateRangeText('2026-11-16', '2026-11-18')).toBe('Mon, Nov 16 to Wed, Nov 18');
  });
  it('judges a qualification on a date', () => {
    expect(qualificationState({ valid_from: null, expires_on: null }, '2026-11-16')).toBe('valid');
    expect(qualificationState({ valid_from: null, expires_on: '2026-11-15' }, '2026-11-16')).toBe(
      'expired',
    );
    expect(qualificationState({ valid_from: null, expires_on: '2026-11-16' }, '2026-11-16')).toBe(
      'valid',
    );
    expect(qualificationState({ valid_from: '2026-11-17', expires_on: null }, '2026-11-16')).toBe(
      'not_yet',
    );
  });
});
