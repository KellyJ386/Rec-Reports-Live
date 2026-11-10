import { describe, expect, it } from 'vitest';
import {
  addDays,
  formatClock,
  formatHoursRange,
  formatInZone,
  listTimeZones,
  toTimeInput,
  weekdayLabel,
  zonedLocalToUtc,
} from './time';

describe('hours formatting', () => {
  it('formats clock times', () => {
    expect(formatClock('00:00:00')).toBe('12:00 AM');
    expect(formatClock('09:30:00')).toBe('9:30 AM');
    expect(formatClock('12:00:00')).toBe('12:00 PM');
    expect(formatClock('21:05')).toBe('9:05 PM');
    expect(formatClock('24:00:00')).toBe('midnight (end of day)');
  });
  it('formats a range and a time input value', () => {
    expect(formatHoursRange('06:00:00', '24:00:00')).toBe('6:00 AM to midnight (end of day)');
    expect(toTimeInput('06:00:00')).toBe('06:00');
  });
  it('names ISO weekdays, 1 = Monday', () => {
    expect(weekdayLabel(1)).toBe('Monday');
    expect(weekdayLabel(7)).toBe('Sunday');
  });
});

describe('time zones', () => {
  it('lists UTC first and only Area/Location names after it', () => {
    const zones = listTimeZones();
    expect(zones[0]).toBe('UTC');
    expect(zones).toContain('America/New_York');
    expect(zones.slice(1).every((z) => z.includes('/'))).toBe(true);
  });
  it('converts local wall time to UTC across DST', () => {
    expect(zonedLocalToUtc('2026-01-15T09:00', 'America/New_York')).toBe(
      '2026-01-15T14:00:00.000Z',
    );
    expect(zonedLocalToUtc('2026-07-15T09:00', 'America/New_York')).toBe(
      '2026-07-15T13:00:00.000Z',
    );
    expect(zonedLocalToUtc('2026-07-15T09:00', 'Asia/Kolkata')).toBe('2026-07-15T03:30:00.000Z');
    expect(zonedLocalToUtc('2026-07-15T09:00', 'UTC')).toBe('2026-07-15T09:00:00.000Z');
  });
  it('handles the day DST ends (fall back keeps the first occurrence offset rules consistent)', () => {
    // 2026-11-01 is the fall-back day in New York: noon is EST (UTC-5).
    expect(zonedLocalToUtc('2026-11-01T12:00', 'America/New_York')).toBe(
      '2026-11-01T17:00:00.000Z',
    );
  });
  it('rejects bad input', () => {
    expect(zonedLocalToUtc('2026-02-30T09:00', 'UTC')).toBeNull();
    expect(zonedLocalToUtc('nope', 'UTC')).toBeNull();
    expect(zonedLocalToUtc('2026-01-01T09:00', 'Not/AZone')).toBeNull();
  });
  it('shows an instant in the zone and names the zone', () => {
    const text = formatInZone('2026-01-15T14:00:00.000Z', 'America/New_York');
    expect(text).toContain('9:00 AM');
    expect(text).toContain('(America/New_York)');
    expect(text).toContain('EST');
  });
  it('adds calendar days', () => {
    expect(addDays('2026-02-28', 1)).toBe('2026-03-01');
    expect(addDays('2026-12-31', 1)).toBe('2027-01-01');
    expect(addDays('bad', 1)).toBeNull();
  });
});
