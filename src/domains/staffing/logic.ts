// Pure helpers for staff scheduling: week and day grouping in a location's time zone, the
// wording of statuses and refusals, and the override rule. No database access, so it is unit
// tested. A time is never shown without the zone of the location it belongs to.
import { addDays } from '@/lib/time';

// ---- assignment rules and the override flow ----

export const ASSIGN_RULES = ['not_member', 'overlap', 'time_off', 'qualification'] as const;
export type AssignRule = (typeof ASSIGN_RULES)[number];

/** The rule a refused assignment broke: DETAIL carries the code, the message is the fallback. */
export function assignRuleOf(error: {
  code?: string | null;
  message?: string | null;
  details?: string | null;
}): AssignRule | null {
  if (error.code !== '23514') return null;
  const detail = (error.details ?? '').trim();
  const byDetail = ASSIGN_RULES.find((r) => r === detail);
  if (byDetail) return byDetail;
  const message = (error.message ?? '').toLowerCase();
  if (message.includes('cannot work at this location')) return 'not_member';
  if (message.includes('already has a shift at that time')) return 'overlap';
  if (message.includes('approved time off')) return 'time_off';
  if (message.includes('missing a required qualification')) return 'qualification';
  return null;
}

/** Only time off and qualification can be overridden, and only by a schedule admin. */
export function canOfferOverride(rule: AssignRule | null, isScheduleAdmin: boolean): boolean {
  return isScheduleAdmin && (rule === 'time_off' || rule === 'qualification');
}

export const RULE_TEXT: Record<AssignRule, string> = {
  not_member: 'That person cannot work at this location.',
  overlap: 'That person already has a shift at that time.',
  time_off: 'That person has approved time off then.',
  qualification: 'That person is missing a required qualification.',
};

// ---- time zones, days and weeks ----

/** The local calendar date ('YYYY-MM-DD') of an instant in a time zone. */
export function localDateOf(iso: string, timeZone: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).formatToParts(date);
    const get = (t: string) => parts.find((p) => p.type === t)?.value ?? '';
    return `${get('year')}-${get('month')}-${get('day')}`;
  } catch {
    return '';
  }
}

function clock(iso: string, timeZone: string, withZone: boolean): string {
  return new Intl.DateTimeFormat('en-US', {
    timeZone,
    hour: 'numeric',
    minute: '2-digit',
    ...(withZone ? { timeZoneName: 'short' } : {}),
  }).format(new Date(iso));
}

/** "Mon, Nov 16" for a local date string. */
export function dayLabel(date: string): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!m) return date;
  return new Intl.DateTimeFormat('en-US', {
    timeZone: 'UTC',
    weekday: 'short',
    month: 'short',
    day: 'numeric',
  }).format(new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))));
}

/**
 * A shift as text, always with the location's zone named: "Mon, Nov 16, 9:00 AM to 5:00 PM EST
 * (America/New_York)". A shift that ends on another local day names that day too.
 */
export function formatShiftRange(startsAt: string, endsAt: string, timeZone: string): string {
  try {
    const startDay = localDateOf(startsAt, timeZone);
    const endDay = localDateOf(endsAt, timeZone);
    const start = `${dayLabel(startDay)}, ${clock(startsAt, timeZone, false)}`;
    const end =
      endDay === startDay
        ? clock(endsAt, timeZone, true)
        : `${dayLabel(endDay)}, ${clock(endsAt, timeZone, true)}`;
    return `${start} to ${end} (${timeZone})`;
  } catch {
    return `${startsAt} to ${endsAt} (UTC)`;
  }
}

/** A short "Mon, Nov 16, 9:00 AM" (no zone: used in notification titles, whose link shows it). */
export function shortShiftStart(startsAt: string, timeZone: string): string {
  try {
    return `${dayLabel(localDateOf(startsAt, timeZone))}, ${clock(startsAt, timeZone, false)}`;
  } catch {
    return startsAt;
  }
}

/** The seven local dates of a week. */
export function weekDates(weekStart: string): string[] {
  const out: string[] = [];
  for (let i = 0; i < 7; i++) {
    const d = addDays(weekStart, i);
    if (!d) return [];
    out.push(d);
  }
  return out;
}

/** The date a week containing `date` starts on, for an organization whose week starts on `weekStartsOn` (0 = Sunday). */
export function weekStartOf(date: string, weekStartsOn: number): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!m) return null;
  const dow = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]))).getUTCDay();
  const back = (dow - weekStartsOn + 7) % 7;
  return addDays(date, -back);
}

/** Today's local date in a time zone. */
export function todayIn(timeZone: string, now: Date = new Date()): string {
  return localDateOf(now.toISOString(), timeZone);
}

export type ShiftLike = { id: string; starts_at: string; ends_at: string };

/** Shifts grouped by the local day they start on (in the location's zone), oldest first. */
export function groupShiftsByDay<T extends ShiftLike>(
  shifts: readonly T[],
  timeZone: string,
  weekStart: string,
): { date: string; label: string; shifts: T[] }[] {
  const days = weekDates(weekStart);
  const byDay = new Map<string, T[]>(days.map((d) => [d, []]));
  for (const s of shifts) {
    const key = localDateOf(s.starts_at, timeZone);
    const list = byDay.get(key);
    if (list) list.push(s);
  }
  return days.map((date) => ({
    date,
    label: dayLabel(date),
    shifts: [...(byDay.get(date) ?? [])].sort(
      (a, b) => Date.parse(a.starts_at) - Date.parse(b.starts_at) || a.id.localeCompare(b.id),
    ),
  }));
}

// ---- wording ----

export function swapStatusLabel(status: string): string {
  switch (status) {
    case 'requested':
      return 'Waiting for the other person';
    case 'accepted':
      return 'Waiting for a manager';
    case 'approved':
      return 'Approved';
    case 'denied':
      return 'Declined';
    case 'cancelled':
      return 'Cancelled';
    default:
      return status;
  }
}

export function dropStatusLabel(status: string): string {
  if (status === 'requested') return 'Waiting for a manager';
  return swapStatusLabel(status);
}

export function claimStatusLabel(status: string): string {
  switch (status) {
    case 'requested':
      return 'Waiting for a manager';
    case 'approved':
      return 'You got the shift';
    case 'denied':
      return 'Not approved';
    case 'cancelled':
      return 'Cancelled';
    default:
      return status;
  }
}

export function timeOffStatusLabel(status: string): string {
  switch (status) {
    case 'pending':
      return 'Waiting for a decision';
    case 'approved':
      return 'Approved';
    case 'denied':
      return 'Not approved';
    case 'cancelled':
      return 'Cancelled';
    default:
      return status;
  }
}

export function availabilityKindLabel(kind: string): string {
  if (kind === 'available') return 'Can work';
  if (kind === 'unavailable') return 'Cannot work';
  if (kind === 'preferred') return 'Prefer to work';
  return kind;
}

/** Template apply result: why an item became an open shift. */
export function refusedText(refused: string | null): string {
  if (!refused) return 'Assigned.';
  if (
    refused === 'not_member' ||
    refused === 'overlap' ||
    refused === 'time_off' ||
    refused === 'qualification'
  ) {
    return `Left open. ${RULE_TEXT[refused]}`;
  }
  if (refused === 'time_change') {
    return 'Not added. It falls on a clock change, so the time is not clear. Add it by hand.';
  }
  if (refused === 'position_unavailable') {
    return 'Not added. Its position is archived or not available here.';
  }
  return 'Left open.';
}

/** A time off range as text, from two local dates. */
export function dateRangeText(startsOn: string, endsOn: string): string {
  return startsOn === endsOn ? dayLabel(startsOn) : `${dayLabel(startsOn)} to ${dayLabel(endsOn)}`;
}

/** Whether a shift has not started yet (swaps, drops and claims need that). */
export function notStarted(startsAt: string, now: number = Date.now()): boolean {
  return Date.parse(startsAt) > now;
}

/** A person's qualification is valid on a local date when it is inside valid_from..expires_on. */
export function qualificationState(
  q: { valid_from: string | null; expires_on: string | null },
  today: string,
): 'valid' | 'expired' | 'not_yet' {
  if (q.expires_on && q.expires_on < today) return 'expired';
  if (q.valid_from && q.valid_from > today) return 'not_yet';
  return 'valid';
}
