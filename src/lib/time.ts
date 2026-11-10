// Time helpers. Times are stored in UTC; the UI shows them in the location's time zone and
// always names the zone. ISO weekdays: 1 = Monday ... 7 = Sunday (space_hours.day_of_week).

export const ISO_WEEKDAYS = [
  { value: 1, label: 'Monday' },
  { value: 2, label: 'Tuesday' },
  { value: 3, label: 'Wednesday' },
  { value: 4, label: 'Thursday' },
  { value: 5, label: 'Friday' },
  { value: 6, label: 'Saturday' },
  { value: 7, label: 'Sunday' },
] as const;

export const WEEK_START_OPTIONS = [
  { value: 0, label: 'Sunday' },
  { value: 1, label: 'Monday' },
  { value: 2, label: 'Tuesday' },
  { value: 3, label: 'Wednesday' },
  { value: 4, label: 'Thursday' },
  { value: 5, label: 'Friday' },
  { value: 6, label: 'Saturday' },
] as const;

export function weekdayLabel(day: number): string {
  return ISO_WEEKDAYS.find((d) => d.value === day)?.label ?? `Day ${day}`;
}

/** IANA zones the database accepts: UTC, or Area/Location names. */
export function listTimeZones(): string[] {
  const zones = Intl.supportedValuesOf('timeZone').filter((z) => z.includes('/'));
  return ['UTC', ...zones];
}

/** '09:00:00' -> '9:00 AM'; '24:00:00' -> 'midnight (end of day)'. */
export function formatClock(time: string): string {
  const m = /^(\d{2}):(\d{2})/.exec(time);
  if (!m) return time;
  const h = Number(m[1]);
  const min = m[2];
  if (h === 24) return 'midnight (end of day)';
  const suffix = h >= 12 ? 'PM' : 'AM';
  const h12 = h % 12 === 0 ? 12 : h % 12;
  return `${h12}:${min} ${suffix}`;
}

/** '09:00:00' -> '09:00' (value for an <input type="time">). */
export function toTimeInput(time: string): string {
  const m = /^(\d{2}):(\d{2})/.exec(time);
  return m ? `${m[1]}:${m[2]}` : time;
}

export function formatHoursRange(opensAt: string, closesAt: string): string {
  return `${formatClock(opensAt)} to ${formatClock(closesAt)}`;
}

/** An instant shown in a time zone, with the zone named: "Nov 10, 2026, 3:30 PM EST (America/New_York)". */
export function formatInZone(iso: string, timeZone: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  try {
    const text = new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      timeZoneName: 'short',
    }).format(date);
    return `${text} (${timeZone})`;
  } catch {
    return `${date.toISOString()} (UTC)`;
  }
}

function zoneOffsetMs(utcMs: number, timeZone: string): number {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    hourCycle: 'h23',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).formatToParts(new Date(utcMs));
  const get = (type: string) => Number(parts.find((p) => p.type === type)?.value);
  const asUtc = Date.UTC(
    get('year'),
    get('month') - 1,
    get('day'),
    get('hour'),
    get('minute'),
    get('second'),
  );
  return asUtc - utcMs;
}

/**
 * A wall-clock time in a time zone ("2026-11-10T15:30", as an <input type="datetime-local">
 * gives it) to a UTC ISO string. Null when the text is not a valid local date and time or the
 * zone is unknown. A time that does not exist (spring-forward gap) moves forward an hour.
 */
export function zonedLocalToUtc(local: string, timeZone: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(local);
  if (!m) return null;
  const [y, mo, d, h, mi, s] = [m[1], m[2], m[3], m[4], m[5], m[6] ?? '0'].map(Number) as [
    number,
    number,
    number,
    number,
    number,
    number,
  ];
  const naive = Date.UTC(y, mo - 1, d, h, mi, s);
  const check = new Date(naive);
  if (
    check.getUTCFullYear() !== y ||
    check.getUTCMonth() !== mo - 1 ||
    check.getUTCDate() !== d ||
    h > 23 ||
    mi > 59
  ) {
    return null;
  }
  try {
    const first = naive - zoneOffsetMs(naive, timeZone);
    const second = naive - zoneOffsetMs(first, timeZone);
    return new Date(second).toISOString();
  } catch {
    return null;
  }
}

/** Adds whole days to a 'YYYY-MM-DD' date string (calendar arithmetic, no time zone). */
export function addDays(date: string, days: number): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(date);
  if (!m) return null;
  const ms = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) + days * 86400000;
  return new Date(ms).toISOString().slice(0, 10);
}
