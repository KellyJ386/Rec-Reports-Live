import { chunk, clip } from '@/lib/cron/run-all';
import type { EventHandler, HandlerContext, OutboxEvent } from '@/lib/cron/outbox-types';
import { dateRangeText, dayLabel, shortShiftStart } from '../logic';
import type { ShiftSnapshot, StaffingNotifier, StaffingPort } from './types';

/** Ledger name (stored in outbox_event_handlers: add, never rename). */
export const STAFFING_HANDLER_NAME = 'notify_staffing_recipients';

/** People per create_notifications call. */
export const NOTIFY_CHUNK = 200;

export const SCHEDULE_LINK = '/app/schedule';
export const OPEN_SHIFTS_LINK = '/app/schedule/open';
export const SWAPS_LINK = '/app/schedule/swaps';
export const TIME_OFF_LINK = '/app/schedule/time-off';
export const ADMIN_SCHEDULE_LINK = '/app/admin/schedule';
export const ADMIN_REQUESTS_LINK = '/app/admin/schedule/requests';

type Urgency = 'normal' | 'high';
type Spec = {
  /** One notification kind per event type (the idempotency key is event + person + kind). */
  kind: string;
  /** Title from non-free-text fields only. `shift` is null for events with no shift. */
  title: (reason: string, shift: ShiftSnapshot | null, event: OutboxEvent) => string;
  link: (reason: string) => string;
  urgency?: Urgency;
  /** The event needs the shift to make a title. */
  needsShift: boolean;
};

const approverReasons = new Set(['needs_approval', 'uncovered', 'time_off_cancelled']);
const adminLink = (reason: string, fallback: string, adminTo: string) =>
  approverReasons.has(reason) ? adminTo : fallback;

/** What a shift is, in words a person can read at a glance: position, then local day and time. */
function what(shift: ShiftSnapshot): string {
  return `${shift.positionName}, ${shortShiftStart(shift.startsAt, shift.timezone)}`;
}

function dateOf(value: unknown): string | null {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value) ? value : null;
}

const SPECS: Record<string, Spec> = {
  'schedule.published': {
    kind: 'schedule_published',
    needsShift: false,
    title: (_r, _s, e) => {
      const week = dateOf(e.payload.week_start);
      return week ? `New schedule: week of ${dayLabel(week)}` : 'A new schedule was published';
    },
    link: () => SCHEDULE_LINK,
  },
  'shift.assigned': {
    kind: 'shift_assigned',
    needsShift: true,
    title: (_r, s) => `You were given a shift: ${what(s!)}`,
    link: () => SCHEDULE_LINK,
  },
  'shift.unassigned': {
    kind: 'shift_unassigned',
    needsShift: true,
    title: (_r, s) => `You were taken off a shift: ${what(s!)}`,
    link: () => SCHEDULE_LINK,
  },
  'shift.changed': {
    kind: 'shift_changed',
    needsShift: true,
    title: (_r, s) => `Your shift changed: ${what(s!)}`,
    link: () => SCHEDULE_LINK,
  },
  'shift.cancelled': {
    kind: 'shift_cancelled',
    needsShift: true,
    title: (_r, s) => `Your shift was cancelled: ${what(s!)}`,
    link: () => SCHEDULE_LINK,
  },
  'shift.opened': {
    kind: 'shift_opened',
    needsShift: true,
    title: (_r, s) => `Open shift you can take: ${what(s!)}`,
    link: () => OPEN_SHIFTS_LINK,
  },
  'shift.uncovered': {
    kind: 'shift_uncovered',
    needsShift: true,
    urgency: 'high',
    title: (_r, s) => `Nobody is on this shift yet: ${what(s!)}`,
    link: () => ADMIN_SCHEDULE_LINK,
  },
  'shift_swap.requested': {
    kind: 'swap_requested',
    needsShift: true,
    title: (r, s) =>
      r === 'needs_approval'
        ? `A shift drop needs a decision: ${what(s!)}`
        : `Someone offered you a swap: ${what(s!)}`,
    link: (r) => adminLink(r, SWAPS_LINK, ADMIN_REQUESTS_LINK),
  },
  'shift_swap.accepted': {
    kind: 'swap_accepted',
    needsShift: true,
    title: (r, s) =>
      r === 'needs_approval'
        ? `A swap needs a decision: ${what(s!)}`
        : `Your swap was accepted: ${what(s!)}`,
    link: (r) => adminLink(r, SWAPS_LINK, ADMIN_REQUESTS_LINK),
  },
  'shift_swap.approved': {
    kind: 'swap_approved',
    needsShift: true,
    title: (_r, s) => `Swap approved: ${what(s!)}`,
    link: () => SCHEDULE_LINK,
  },
  'shift_swap.denied': {
    kind: 'swap_denied',
    needsShift: true,
    title: (_r, s) => `Swap not approved: ${what(s!)}`,
    link: () => SWAPS_LINK,
  },
  'shift_swap.cancelled': {
    kind: 'swap_cancelled',
    needsShift: true,
    title: (_r, s) => `Swap cancelled: ${what(s!)}`,
    link: () => SWAPS_LINK,
  },
  'shift_claim.requested': {
    kind: 'claim_requested',
    needsShift: true,
    title: (_r, s) => `A claim on an open shift needs a decision: ${what(s!)}`,
    link: () => ADMIN_REQUESTS_LINK,
  },
  'shift_claim.approved': {
    kind: 'claim_approved',
    needsShift: true,
    title: (_r, s) => `You got the open shift: ${what(s!)}`,
    link: () => SCHEDULE_LINK,
  },
  'shift_claim.denied': {
    kind: 'claim_denied',
    needsShift: true,
    title: (_r, s) => `Your claim was not approved: ${what(s!)}`,
    link: () => OPEN_SHIFTS_LINK,
  },
  'time_off.requested': {
    kind: 'time_off_requested',
    needsShift: false,
    title: (_r, _s, e) => {
      const a = dateOf(e.payload.starts_on);
      const b = dateOf(e.payload.ends_on);
      return a && b
        ? `Time off to review: ${dateRangeText(a, b)}`
        : 'A time off request needs a decision';
    },
    link: () => ADMIN_REQUESTS_LINK,
  },
  'time_off.decided': {
    kind: 'time_off_decided',
    needsShift: false,
    title: (_r, _s, e) => {
      const a = dateOf(e.payload.starts_on);
      const b = dateOf(e.payload.ends_on);
      const status =
        e.payload.status === 'approved'
          ? 'approved'
          : e.payload.status === 'denied'
            ? 'not approved'
            : 'decided';
      return a && b ? `Time off ${status}: ${dateRangeText(a, b)}` : `Your time off was ${status}`;
    },
    link: () => TIME_OFF_LINK,
  },
  'time_off.cancelled': {
    kind: 'time_off_cancelled',
    needsShift: false,
    title: (_r, _s, e) => {
      const a = dateOf(e.payload.starts_on);
      const b = dateOf(e.payload.ends_on);
      return a && b
        ? `Approved time off was cancelled: ${dateRangeText(a, b)}`
        : 'Approved time off was cancelled';
    },
    link: () => ADMIN_REQUESTS_LINK,
  },
};

/** Every event type this worker turns into notifications. */
export const STAFFING_EVENT_TYPES = Object.keys(SPECS);

/**
 * One handler for a staffing event type. It asks the database who to tell
 * (`worker_shift_event_recipients`, one row per person with a reason) and what the shift is
 * (`worker_shift_for_event`), then creates the notifications with `create_notifications`, in chunks,
 * with a deadline check before each. One consistent kind per event type. The title holds only the
 * position name and the local day and time in the location's zone, or dates: never notes, reasons
 * or names. People with the same reason get the same text; a person appears once per event, so a
 * re-run creates nothing new.
 */
export function createStaffingNotifyHandler(
  type: string,
  deps: { staffing: StaffingPort; notifier: StaffingNotifier },
): EventHandler {
  const spec = SPECS[type];
  if (!spec) throw new Error(`no staffing notification for ${type}`);
  return {
    name: STAFFING_HANDLER_NAME,
    async run(event: OutboxEvent, ctx: HandlerContext) {
      const recipients = await deps.staffing.recipients(event.id);
      if (recipients.length === 0) return;
      let shift: ShiftSnapshot | null = null;
      if (spec.needsShift) {
        shift = await deps.staffing.shiftForEvent(event.id);
        if (!shift) return;
      }
      const byReason = new Map<string, string[]>();
      for (const r of recipients) {
        byReason.set(r.reason, [...(byReason.get(r.reason) ?? []), r.personId]);
      }
      for (const [reason, people] of byReason) {
        for (const personIds of chunk([...new Set(people)], NOTIFY_CHUNK)) {
          await ctx.checkpoint();
          await deps.notifier.createNotifications({
            eventId: event.id,
            personIds,
            kind: spec.kind,
            title: clip(spec.title(reason, shift, event), 120),
            body: null,
            linkPath: spec.link(reason),
            urgency: spec.urgency ?? 'normal',
          });
        }
      }
    },
  };
}

/** The (type, handler) pairs for the registry's `external` list. */
export function createStaffingHandlers(deps: {
  staffing: StaffingPort;
  notifier: StaffingNotifier;
}): { type: string; handler: EventHandler }[] {
  return STAFFING_EVENT_TYPES.map((type) => ({
    type,
    handler: createStaffingNotifyHandler(type, deps),
  }));
}
