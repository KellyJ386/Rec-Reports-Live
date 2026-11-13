// Ports of the staffing worker (notifications for schedule, shift, swap, claim and time off
// events). Production: ./supabase-ports.ts. Tests: src/lib/cron/testing.

/** worker_shift_for_event: the shift an event is about. No notes. */
export interface ShiftSnapshot {
  shiftId: string;
  locationId: string;
  locationName: string;
  /** IANA zone of the location: every time in a notification is shown in it. */
  timezone: string;
  positionName: string;
  startsAt: string;
  endsAt: string;
  assignedPersonId: string | null;
  status: string;
}

export interface StaffingRecipient {
  personId: string;
  /** Why this person is told (schedule_published, assigned, can_claim, needs_approval, ...). */
  reason: string;
}

export interface StaffingPort {
  /** Null: the event has no shift (schedule and time off events), or it is gone. */
  shiftForEvent(eventId: string): Promise<ShiftSnapshot | null>;
  /** One row per person to tell, already filtered by the database to active members. */
  recipients(eventId: string): Promise<StaffingRecipient[]>;
  /** emit_uncovered_shift_events: returns how many shift.uncovered events were emitted. */
  emitUncovered(withinHours: number, limit?: number): Promise<number>;
}

/** What the handlers need from the communications domain (create_notifications). */
export interface StaffingNotifier {
  createNotifications(input: {
    eventId: string;
    personIds: string[];
    kind: string;
    title: string;
    body?: string | null;
    linkPath?: string | null;
    urgency?: 'normal' | 'high' | 'critical';
  }): Promise<number>;
}
