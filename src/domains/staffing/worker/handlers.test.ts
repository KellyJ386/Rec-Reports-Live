import { describe, expect, it } from 'vitest';
import { DeadlineReached } from '@/lib/cron/error-class';
import type { OutboxEvent } from '@/lib/cron/outbox-types';
import { InMemoryDb, NO_DEADLINE, fakeId } from '@/lib/cron/testing/in-memory-db';
import { buildHandlerRegistry } from '@/domains/workflows';
import {
  NOTIFY_CHUNK,
  STAFFING_EVENT_TYPES,
  createStaffingHandlers,
  createStaffingNotifyHandler,
} from './handlers';
import type { ShiftSnapshot } from './types';

const asEvent = (db: InMemoryDb, id: string): OutboxEvent => ({
  ...(db.events.get(id) as OutboxEvent),
});

const SHIFT: ShiftSnapshot = {
  shiftId: 'sh',
  locationId: 'loc',
  locationName: 'Main Rink',
  timezone: 'America/New_York',
  positionName: 'Lifeguard',
  startsAt: '2026-11-16T14:00:00Z',
  endsAt: '2026-11-16T22:00:00Z',
  assignedPersonId: null,
  status: 'scheduled',
};

function setup(type: string, rows: { personId: string; reason: string }[], payload = {}) {
  const db = new InMemoryDb();
  rows.forEach((r) => db.addMember(r.personId));
  const id = db.emit(type, fakeId(), payload);
  db.shiftSnapshots.set(id, { ...SHIFT });
  db.staffingRecipientRows.set(id, rows);
  const h = createStaffingNotifyHandler(type, { staffing: db, notifier: db });
  return { db, id, h };
}

describe('staffing notify handler', () => {
  it('one event gives one notification per recipient, and a retry adds nothing', async () => {
    const [a, b] = [fakeId(), fakeId()];
    const { db, id, h } = setup('shift.opened', [
      { personId: a, reason: 'can_claim' },
      { personId: b, reason: 'can_claim' },
    ]);
    await h.run(asEvent(db, id), NO_DEADLINE);
    await h.run(asEvent(db, id), NO_DEADLINE);
    const made = [...db.notifications.values()];
    expect(made.map((n) => n.personId).sort()).toEqual([a, b].sort());
    expect(made.every((n) => n.kind === 'shift_opened' && n.sourceEventId === id)).toBe(true);
    expect(db.deliveries.size).toBe(6);
  });

  it('builds the title from position and local time only, in the location zone, with no body', async () => {
    const a = fakeId();
    const { db, id, h } = setup('shift.assigned', [{ personId: a, reason: 'assigned' }]);
    await h.run(asEvent(db, id), NO_DEADLINE);
    const n = [...db.notifications.values()][0];
    expect(n?.title).toBe('You were given a shift: Lifeguard, Mon, Nov 16, 9:00 AM');
    expect(n?.body).toBeNull();
    expect(n?.linkPath).toBe('/app/schedule');
  });

  it('gives approvers and the other party different text and links, one kind per event type', async () => {
    const [a, mgr] = [fakeId(), fakeId()];
    const { db, id, h } = setup('shift_swap.accepted', [
      { personId: a, reason: 'swap_accepted' },
      { personId: mgr, reason: 'needs_approval' },
    ]);
    await h.run(asEvent(db, id), NO_DEADLINE);
    const byPerson = new Map([...db.notifications.values()].map((n) => [n.personId, n]));
    expect(byPerson.get(a)?.title).toMatch(/^Your swap was accepted/);
    expect(byPerson.get(mgr)?.title).toMatch(/^A swap needs a decision/);
    expect(byPerson.get(mgr)?.linkPath).toBe('/app/admin/schedule/requests');
    expect(new Set([...db.notifications.values()].map((n) => n.kind))).toEqual(
      new Set(['swap_accepted']),
    );
  });

  it('uses the payload dates for schedule and time off events (no shift needed)', async () => {
    const a = fakeId();
    const s = setup('schedule.published', [{ personId: a, reason: 'schedule_published' }], {
      week_start: '2026-11-15',
    });
    s.db.shiftSnapshots.clear();
    await s.h.run(asEvent(s.db, s.id), NO_DEADLINE);
    expect([...s.db.notifications.values()][0]?.title).toBe('New schedule: week of Sun, Nov 15');

    const t = setup('time_off.decided', [{ personId: a, reason: 'time_off_decided' }], {
      starts_on: '2026-12-01',
      ends_on: '2026-12-03',
      status: 'approved',
    });
    await t.h.run(asEvent(t.db, t.id), NO_DEADLINE);
    expect([...t.db.notifications.values()][0]?.title).toBe(
      'Time off approved: Tue, Dec 1 to Thu, Dec 3',
    );
  });

  it('does nothing when the database names nobody, or the shift is gone', async () => {
    const empty = setup('shift.cancelled', []);
    await empty.h.run(asEvent(empty.db, empty.id), NO_DEADLINE);
    expect(empty.db.notifications.size).toBe(0);
    const a = fakeId();
    const gone = setup('shift.cancelled', [{ personId: a, reason: 'cancelled' }]);
    gone.db.shiftSnapshots.clear();
    await gone.h.run(asEvent(gone.db, gone.id), NO_DEADLINE);
    expect(gone.db.notifications.size).toBe(0);
  });

  it('marks an uncovered shift high urgency', async () => {
    const a = fakeId();
    const { db, id, h } = setup('shift.uncovered', [{ personId: a, reason: 'uncovered' }]);
    await h.run(asEvent(db, id), NO_DEADLINE);
    expect([...db.notifications.values()][0]?.urgency).toBe('high');
  });

  it('stops at the deadline between chunks and a re-run finishes without doubling anyone', async () => {
    const people = Array.from({ length: NOTIFY_CHUNK * 3 }, () => fakeId());
    const { db, id, h } = setup(
      'shift.opened',
      people.map((personId) => ({ personId, reason: 'can_claim' })),
    );
    let n = 0;
    const stop = {
      checkpoint: async () => {
        n += 1;
        if (n > 1) throw new DeadlineReached();
      },
    };
    await expect(h.run(asEvent(db, id), stop)).rejects.toBeInstanceOf(DeadlineReached);
    expect(db.notifications.size).toBe(NOTIFY_CHUNK);
    await h.run(asEvent(db, id), NO_DEADLINE);
    expect(db.notifications.size).toBe(NOTIFY_CHUNK * 3);
  });
});

describe('staffing registration', () => {
  it('registers a handler for every staffing event type, after the rules handler where there is one', () => {
    const db = new InMemoryDb();
    const registry = buildHandlerRegistry({
      workflows: db,
      tasks: db,
      notifier: db,
      external: createStaffingHandlers({ staffing: db, notifier: db }),
    });
    for (const type of STAFFING_EVENT_TYPES) {
      expect((registry.get(type) ?? []).map((h) => h.name)).toContain('notify_staffing_recipients');
    }
    expect((registry.get('shift.uncovered') ?? []).map((h) => h.name)).toEqual([
      'workflow_rules',
      'notify_staffing_recipients',
    ]);
    for (const type of STAFFING_EVENT_TYPES) {
      const kinds = new Set<string>();
      expect(kinds.size).toBe(0);
      expect(type).toMatch(/^[a-z_]+\.[a-z_]+$/);
    }
  });
});
