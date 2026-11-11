// End to end in memory: one notice.published event with three audience members, processed twice,
// yields exactly three notifications and nine deliveries; the sends then happen once each.
// The domain indexes pull in code that imports server-only modules, so those are stubbed.
import { describe, expect, it, vi } from 'vitest';

vi.mock('server-only', () => ({}));
vi.mock('@/lib/supabase/server', () => ({ createClient: vi.fn() }));

import { buildHandlerRegistry, drainOutbox, type DrainOptions } from '@/domains/workflows';
import {
  createChannels,
  createMessageNotifyHandler,
  createNoticeNotifyHandler,
  deliverNotifications,
  type DeliverOptions,
} from '@/domains/communications';
import { InMemoryDb, fakeId } from './testing/in-memory-db';

const quiet = () => undefined;
const SITE = 'https://app.example.com';

function setup() {
  const db = new InMemoryDb();
  const people = [fakeId(), fakeId(), fakeId()];
  people.forEach((p, i) => db.addMember(p, { email: `p${i}@example.com`, push: true }));
  const noticeId = fakeId();
  db.notices.set(noticeId, {
    id: noticeId,
    title: 'Pool closed Friday',
    status: 'published',
    urgency: 'critical',
    requiresAcknowledgment: true,
    expiresAt: null,
  });
  db.noticeAudience.set(noticeId, people);
  const eventId = db.emit('notice.published', noticeId, { urgency: 'critical' }, 'notices');

  const registry = buildHandlerRegistry({
    workflows: db,
    tasks: db,
    notifier: db,
    external: [
      {
        type: 'notice.published',
        handler: createNoticeNotifyHandler({ notices: db, notifier: db }),
      },
      { type: 'message.sent', handler: createMessageNotifyHandler({ notifier: db }) },
    ],
  });
  const drain: DrainOptions = {
    workerId: 'w',
    softBudgetMs: 10_000,
    hardBudgetMs: 20_000,
    batchSize: 5,
    lockSeconds: 120,
    now: () => db.clock,
    log: quiet,
  };
  return { db, people, noticeId, eventId, registry, drain };
}

describe('notice.published end to end (in memory)', () => {
  it('processed twice: exactly three notifications and nine deliveries', async () => {
    const { db, eventId, registry, drain } = setup();

    const first = await drainOutbox(db, registry, drain);
    expect(first).toMatchObject({ claimed: 1, completed: 1 });
    expect(db.notifications.size).toBe(3);
    expect(db.deliveries.size).toBe(9);

    // The same event is delivered again (as after a crash before the ledger or completion was
    // written): the ledger is lost and the event is pending again.
    for (const key of [...db.ledger]) if (key.startsWith(eventId)) db.ledger.delete(key);
    const event = db.events.get(eventId);
    if (!event) throw new Error('event missing');
    event.status = 'pending';
    event.nextAttemptAt = db.clock;
    const second = await drainOutbox(db, registry, drain);
    expect(second).toMatchObject({ claimed: 1, completed: 1, handlersRun: 2 });

    expect(db.notifications.size).toBe(3);
    expect(db.deliveries.size).toBe(9);
    expect([...db.notifications.values()].every((n) => n.urgency === 'critical')).toBe(true);
    // in_app is recorded at once; email and push wait for the sender
    const byStatus = (s: string) =>
      [...db.deliveries.values()].filter((d) => d.status === s).length;
    expect(byStatus('sent')).toBe(3);
    expect(byStatus('pending')).toBe(6);
  });

  it('a third pass over a finished event does nothing at all', async () => {
    const { db, registry, drain } = setup();
    await drainOutbox(db, registry, drain);
    const before = db.calls.createNotification;
    const again = await drainOutbox(db, registry, drain);
    expect(again.claimed).toBe(0);
    expect(db.calls.createNotification).toBe(before);
  });

  it('then delivers each email and push once, with only title, summary and link', async () => {
    const { db, registry, drain } = setup();
    await drainOutbox(db, registry, drain);

    const mails: { to: string[]; subject: string; text: string }[] = [];
    const pushes: string[] = [];
    const channels = createChannels({
      email: {
        config: { apiKey: 'k', from: 'Rec Reports <a@example.com>' },
        siteUrl: SITE,
        people: db.delivery,
        fetchImpl: (async (_u: string | URL | Request, init?: RequestInit) => {
          mails.push(JSON.parse(String(init?.body)));
          return Response.json({ id: `m${mails.length}` });
        }) as typeof fetch,
      },
      push: {
        vapid: { subject: 'mailto:a@example.com', publicKey: 'pub', privateKey: 'priv' },
        siteUrl: SITE,
        devices: db.delivery,
        send: async (_t, payload) => {
          pushes.push(payload);
        },
      },
    });
    const options: DeliverOptions = { ...drain, batchSize: 10 };
    const sent = await deliverNotifications(db.delivery, channels, options);
    expect(sent).toMatchObject({ claimed: 6, sent: 6, skipped: 0 });
    const again = await deliverNotifications(db.delivery, channels, options);
    expect(again.claimed).toBe(0);

    expect(mails).toHaveLength(3);
    expect(pushes).toHaveLength(3);
    expect(mails.every((m) => m.subject === 'Urgent: Pool closed Friday')).toBe(true);
    expect(mails.every((m) => m.text.includes(`${SITE}/app/notices/`))).toBe(true);
    expect([...db.deliveries.values()].every((d) => d.status === 'sent')).toBe(true);
    expect(JSON.parse(pushes[0] ?? '{}')).toMatchObject({
      urgent: true,
      title: 'Pool closed Friday',
    });
  });

  it('with email and push unconfigured, the deliveries are skipped with their reasons', async () => {
    const { db, registry, drain } = setup();
    await drainOutbox(db, registry, drain);
    const channels = createChannels({
      email: { config: {}, siteUrl: SITE, people: db.delivery },
      push: { vapid: null, siteUrl: SITE, devices: db.delivery, send: async () => undefined },
    });
    const s = await deliverNotifications(db.delivery, channels, drain);
    expect(s).toMatchObject({ claimed: 6, skipped: 6, sent: 0 });
    const reasons = new Set(
      [...db.deliveries.values()].filter((d) => d.lastError).map((d) => d.lastError),
    );
    expect(reasons).toEqual(new Set(['email not configured', 'push not configured']));
  });
});
