import { describe, expect, it } from 'vitest';
import { InMemoryDb, fakeId } from '@/lib/cron/testing/in-memory-db';
import { deliverNotifications, type DeliverOptions } from './deliver';
import type { DeliveryChannel, SendResult } from './types';

const quiet = () => undefined;
const opts = (db: InMemoryDb, extra: Partial<DeliverOptions> = {}): DeliverOptions => ({
  workerId: 'w1',
  softBudgetMs: 1000,
  hardBudgetMs: 2000,
  batchSize: 10,
  lockSeconds: 120,
  now: () => db.clock,
  log: quiet,
  ...extra,
});
const channel = (name: 'email' | 'push', send: () => Promise<SendResult>): DeliveryChannel => ({
  channel: name,
  send,
});

function seed(db: InMemoryDb, n = 1) {
  const people: string[] = [];
  for (let i = 0; i < n; i += 1) {
    const p = fakeId();
    db.addMember(p, { email: `p${i}@example.com`, push: true });
    people.push(p);
  }
  const e = db.emit('x.y', fakeId());
  return db.createNotifications({ eventId: e, personIds: people, kind: 'k', title: 'T' });
}
const statusOf = (db: InMemoryDb, ch: string) =>
  [...db.deliveries.values()].filter((d) => d.channel === ch).map((d) => d.status);

describe('deliverNotifications', () => {
  it('sends each pending email and push delivery and records the provider id', async () => {
    const db = new InMemoryDb();
    await seed(db, 2);
    const s = await deliverNotifications(
      db.delivery,
      {
        email: channel('email', async () => ({ outcome: 'sent', providerMessageId: 'r1' })),
        push: channel('push', async () => ({ outcome: 'sent' })),
      },
      opts(db),
    );
    expect(s).toMatchObject({ claimed: 4, sent: 4, skipped: 0, retried: 0, failed: 0 });
    expect(statusOf(db, 'email')).toEqual(['sent', 'sent']);
    expect([...db.deliveries.values()].find((d) => d.channel === 'email')?.providerMessageId).toBe(
      'r1',
    );
  });

  it('records skips with their reason', async () => {
    const db = new InMemoryDb();
    await seed(db);
    const s = await deliverNotifications(
      db.delivery,
      {
        email: channel('email', async () => ({
          outcome: 'skipped',
          reason: 'email not configured',
        })),
        push: channel('push', async () => ({ outcome: 'skipped', reason: 'push not configured' })),
      },
      opts(db),
    );
    expect(s.skipped).toBe(2);
    const reasons = [...db.deliveries.values()]
      .filter((d) => d.status === 'skipped')
      .map((d) => d.lastError);
    expect(reasons.sort()).toEqual(['email not configured', 'push not configured']);
  });

  it('a transient failure is retried later with backoff and then succeeds', async () => {
    const db = new InMemoryDb();
    await seed(db);
    let fail = true;
    const email = channel('email', async () =>
      fail ? { outcome: 'retry', error: 'resend_503' } : { outcome: 'sent' },
    );
    const push = channel('push', async () => ({ outcome: 'sent' }));
    const first = await deliverNotifications(db.delivery, { email, push }, opts(db));
    expect(first).toMatchObject({ retried: 1, sent: 1 });
    expect(statusOf(db, 'email')).toEqual(['pending']);
    // Not due yet
    expect((await deliverNotifications(db.delivery, { email, push }, opts(db))).claimed).toBe(0);
    fail = false;
    db.clock += 2 * 60_000;
    const second = await deliverNotifications(db.delivery, { email, push }, opts(db));
    expect(second.sent).toBe(1);
    expect(statusOf(db, 'email')).toEqual(['sent']);
  });

  it('a permanent failure is final, and the last attempt of a transient one fails for good', async () => {
    const db = new InMemoryDb();
    await seed(db, 2);
    let n = 0;
    const email = channel('email', async () =>
      n++ === 0
        ? { outcome: 'failed', error: 'resend_422' }
        : { outcome: 'retry', error: 'resend_503' },
    );
    const push = channel('push', async () => ({ outcome: 'sent' }));
    const first = await deliverNotifications(db.delivery, { email, push }, opts(db));
    expect(first).toMatchObject({ failed: 1, retried: 1 });
    let failed = 0;
    for (let i = 0; i < 6; i += 1) {
      db.clock += 7 * 3_600_000;
      failed += (await deliverNotifications(db.delivery, { email, push }, opts(db))).failed;
    }
    expect(failed).toBe(1);
    expect(statusOf(db, 'email').sort()).toEqual(['failed', 'failed']);
  });

  it('a send that throws is retried and does not block the next delivery', async () => {
    const db = new InMemoryDb();
    await seed(db, 2);
    let n = 0;
    const email = channel('email', async () => {
      if (n++ === 0) throw Object.assign(new Error('x'), { code: 'ECONNRESET' });
      return { outcome: 'sent' };
    });
    const s = await deliverNotifications(
      db.delivery,
      { email, push: channel('push', async () => ({ outcome: 'sent' })) },
      opts(db),
    );
    expect(s).toMatchObject({ retried: 1, sent: 3 });
    expect([...db.deliveries.values()].find((d) => d.lastError)?.lastError).toBe('code_ECONNRESET');
  });

  it('skips a delivery whose notification has gone', async () => {
    const db = new InMemoryDb();
    await seed(db);
    db.notifications.clear();
    const s = await deliverNotifications(
      db.delivery,
      {
        email: channel('email', async () => ({ outcome: 'sent' })),
        push: channel('push', async () => ({ outcome: 'sent' })),
      },
      opts(db),
    );
    expect(s.skipped).toBe(2);
  });

  it('does not claim in_app deliveries and does not touch turned-off channels', async () => {
    const db = new InMemoryDb();
    const p = fakeId();
    db.addMember(p, { email: 'a@example.com', push: true });
    db.turnedOff.add(`${p}:email`);
    await db.createNotifications({
      eventId: db.emit('x.y', fakeId()),
      personIds: [p],
      kind: 'k',
      title: 'T',
    });
    const calls: string[] = [];
    await deliverNotifications(
      db.delivery,
      {
        email: channel('email', async () => (calls.push('email'), { outcome: 'sent' })),
        push: channel('push', async () => (calls.push('push'), { outcome: 'sent' })),
      },
      opts(db),
    );
    expect(calls).toEqual(['push']);
    expect(statusOf(db, 'in_app')).toEqual(['sent']);
  });

  it('stops claiming at the soft budget and leaves unstarted claims alone at the hard budget', async () => {
    const db = new InMemoryDb();
    await seed(db, 6);
    const slow = (name: 'email' | 'push') =>
      channel(name, async () => {
        db.clock += 600;
        return { outcome: 'sent' };
      });
    const s = await deliverNotifications(
      db.delivery,
      { email: slow('email'), push: slow('push') },
      opts(db, { batchSize: 4, softBudgetMs: 1000, hardBudgetMs: 1500 }),
    );
    expect(s.budgetExhausted).toBe(true);
    expect(s.abandoned).toBeGreaterThan(0);
    expect(s.sent + s.abandoned).toBeLessThanOrEqual(s.claimed);
    // Unstarted claims are given back, with no attempt counted, instead of waiting for a lock.
    expect(db.calls.deliveryRelease).toBe(s.abandoned);
    const unsent = [...db.deliveries.values()].filter(
      (d) => d.channel !== 'in_app' && d.status === 'pending',
    );
    expect(unsent.filter((d) => d.lockedBy === null && d.attempts === 0).length).toBeGreaterThan(0);
    expect(unsent.every((d) => d.lockedBy === null || d.attempts > 0)).toBe(true);
  });
});
