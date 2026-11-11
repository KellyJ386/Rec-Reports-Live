import { describe, expect, it } from 'vitest';
import type { OutboxEvent } from '@/lib/cron/outbox-types';
import { InMemoryDb, fakeId } from '@/lib/cron/testing/in-memory-db';
import { createMessageNotifyHandler, createNoticeNotifyHandler, noticeLink } from './handlers';

const asEvent = (db: InMemoryDb, id: string): OutboxEvent => ({
  ...(db.events.get(id) as OutboxEvent),
});

function notice(db: InMemoryDb, over: Partial<Parameters<typeof db.notices.set>[1]> = {}) {
  const id = fakeId();
  db.notices.set(id, {
    id,
    title: 'Pool closed Friday',
    status: 'published',
    urgency: 'normal',
    requiresAcknowledgment: false,
    expiresAt: null,
    ...over,
  });
  return id;
}

describe('notice.published handler', () => {
  it('notifies every audience member once, with the title and a link, and no body', async () => {
    const db = new InMemoryDb();
    const people = [fakeId(), fakeId(), fakeId()];
    people.forEach((p) => db.addMember(p));
    const nid = notice(db);
    db.noticeAudience.set(nid, people);
    const id = db.emit('notice.published', nid);
    const h = createNoticeNotifyHandler({ notices: db, notifier: db });
    await h.run(asEvent(db, id));
    await h.run(asEvent(db, id));
    const made = [...db.notifications.values()];
    expect(made).toHaveLength(3);
    expect(
      made.every((n) => n.kind === 'notice_published' && n.title === 'Pool closed Friday'),
    ).toBe(true);
    expect(made.every((n) => n.linkPath === noticeLink(nid) && n.body === null)).toBe(true);
  });

  it('flags a critical notice as critical, using the row and not the payload', async () => {
    const db = new InMemoryDb();
    const p = fakeId();
    db.addMember(p);
    const nid = notice(db, { urgency: 'critical', requiresAcknowledgment: true });
    db.noticeAudience.set(nid, [p]);
    const id = db.emit('notice.published', nid, { urgency: 'normal' });
    await createNoticeNotifyHandler({ notices: db, notifier: db }).run(asEvent(db, id));
    const n = [...db.notifications.values()][0];
    expect(n?.urgency).toBe('critical');
    expect(n?.body).toMatch(/Acknowledge/);
  });

  it('sends nothing for an archived, expired, draft or missing notice', async () => {
    const db = new InMemoryDb();
    const p = fakeId();
    db.addMember(p);
    const h = createNoticeNotifyHandler({ notices: db, notifier: db }, () => 5_000);
    const ids = [
      notice(db, { status: 'archived' }),
      notice(db, { status: 'draft' }),
      notice(db, { expiresAt: new Date(4_000).toISOString() }),
      fakeId(),
    ];
    for (const nid of ids) {
      db.noticeAudience.set(nid, [p]);
      await h.run(asEvent(db, db.emit('notice.published', nid)));
    }
    expect(db.notifications.size).toBe(0);
  });

  it('skips audience members who are not active (create_notification returns null)', async () => {
    const db = new InMemoryDb();
    const active = fakeId();
    db.addMember(active);
    const nid = notice(db);
    db.noticeAudience.set(nid, [active, fakeId()]);
    await createNoticeNotifyHandler({ notices: db, notifier: db }).run(
      asEvent(db, db.emit('notice.published', nid)),
    );
    expect(db.notifications.size).toBe(1);
  });
});

describe('message.sent handler', () => {
  it('notifies each recipient once with no sender and no content', async () => {
    const db = new InMemoryDb();
    const [a, b, sender] = [fakeId(), fakeId(), fakeId()];
    [a, b, sender].forEach((p) => db.addMember(p));
    const id = db.emit('message.sent', fakeId(), {
      sender_person_id: sender,
      recipient_person_ids: [a, b, a, sender, 'not-a-uuid', 42],
    });
    const h = createMessageNotifyHandler({ notifier: db });
    await h.run(asEvent(db, id));
    await h.run(asEvent(db, id));
    const made = [...db.notifications.values()];
    expect(made.map((n) => n.personId).sort()).toEqual([a, b].sort());
    expect(made.every((n) => n.title === 'New message' && n.body === null)).toBe(true);
  });

  it('does nothing when the payload has no recipient list', async () => {
    const db = new InMemoryDb();
    await createMessageNotifyHandler({ notifier: db }).run(
      asEvent(db, db.emit('message.sent', fakeId())),
    );
    expect(db.notifications.size).toBe(0);
  });
});
