import { describe, expect, it } from 'vitest';
import type { OutboxEvent } from '@/lib/cron/outbox-types';
import { InMemoryDb, NO_DEADLINE, fakeId } from '@/lib/cron/testing/in-memory-db';
import {
  HANDLER_NAMES,
  createOverdueNotifyHandler,
  createRulesHandler,
  createTaskNotifyHandler,
  taskLink,
} from './handlers';
import { RULE_EVENT_TYPES, buildHandlerRegistry } from './registry';

const asEvent = (db: InMemoryDb, id: string): OutboxEvent => {
  const e = db.events.get(id);
  if (!e) throw new Error('no event');
  return { ...e };
};

describe('rules handler', () => {
  it('creates one task per matching rule, through the idempotent function, and is safe to run twice', async () => {
    const db = new InMemoryDb();
    db.rules.push(
      { id: 'r1', templateId: 't1', eventType: 'incident.submitted', enabled: true },
      { id: 'r2', templateId: 't2', eventType: 'incident.submitted', enabled: true },
      { id: 'r3', templateId: 't3', eventType: 'incident.submitted', enabled: false },
      { id: 'r4', templateId: 't4', eventType: 'checklist.completed', enabled: true },
    );
    const id = db.emit('incident.submitted', 'inc1');
    const h = createRulesHandler(db);
    await h.run(asEvent(db, id), NO_DEADLINE);
    await h.run(asEvent(db, id), NO_DEADLINE);
    expect(db.tasksByKey.size).toBe(2); // exactly one task per (event, template)
    expect(db.calls.createTaskFromEvent).toBe(4);
  });

  it('two rules sharing a template still make one task', async () => {
    const db = new InMemoryDb();
    db.rules.push(
      { id: 'r1', templateId: 't1', eventType: 'shift.uncovered', enabled: true },
      { id: 'r2', templateId: 't1', eventType: 'shift.uncovered', enabled: true },
    );
    const id = db.emit('shift.uncovered', 's1');
    await createRulesHandler(db).run(asEvent(db, id), NO_DEADLINE);
    expect(db.tasksByKey.size).toBe(1);
  });

  it('keeps going past a failing rule, then fails so the event is retried', async () => {
    const db = new InMemoryDb();
    db.rules.push(
      { id: 'r1', templateId: 't1', eventType: 'booking.confirmed', enabled: true },
      { id: 'r2', templateId: 't2', eventType: 'booking.confirmed', enabled: true },
    );
    const id = db.emit('booking.confirmed', 'b1');
    const real = db.createTaskFromEvent.bind(db);
    db.createTaskFromEvent = async (e, r) => {
      if (r === 'r1') throw new Error('x');
      return real(e, r);
    };
    await expect(createRulesHandler(db).run(asEvent(db, id), NO_DEADLINE)).rejects.toThrow();
    expect(db.tasksByKey.size).toBe(1);
  });

  it('does nothing when no rule matches', async () => {
    const db = new InMemoryDb();
    const id = db.emit('booking.confirmed', 'b1');
    await createRulesHandler(db).run(asEvent(db, id), NO_DEADLINE);
    expect(db.calls.createTaskFromEvent).toBe(0);
  });
});

describe('task notify handlers', () => {
  const setup = () => {
    const db = new InMemoryDb();
    const alice = fakeId();
    const bob = fakeId();
    db.addMember(alice);
    db.addMember(bob);
    return { db, alice, bob };
  };

  it('task.created notifies the recipients, links to the task, and skips the actor', async () => {
    const { db, alice, bob } = setup();
    const task = db.addTask({ id: fakeId(), title: 'Mop the lobby', priority: 'urgent' }, [
      alice,
      bob,
    ]);
    const id = db.emit('task.created', task.id, { actor_person_id: bob });
    await createTaskNotifyHandler({ tasks: db, notifier: db }, 'task_created').run(
      asEvent(db, id),
      NO_DEADLINE,
    );
    const made = [...db.notifications.values()];
    expect(made).toHaveLength(1);
    expect(made[0]).toMatchObject({
      personId: alice,
      kind: 'task_created',
      title: 'New task: Mop the lobby',
      linkPath: taskLink(task.id),
      urgency: 'high',
      sourceEventId: id,
    });
  });

  it('task.assigned says "Assigned to you" and is idempotent on re-run', async () => {
    const { db, alice } = setup();
    const task = db.addTask({ id: fakeId() }, [alice]);
    const id = db.emit('task.assigned', task.id);
    const h = createTaskNotifyHandler({ tasks: db, notifier: db }, 'task_assigned');
    await h.run(asEvent(db, id), NO_DEADLINE);
    await h.run(asEvent(db, id), NO_DEADLINE);
    expect(db.notifications.size).toBe(1);
    expect([...db.notifications.values()][0]?.title).toMatch(/^Assigned to you/);
  });

  it('sends nothing for a finished or missing task, or one with no recipients', async () => {
    const { db, alice } = setup();
    const done = db.addTask({ id: fakeId(), status: 'done' }, [alice]);
    const open = db.addTask({ id: fakeId() }, []);
    const h = createTaskNotifyHandler({ tasks: db, notifier: db }, 'task_created');
    await h.run(asEvent(db, db.emit('task.created', done.id)), NO_DEADLINE);
    await h.run(asEvent(db, db.emit('task.created', open.id)), NO_DEADLINE);
    await h.run(asEvent(db, db.emit('task.created', fakeId())), NO_DEADLINE);
    expect(db.notifications.size).toBe(0);
  });

  const overdue = (db: InMemoryDb) =>
    createOverdueNotifyHandler({ tasks: db, workflows: db, notifier: db });

  it('task.overdue tells the staff assignee and the managers, once, with a neutral text', async () => {
    const { db, alice, bob } = setup();
    const late = db.addTask({ id: fakeId(), title: 'Fix door' }, [alice]);
    db.escalationRecipients.set(late.id, [bob]); // the manager, not the assignee
    const id = db.emit('task.overdue', late.id);
    await overdue(db).run(asEvent(db, id), NO_DEADLINE);
    await overdue(db).run(asEvent(db, id), NO_DEADLINE); // retry: nothing new
    const made = [...db.notifications.values()];
    expect(made.map((n) => n.personId).sort()).toEqual([alice, bob].sort());
    for (const n of made) {
      expect(n).toMatchObject({
        kind: 'task_overdue',
        urgency: 'high',
        title: 'Task overdue: Fix door',
        body: null,
        sourceEventId: id,
      });
    }
  });

  it('the assignee still gets it when escalation returns nobody', async () => {
    const { db, alice } = setup();
    const late = db.addTask({ id: fakeId() }, [alice]);
    await overdue(db).run(asEvent(db, db.emit('task.overdue', late.id)), NO_DEADLINE);
    expect([...db.notifications.values()].map((n) => n.personId)).toEqual([alice]);
  });

  it('a manager who is also the assignee gets one notification, not two', async () => {
    const { db, alice, bob } = setup();
    const late = db.addTask({ id: fakeId() }, [alice, bob]);
    db.escalationRecipients.set(late.id, [alice]);
    await overdue(db).run(asEvent(db, db.emit('task.overdue', late.id)), NO_DEADLINE);
    const made = [...db.notifications.values()];
    expect(made).toHaveLength(2);
    expect(made.filter((n) => n.personId === alice)).toHaveLength(1);
  });

  it('task.overdue sends nothing for a closed task or one nobody is on', async () => {
    const { db, alice } = setup();
    const nobody = db.addTask({ id: fakeId() }, []);
    const fixed = db.addTask({ id: fakeId(), status: 'cancelled' }, [alice]);
    db.escalationRecipients.set(fixed.id, [alice]);
    await overdue(db).run(asEvent(db, db.emit('task.overdue', nobody.id)), NO_DEADLINE);
    await overdue(db).run(asEvent(db, db.emit('task.overdue', fixed.id)), NO_DEADLINE);
    expect(db.notifications.size).toBe(0);
  });

  it('never puts the task instructions or other fields in a notification', async () => {
    const { db, alice } = setup();
    const task = db.addTask({ id: fakeId(), title: 'T' }, [alice]);
    await createTaskNotifyHandler({ tasks: db, notifier: db }, 'task_created').run(
      asEvent(db, db.emit('task.created', task.id)),
      NO_DEADLINE,
    );
    const n = [...db.notifications.values()][0];
    expect(Object.keys(n ?? {}).sort()).toEqual(
      ['body', 'id', 'kind', 'linkPath', 'personId', 'sourceEventId', 'title', 'urgency'].sort(),
    );
  });
});

describe('registry', () => {
  const db = new InMemoryDb();
  const registry = buildHandlerRegistry({ workflows: db, tasks: db, notifier: db });
  const names = (type: string) => (registry.get(type) ?? []).map((h) => h.name);

  it('runs rules for every rule-able event type', () => {
    for (const type of RULE_EVENT_TYPES) expect(names(type)[0]).toBe(HANDLER_NAMES.workflowRules);
  });
  it('orders handlers: rules first, then notifications', () => {
    expect(names('task.overdue')).toEqual(['workflow_rules', 'notify_task_overdue']);
    expect(names('task.created')).toEqual(['notify_task_recipients']);
    expect(names('task.assigned')).toEqual(['notify_task_recipients']);
  });
  it('has nothing for unlisted types', () => {
    expect(registry.has('task.completed')).toBe(false);
    expect(registry.has('mystery.happened')).toBe(false);
  });
  it('appends handlers owned by other domains after the built-in ones', () => {
    const reg = buildHandlerRegistry({
      workflows: db,
      tasks: db,
      notifier: db,
      external: [{ type: 'notice.published', handler: { name: 'x', run: async () => undefined } }],
    });
    expect((reg.get('notice.published') ?? []).map((h) => h.name)).toEqual(['workflow_rules', 'x']);
  });
  it('refuses a duplicate handler name for one type', () => {
    expect(() =>
      buildHandlerRegistry({
        workflows: db,
        tasks: db,
        notifier: db,
        external: [
          { type: 'task.overdue', handler: { name: 'workflow_rules', run: async () => undefined } },
        ],
      }),
    ).toThrow(/duplicate/);
  });
  it('uses ledger names the database accepts', () => {
    for (const list of registry.values())
      for (const h of list) expect(h.name).toMatch(/^[a-z][a-z0-9_.:-]{0,99}$/);
  });
});
