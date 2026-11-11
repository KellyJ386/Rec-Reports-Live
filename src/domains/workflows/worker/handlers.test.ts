import { describe, expect, it } from 'vitest';
import type { OutboxEvent } from '@/lib/cron/outbox-types';
import { InMemoryDb, fakeId } from '@/lib/cron/testing/in-memory-db';
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
    await h.run(asEvent(db, id));
    await h.run(asEvent(db, id));
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
    await createRulesHandler(db).run(asEvent(db, id));
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
    await expect(createRulesHandler(db).run(asEvent(db, id))).rejects.toThrow();
    expect(db.tasksByKey.size).toBe(1);
  });

  it('does nothing when no rule matches', async () => {
    const db = new InMemoryDb();
    const id = db.emit('booking.confirmed', 'b1');
    await createRulesHandler(db).run(asEvent(db, id));
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
    await createTaskNotifyHandler({ tasks: db, notifier: db }, 'task_created').run(asEvent(db, id));
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
    await h.run(asEvent(db, id));
    await h.run(asEvent(db, id));
    expect(db.notifications.size).toBe(1);
    expect([...db.notifications.values()][0]?.title).toMatch(/^Assigned to you/);
  });

  it('sends nothing for a finished or missing task, or one with no recipients', async () => {
    const { db, alice } = setup();
    const done = db.addTask({ id: fakeId(), status: 'done' }, [alice]);
    const open = db.addTask({ id: fakeId() }, []);
    const h = createTaskNotifyHandler({ tasks: db, notifier: db }, 'task_created');
    await h.run(asEvent(db, db.emit('task.created', done.id)));
    await h.run(asEvent(db, db.emit('task.created', open.id)));
    await h.run(asEvent(db, db.emit('task.created', fakeId())));
    expect(db.notifications.size).toBe(0);
  });

  it('task.overdue notifies at high urgency, and not for a task finished meanwhile', async () => {
    const { db, alice } = setup();
    const late = db.addTask({ id: fakeId(), title: 'Fix door' }, [alice]);
    const fixed = db.addTask({ id: fakeId(), status: 'cancelled' }, [alice]);
    const h = createOverdueNotifyHandler({ tasks: db, notifier: db });
    await h.run(asEvent(db, db.emit('task.overdue', late.id)));
    await h.run(asEvent(db, db.emit('task.overdue', fixed.id)));
    const made = [...db.notifications.values()];
    expect(made).toHaveLength(1);
    expect(made[0]).toMatchObject({
      kind: 'task_overdue',
      urgency: 'high',
      title: 'Overdue: Fix door',
    });
  });

  it('never puts the task instructions or other fields in a notification', async () => {
    const { db, alice } = setup();
    const task = db.addTask({ id: fakeId(), title: 'T' }, [alice]);
    await createTaskNotifyHandler({ tasks: db, notifier: db }, 'task_created').run(
      asEvent(db, db.emit('task.created', task.id)),
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
