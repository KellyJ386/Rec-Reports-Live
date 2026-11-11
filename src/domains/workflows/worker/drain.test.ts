import { describe, expect, it } from 'vitest';
import type {
  EventHandler,
  HandlerContext,
  HandlerRegistry,
  OutboxEvent,
} from '@/lib/cron/outbox-types';
import { InMemoryDb, NO_DEADLINE } from '@/lib/cron/testing/in-memory-db';
import { drainOutbox, type DrainOptions } from './drain';

const quiet = () => undefined;

function options(db: InMemoryDb, extra: Partial<DrainOptions> = {}): DrainOptions {
  return {
    workerId: 'w1',
    softBudgetMs: 1000,
    hardBudgetMs: 2000,
    batchSize: 5,
    lockSeconds: 120,
    now: () => db.clock,
    log: quiet,
    ...extra,
  };
}

function handler(
  name: string,
  run: (e: OutboxEvent, ctx: HandlerContext) => Promise<void> = async () => undefined,
) {
  const calls: string[] = [];
  const h: EventHandler = {
    name,
    async run(e, ctx) {
      calls.push(e.id);
      await run(e, ctx);
    },
  };
  return { h, calls };
}

const registryOf = (type: string, ...handlers: EventHandler[]): HandlerRegistry =>
  new Map([[type, handlers]]);

describe('drainOutbox', () => {
  it('runs every handler in order, records each, and completes the event', async () => {
    const db = new InMemoryDb();
    const order: string[] = [];
    const a = handler('a', async () => void order.push('a'));
    const b = handler('b', async () => void order.push('b'));
    const id = db.emit('t.x', 'e1');
    const s = await drainOutbox(db, registryOf('t.x', a.h, b.h), options(db));
    expect(order).toEqual(['a', 'b']);
    expect(await db.handlersDone(id)).toEqual(['a', 'b']);
    expect(db.events.get(id)?.status).toBe('done');
    expect(s).toMatchObject({ claimed: 1, completed: 1, handlersRun: 2, failed: 0, dead: 0 });
  });

  it('skips handlers the ledger says are finished', async () => {
    const db = new InMemoryDb();
    const a = handler('a');
    const b = handler('b');
    const id = db.emit('t.x', 'e1');
    await db.recordHandler(id, 'a');
    const s = await drainOutbox(db, registryOf('t.x', a.h, b.h), options(db));
    expect(a.calls).toEqual([]);
    expect(b.calls).toEqual([id]);
    expect(s).toMatchObject({ handlersSkipped: 1, handlersRun: 1, completed: 1 });
  });

  it('a crash after the first handler, then a re-run, does not repeat that handler', async () => {
    const db = new InMemoryDb();
    const a = handler('a');
    let crash = true;
    const b = handler('b', async () => {
      if (crash) throw new Error('boom');
    });
    const id = db.emit('t.x', 'e1');
    const reg = registryOf('t.x', a.h, b.h);

    const first = await drainOutbox(db, reg, options(db));
    expect(first).toMatchObject({ failed: 1, completed: 0 });
    expect(db.events.get(id)?.status).toBe('pending');
    expect(db.events.get(id)?.lastError).toBe('b: Error');
    expect(a.calls).toHaveLength(1);

    crash = false;
    db.clock += 2 * 60_000; // past the backoff
    const second = await drainOutbox(db, reg, options(db));
    expect(second).toMatchObject({ completed: 1, handlersSkipped: 1, handlersRun: 1 });
    expect(a.calls).toHaveLength(1); // not repeated
    expect(b.calls).toHaveLength(2);
    expect(db.events.get(id)?.status).toBe('done');
  });

  it('a crash of the whole worker (lock left behind) lets a later run finish without repeating handlers', async () => {
    const db = new InMemoryDb();
    const a = handler('a');
    const b = handler('b');
    const id = db.emit('t.x', 'e1');
    // Worker 1 claimed, ran "a", recorded it, and died before "b".
    await db.claim('dead-worker', 5, 120);
    await a.h.run({ ...(db.events.get(id) as OutboxEvent) }, NO_DEADLINE);
    await db.recordHandler(id, 'a');
    // Not reclaimable until the lock expires.
    expect((await drainOutbox(db, registryOf('t.x', a.h, b.h), options(db))).claimed).toBe(0);
    db.clock += 121_000;
    const s = await drainOutbox(db, registryOf('t.x', a.h, b.h), options(db));
    expect(s).toMatchObject({ claimed: 1, completed: 1 });
    expect(a.calls).toHaveLength(1);
    expect(b.calls).toHaveLength(1);
  });

  it('a failing handler fails its event and the next event still runs', async () => {
    const db = new InMemoryDb();
    const poison = handler('p', async (e) => {
      if (e.entityId === 'bad') throw Object.assign(new Error('x'), { code: '23505' });
    });
    const bad = db.emit('t.x', 'bad');
    const good = db.emit('t.x', 'good');
    const s = await drainOutbox(db, registryOf('t.x', poison.h), options(db));
    expect(db.events.get(bad)?.status).toBe('pending');
    expect(db.events.get(bad)?.lastError).toBe('p: code_23505');
    expect(db.events.get(good)?.status).toBe('done');
    expect(s).toMatchObject({ claimed: 2, completed: 1, failed: 1 });
  });

  it('reports dead when the last attempt fails', async () => {
    const db = new InMemoryDb();
    const h = handler('p', async () => {
      throw new Error('always');
    });
    const id = db.emit('t.x', 'e');
    let dead = 0;
    for (let i = 0; i < 8; i += 1) {
      db.clock += 7 * 3_600_000;
      dead += (await drainOutbox(db, registryOf('t.x', h.h), options(db))).dead;
    }
    expect(dead).toBe(1);
    expect(db.events.get(id)?.status).toBe('dead');
    expect(h.calls).toHaveLength(8);
  });

  it('completes an unknown event type with no action and counts it', async () => {
    const db = new InMemoryDb();
    const a = handler('a');
    const id = db.emit('mystery.happened', 'e1');
    const s = await drainOutbox(db, registryOf('t.x', a.h), options(db));
    expect(db.events.get(id)?.status).toBe('done');
    expect(s).toMatchObject({ unknownType: 1, completed: 1, handlersRun: 0 });
    expect(a.calls).toEqual([]);
  });

  it('stops claiming when the soft budget is spent', async () => {
    const db = new InMemoryDb();
    const slow = handler('slow', async () => {
      db.clock += 600; // each event costs 600 ms
    });
    for (let i = 0; i < 6; i += 1) db.emit('t.x', `e${i}`);
    const s = await drainOutbox(
      db,
      registryOf('t.x', slow.h),
      options(db, { batchSize: 2, softBudgetMs: 1000, hardBudgetMs: 100_000 }),
    );
    // batch 1 (1200 ms) exceeds the budget, so no third batch is claimed
    expect(s.batches).toBe(1);
    expect(s.claimed).toBe(2);
    expect(s.budgetExhausted).toBe(true);
    expect([...db.events.values()].filter((e) => e.status === 'pending')).toHaveLength(4);
  });

  it('gives back claimed events it has no time to start, never half-run', async () => {
    const db = new InMemoryDb();
    const slow = handler('slow', async () => {
      db.clock += 600;
    });
    for (let i = 0; i < 4; i += 1) db.emit('t.x', `e${i}`);
    const s = await drainOutbox(
      db,
      registryOf('t.x', slow.h),
      options(db, { batchSize: 4, softBudgetMs: 1000, hardBudgetMs: 1000 }),
    );
    expect(s).toMatchObject({ claimed: 4, completed: 2, abandoned: 2, budgetExhausted: true });
    expect(slow.calls).toHaveLength(2);
    // They were released (no lock wait, no attempt used), so the next run takes them at once.
    expect(db.calls.release).toBe(2);
    expect(
      [...db.events.values()].filter((e) => e.status === 'pending' && e.attempts === 0),
    ).toHaveLength(2);
    const again = await drainOutbox(db, registryOf('t.x', slow.h), options(db));
    expect(again.completed).toBe(2);
  });

  it('a handler that hits the deadline inside its loop is released, not failed, and resumes next run', async () => {
    const db = new InMemoryDb();
    const done: number[] = [];
    // A fan-out of 5 chunks; each chunk costs 400 ms. The hard budget (1000 ms) runs out mid-way.
    const fanOut = handler('fan', async (_e, ctx) => {
      for (let chunk = 0; chunk < 5; chunk += 1) {
        if (done.includes(chunk)) continue; // idempotent: already made on an earlier run
        await ctx.checkpoint();
        done.push(chunk);
        db.clock += 400;
      }
    });
    const id = db.emit('t.x', 'e1');
    const first = await drainOutbox(
      db,
      registryOf('t.x', fanOut.h),
      options(db, { softBudgetMs: 1000, hardBudgetMs: 1000 }),
    );
    expect(first).toMatchObject({
      completed: 0,
      failed: 0,
      dead: 0,
      abandoned: 1,
      budgetExhausted: true,
    });
    expect(done).toEqual([0, 1, 2]);
    expect(db.events.get(id)).toMatchObject({ status: 'pending', attempts: 0 });
    const second = await drainOutbox(db, registryOf('t.x', fanOut.h), options(db));
    expect(second.completed).toBe(1);
    expect(done).toEqual([0, 1, 2, 3, 4]);
  });

  it('extends the lock of a long fan-out, and stops quietly when the claim is gone', async () => {
    const db = new InMemoryDb();
    const long = handler('long', async (_e, ctx) => {
      for (let i = 0; i < 4; i += 1) {
        await ctx.checkpoint();
        db.clock += 40_000; // a quarter of a 120 s lock is 30 s
      }
    });
    const id = db.emit('t.x', 'e1');
    const s = await drainOutbox(
      db,
      registryOf('t.x', long.h),
      options(db, { softBudgetMs: 1_000_000, hardBudgetMs: 1_000_000 }),
    );
    expect(s.completed).toBe(1);
    expect(db.calls.extendLock).toBeGreaterThanOrEqual(2);
    expect(db.events.get(id)?.status).toBe('done');

    const db2 = new InMemoryDb();
    const stolen = handler('stolen', async (e, ctx) => {
      const ev = db2.events.get(e.id);
      if (ev) ev.lockedBy = 'someone-else';
      db2.clock += 40_000;
      await ctx.checkpoint();
    });
    db2.emit('t.x', 'e1');
    const s2 = await drainOutbox(
      db2,
      registryOf('t.x', stolen.h),
      options(db2, { softBudgetMs: 1_000_000, hardBudgetMs: 1_000_000 }),
    );
    expect(s2).toMatchObject({ lostClaim: 1, completed: 0, failed: 0 });
  });

  it('counts a lost claim instead of throwing', async () => {
    const db = new InMemoryDb();
    const stealer = handler('s', async (e) => {
      // Another worker takes over: its claim replaces ours.
      const ev = db.events.get(e.id);
      if (ev) ev.lockedBy = 'someone-else';
    });
    db.emit('t.x', 'e1');
    const s = await drainOutbox(db, registryOf('t.x', stealer.h), options(db));
    expect(s).toMatchObject({ lostClaim: 1, completed: 0 });
  });

  it('keeps going when recording a failure itself fails', async () => {
    const db = new InMemoryDb();
    const h = handler('p', async (e) => {
      if (e.entityId === 'a') throw new Error('x');
    });
    db.emit('t.x', 'a');
    db.emit('t.x', 'b');
    const realFail = db.fail.bind(db);
    db.fail = async () => {
      throw new Error('db down');
    };
    const s = await drainOutbox(db, registryOf('t.x', h.h), options(db));
    expect(s.completed).toBe(1);
    db.fail = realFail;
  });
});
