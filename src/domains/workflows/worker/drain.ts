import {
  ClaimLost,
  DeadlineReached,
  consoleLogger,
  errorClass,
  type Logger,
} from '@/lib/cron/error-class';
import type {
  EventHandler,
  HandlerContext,
  HandlerRegistry,
  OutboxEvent,
  OutboxPort,
} from '@/lib/cron/outbox-types';

export interface DrainOptions {
  /** Unique per run, so a claim can be traced to the run that holds it. */
  workerId: string;
  /** No new batch is claimed once this much time has passed. */
  softBudgetMs: number;
  /**
   * Past this point nothing new is started: claimed events not yet started are given back with
   * release_outbox_event, and a handler stops at its next checkpoint (its event is released too).
   */
  hardBudgetMs: number;
  batchSize: number;
  lockSeconds: number;
  now?: () => number;
  log?: Logger;
}

export interface DrainSummary {
  batches: number;
  claimed: number;
  completed: number;
  /** Events put back for a retry with backoff. */
  failed: number;
  /** Events that used their last attempt. */
  dead: number;
  handlersRun: number;
  /** Handlers the ledger said were already finished. */
  handlersSkipped: number;
  /** Events of a type with no handlers: completed with no action. */
  unknownType: number;
  /** complete/fail found the claim gone (another worker took it). */
  lostClaim: number;
  /** Claimed but not finished before the hard budget. Given back (release_outbox_event, no attempt counted); the next run takes them. */
  abandoned: number;
  budgetExhausted: boolean;
}

/**
 * Drains the outbox until it is empty or the time budget says stop.
 *
 * Per event: ask the ledger which handlers already finished, run the rest in order, record each
 * one as it succeeds, and complete the event when all are done. A handler that throws fails the
 * event (`fail_outbox_event`: backoff, then dead after the attempt limit) with a short error
 * class, and the loop moves on: one poison event never blocks the batch. Handlers are idempotent
 * on their own, so a crash between a handler's effect and its ledger row only repeats a no-op.
 */
export async function drainOutbox(
  outbox: OutboxPort,
  registry: HandlerRegistry,
  options: DrainOptions,
): Promise<DrainSummary> {
  const now = options.now ?? Date.now;
  const log = options.log ?? consoleLogger;
  const started = now();
  const summary: DrainSummary = {
    batches: 0,
    claimed: 0,
    completed: 0,
    failed: 0,
    dead: 0,
    handlersRun: 0,
    handlersSkipped: 0,
    unknownType: 0,
    lostClaim: 0,
    abandoned: 0,
    budgetExhausted: false,
  };

  for (;;) {
    if (now() - started >= options.softBudgetMs) {
      summary.budgetExhausted = true;
      break;
    }
    const events = await outbox.claim(options.workerId, options.batchSize, options.lockSeconds);
    if (events.length === 0) break;
    summary.batches += 1;
    summary.claimed += events.length;

    for (const [index, event] of events.entries()) {
      if (now() - started >= options.hardBudgetMs) {
        await releaseAll(events.slice(index), outbox, options.workerId, summary, log);
        summary.budgetExhausted = true;
        return summary;
      }
      const outcome = await processEvent(event, outbox, registry, options, started, summary, log);
      if (outcome === 'deadline') {
        await releaseAll(events.slice(index + 1), outbox, options.workerId, summary, log);
        summary.budgetExhausted = true;
        return summary;
      }
    }
    // A short batch means nothing else was due.
    if (events.length < options.batchSize) break;
  }
  return summary;
}

/** Gives claimed events back unprocessed. A failure to release only costs a lock-expiry wait. */
async function releaseAll(
  events: readonly OutboxEvent[],
  outbox: OutboxPort,
  worker: string,
  summary: DrainSummary,
  log: Logger,
): Promise<void> {
  for (const event of events) {
    summary.abandoned += 1;
    try {
      await outbox.release(event.id, worker);
    } catch (error) {
      log({ event: 'outbox.release_failed', id: event.id, errorClass: errorClass(error) });
    }
  }
}

async function processEvent(
  event: OutboxEvent,
  outbox: OutboxPort,
  registry: HandlerRegistry,
  options: DrainOptions,
  started: number,
  summary: DrainSummary,
  log: Logger,
): Promise<'done' | 'deadline'> {
  const worker = options.workerId;
  const now = options.now ?? Date.now;
  let lastExtend = now();
  const ctx: HandlerContext = {
    async checkpoint() {
      if (now() - started >= options.hardBudgetMs) throw new DeadlineReached();
      // Extend a quarter of the way through the lock, so a long fan-out keeps its claim.
      if (now() - lastExtend >= (options.lockSeconds * 1000) / 4) {
        const held = await outbox.extendLock(event.id, worker, options.lockSeconds);
        if (!held) throw new ClaimLost();
        lastExtend = now();
      }
    },
  };
  let step = 'ledger';
  try {
    const handlers: readonly EventHandler[] | undefined = registry.get(event.type);
    if (!handlers || handlers.length === 0) {
      summary.unknownType += 1;
      log({ event: 'outbox.unknown_type', id: event.id, type: event.type });
    } else {
      const done = new Set(await outbox.handlersDone(event.id));
      for (const handler of handlers) {
        if (done.has(handler.name)) {
          summary.handlersSkipped += 1;
          continue;
        }
        step = handler.name;
        await ctx.checkpoint();
        await handler.run(event, ctx);
        step = `${handler.name}:ledger`;
        await outbox.recordHandler(event.id, handler.name);
        summary.handlersRun += 1;
      }
    }
    step = 'complete';
    if (await outbox.complete(event.id, worker)) {
      summary.completed += 1;
    } else {
      summary.lostClaim += 1;
      log({ event: 'outbox.lost_claim', id: event.id });
    }
    return 'done';
  } catch (error) {
    if (error instanceof DeadlineReached) {
      // Out of time mid-event: give it back. Handlers already finished are in the ledger and the
      // rest are idempotent, so the next run carries on where this one stopped.
      summary.abandoned += 1;
      try {
        await outbox.release(event.id, worker);
      } catch (releaseError) {
        log({ event: 'outbox.release_failed', id: event.id, errorClass: errorClass(releaseError) });
      }
      return 'deadline';
    }
    if (error instanceof ClaimLost) {
      summary.lostClaim += 1;
      log({ event: 'outbox.lost_claim', id: event.id });
      return 'done';
    }
    const cls = errorClass(error);
    log({ event: 'outbox.handler_failed', id: event.id, type: event.type, step, errorClass: cls });
    try {
      const status = await outbox.fail(event.id, worker, `${step}: ${cls}`);
      if (status === 'dead') summary.dead += 1;
      else if (status === 'pending') summary.failed += 1;
      else summary.lostClaim += 1;
    } catch (failError) {
      // The database is unreachable: the lock expires and the event is reclaimed.
      log({ event: 'outbox.fail_failed', id: event.id, errorClass: errorClass(failError) });
    }
    return 'done';
  }
}
