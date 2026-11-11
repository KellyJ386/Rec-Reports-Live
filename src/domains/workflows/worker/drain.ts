import { consoleLogger, errorClass, type Logger } from '@/lib/cron/error-class';
import type {
  EventHandler,
  HandlerRegistry,
  OutboxEvent,
  OutboxPort,
} from '@/lib/cron/outbox-types';

export interface DrainOptions {
  /** Unique per run, so a claim can be traced to the run that holds it. */
  workerId: string;
  /** No new batch is claimed once this much time has passed. */
  softBudgetMs: number;
  /** Claimed events not started by now are left to their lock expiry instead of being half-run. */
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
  /** Claimed but not started before the hard budget. They are reclaimed after the lock expires. */
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
        summary.abandoned += events.length - index;
        summary.budgetExhausted = true;
        return summary;
      }
      await processEvent(event, outbox, registry, options.workerId, summary, log);
    }
    // A short batch means nothing else was due.
    if (events.length < options.batchSize) break;
  }
  return summary;
}

async function processEvent(
  event: OutboxEvent,
  outbox: OutboxPort,
  registry: HandlerRegistry,
  worker: string,
  summary: DrainSummary,
  log: Logger,
): Promise<void> {
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
        await handler.run(event);
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
  } catch (error) {
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
  }
}
