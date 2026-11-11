/**
 * The contract between the drain loop (src/domains/workflows/worker) and the handlers of any
 * domain. Pure types: no database client in here. Tests use the in-memory implementation in
 * ./testing/in-memory-db.ts; production uses the Supabase ports in each domain's worker folder.
 */

/** An event as claimed from `outbox_events`. The payload is ids and scalars only (DB CHECK). */
export interface OutboxEvent {
  id: string;
  organizationId: string;
  locationId: string | null;
  type: string;
  schemaVersion: number;
  entityTable: string;
  /** The row the event is about (a task, a notice, a message). Trusted: set by emit_event. */
  entityId: string;
  payload: Readonly<Record<string, unknown>>;
  correlationId: string;
  /** Attempts used so far, including this one. */
  attempts: number;
}

/** The worker functions of migration 000200 (service_role only). */
export interface OutboxPort {
  claim(worker: string, limit: number, lockSeconds: number): Promise<OutboxEvent[]>;
  /** False: the claim was lost (another worker took the event after the lock expired). */
  complete(eventId: string, worker: string): Promise<boolean>;
  /** The new status, or null when the claim was lost. */
  fail(eventId: string, worker: string, error: string): Promise<'pending' | 'dead' | null>;
  handlersDone(eventId: string): Promise<string[]>;
  /** True when newly recorded. */
  recordHandler(eventId: string, handler: string): Promise<boolean>;
  /** Gives a claimed event back unprocessed (the attempt is not counted). False: the claim was lost. */
  release(eventId: string, worker: string): Promise<boolean>;
  /** Pushes the lock of a claimed event out by `seconds`. False: the claim was lost. */
  extendLock(eventId: string, worker: string, seconds: number): Promise<boolean>;
}

/**
 * What the drain loop gives a handler. A handler with a loop (a fan-out to many people) calls
 * `checkpoint()` before each chunk: it throws `DeadlineReached` when the run is out of time (the
 * event is then released, and the next run finishes it: handlers are idempotent) and extends the
 * event's lock now and then so a long fan-out is not reclaimed while it works.
 */
export interface HandlerContext {
  checkpoint(): Promise<void>;
}

/**
 * One named step for one event type. It must be idempotent on its own: a crash between the
 * step's effect and its ledger row runs it again. It re-reads rows by id and creates things
 * only through the idempotent service functions.
 */
export interface EventHandler {
  /** Ledger key: lowercase letters, digits and `_ . : -`, at most 100 characters. */
  readonly name: string;
  run(event: OutboxEvent, ctx: HandlerContext): Promise<void>;
}

/** Event type -> handlers, in the order they run. */
export type HandlerRegistry = ReadonlyMap<string, readonly EventHandler[]>;
