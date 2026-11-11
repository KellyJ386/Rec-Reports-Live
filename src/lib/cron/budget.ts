/**
 * Time budgets for the cron routes. Each route exports `maxDuration = 60` (seconds), which every
 * Vercel plan allows (a longer limit needs a plan or setting that raises it; raise these
 * together). A run stops starting new work after SOFT_BUDGET_MS, finishes the item in hand, and
 * leaves the function 15 seconds of slack before the platform would kill it.
 *
 * Lock seconds must exceed the worst case of one batch, so a slow batch is not reclaimed by the
 * next run while it is still working: HARD_BUDGET_MS (when processing stops) + the longest single
 * item, well inside LOCK_SECONDS.
 */
export const MAX_DURATION_SECONDS = 60;
/** No new batch is claimed after this. */
export const SOFT_BUDGET_MS = 35_000;
/** Claimed items not started by this point are left to their lock (never half-done). */
export const HARD_BUDGET_MS = 45_000;
export const LOCK_SECONDS = 120;
export const OUTBOX_BATCH_SIZE = 5;
export const DELIVERY_BATCH_SIZE = 10;
/** Every outbound HTTP call (Resend, push services) gives up after this long. */
export const OUTBOUND_TIMEOUT_MS = 8_000;
export const OVERDUE_SWEEP_LIMIT = 500;
