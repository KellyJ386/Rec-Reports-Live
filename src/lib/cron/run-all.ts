import { ClaimLost, DeadlineReached } from './error-class';

/**
 * Runs `fn` for every item, one after another, even when some fail, then rethrows the first
 * failure. One bad recipient must not starve the rest of a fan-out; the event still fails so it
 * is retried, and the idempotent create calls make the retry safe.
 */
export async function runAll<T>(
  items: readonly T[],
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let first: unknown;
  let failed = false;
  for (const item of items) {
    try {
      await fn(item);
    } catch (error) {
      // Out of time or out of claim: stop now, do not keep going through the list.
      if (error instanceof DeadlineReached || error instanceof ClaimLost) throw error;
      if (!failed) {
        failed = true;
        first = error;
      }
    }
  }
  if (failed) throw first;
}

/** Splits a list into pieces of at most `size`. */
export function chunk<T>(items: readonly T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/** Shortens text to `max` characters, adding an ellipsis when it was cut. */
export function clip(text: string, max: number): string {
  const flat = text.replace(/\s+/g, ' ').trim();
  return flat.length <= max ? flat : `${flat.slice(0, Math.max(0, max - 1)).trimEnd()}…`;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID.test(value);
}
