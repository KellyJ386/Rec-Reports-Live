// Paging helpers. PostgREST stops at 1000 rows, so every list is paged and filtered on the
// server. Pure apart from fetchAllRows, which only calls the function it is given.
import { fail, failure, ok, type DbErrorLike, type Result } from './db-errors';

export const PAGE_SIZE = 25;
const MAX_PAGE = 100000;

export type Paged<T> = { rows: T[]; total: number; page: number; pageSize: number };

/** The first value of a search param (Next gives string | string[] | undefined). */
export function firstParam(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** A page number from a search param: a positive whole number, otherwise 1. */
export function parsePage(value: string | string[] | undefined): number {
  const text = firstParam(value);
  if (!text || !/^\d{1,6}$/.test(text)) return 1;
  const n = Number(text);
  return n >= 1 && n <= MAX_PAGE ? n : 1;
}

/** Inclusive row range for PostgREST `.range(from, to)`. */
export function pageRange(page: number, pageSize: number = PAGE_SIZE) {
  const from = (Math.max(1, page) - 1) * pageSize;
  return { from, to: from + pageSize - 1 };
}

export function pageCount(total: number, pageSize: number = PAGE_SIZE): number {
  return Math.max(1, Math.ceil(Math.max(0, total) / pageSize));
}

export function toPaged<T>(
  rows: T[] | null,
  total: number | null,
  page: number,
  pageSize: number = PAGE_SIZE,
): Paged<T> {
  const list = rows ?? [];
  return { rows: list, total: total ?? list.length, page, pageSize };
}

const FETCH_CHUNK = 1000;
const FETCH_MAX_PAGES = 20;

/**
 * Reads a whole small table (lookup lists, a location's spaces) in chunks of 1000 so the
 * PostgREST row cap never silently truncates it. The query must have a stable order.
 */
export async function fetchAllRows<T>(
  fetchChunk: (
    from: number,
    to: number,
  ) => PromiseLike<{ data: T[] | null; error: DbErrorLike | null }>,
): Promise<Result<T[]>> {
  const all: T[] = [];
  for (let i = 0; i < FETCH_MAX_PAGES; i++) {
    const from = i * FETCH_CHUNK;
    const { data, error } = await fetchChunk(from, from + FETCH_CHUNK - 1);
    if (error) return failure(error);
    const rows = data ?? [];
    all.push(...rows);
    if (rows.length < FETCH_CHUNK) return ok(all);
  }
  return fail('There is too much to show here. Narrow it down.');
}

/** "/path?a=1&b=2" from non-empty params; blank and undefined values are left out. */
export function buildHref(
  path: string,
  params: Record<string, string | number | undefined>,
): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === '') continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `${path}?${text}` : path;
}
