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

/** The page to show: the requested one, but never past the last page the total allows. */
export function clampPage(page: number, total: number, pageSize: number = PAGE_SIZE): number {
  return Math.min(Math.max(1, page), pageCount(total, pageSize));
}

type PageResponse<T> = {
  data: T[] | null;
  count: number | null;
  error: DbErrorLike | null;
};

/**
 * Runs a counted, ranged query for one page and clamps the page to the real last page. A page
 * past the end comes back from PostgREST either as zero rows or as a 416 (PGRST103); both are
 * answered by showing the last page (or the first, when the table is empty). The query must
 * ask for a count ('exact', or 'estimated' for big tables).
 */
export async function fetchClampedPage<T>(
  page: number,
  run: (from: number, to: number) => PromiseLike<PageResponse<T>>,
  pageSize: number = PAGE_SIZE,
): Promise<Result<Paged<T>>> {
  let current = Math.max(1, page);
  let res = await run(...rangeArgs(current, pageSize));
  if (res.error?.code === 'PGRST103' && current > 1) {
    current = 1;
    res = await run(...rangeArgs(current, pageSize));
  }
  if (res.error) return failure(res.error);
  const total = res.count;
  if ((res.data ?? []).length === 0 && total !== null && total > 0) {
    const last = clampPage(current, total, pageSize);
    if (last !== current) {
      current = last;
      res = await run(...rangeArgs(current, pageSize));
      if (res.error) return failure(res.error);
    }
  }
  return ok(toPaged(res.data, res.count, current, pageSize));
}

function rangeArgs(page: number, pageSize: number): [number, number] {
  const { from, to } = pageRange(page, pageSize);
  return [from, to];
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
