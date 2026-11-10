import { describe, expect, it } from 'vitest';
import {
  buildHref,
  clampPage,
  fetchAllRows,
  fetchClampedPage,
  pageCount,
  pageRange,
  parsePage,
  toPaged,
} from './paging';

describe('parsePage', () => {
  it('defaults to 1 for missing or bad input', () => {
    for (const v of [undefined, '', '0', '-2', 'abc', '1.5', '1e3', '99999999']) {
      expect(parsePage(v), String(v)).toBe(1);
    }
  });
  it('reads a positive whole number, first value of an array', () => {
    expect(parsePage('3')).toBe(3);
    expect(parsePage(['4', '9'])).toBe(4);
  });
});

describe('pageRange / pageCount', () => {
  it('gives inclusive 25-row ranges', () => {
    expect(pageRange(1)).toEqual({ from: 0, to: 24 });
    expect(pageRange(3)).toEqual({ from: 50, to: 74 });
    expect(pageRange(0)).toEqual({ from: 0, to: 24 });
  });
  it('counts pages, minimum one', () => {
    expect(pageCount(0)).toBe(1);
    expect(pageCount(25)).toBe(1);
    expect(pageCount(26)).toBe(2);
  });
  it('builds a paged result', () => {
    expect(toPaged(null, null, 2)).toEqual({ rows: [], total: 0, page: 2, pageSize: 25 });
  });
});

describe('fetchAllRows', () => {
  const makeSource = (n: number) => (from: number, to: number) =>
    Promise.resolve({
      data: Array.from({ length: n }, (_, i) => i).slice(from, to + 1),
      error: null,
    });

  it('reads past the 1000 row cap in chunks', async () => {
    const r = await fetchAllRows(makeSource(2500));
    expect(r.ok && r.data.length).toBe(2500);
  });
  it('stops at an exact multiple of the chunk size', async () => {
    const r = await fetchAllRows(makeSource(1000));
    expect(r.ok && r.data.length).toBe(1000);
  });
  it('returns a plain failure on a database error', async () => {
    const r = await fetchAllRows(() =>
      Promise.resolve({ data: null, error: { code: '42501', message: 'x' } }),
    );
    expect(r).toEqual({ ok: false, message: 'You are not allowed to do that.' });
  });
  it('refuses to read without limit', async () => {
    const r = await fetchAllRows((from, to) =>
      Promise.resolve({ data: Array.from({ length: to - from + 1 }, () => 1), error: null }),
    );
    expect(r.ok).toBe(false);
  });
});

describe('buildHref', () => {
  it('keeps only filled params and encodes them', () => {
    expect(buildHref('/a', { q: 'ana lopez', page: 2, empty: '', none: undefined })).toBe(
      '/a?q=ana+lopez&page=2',
    );
    expect(buildHref('/a', {})).toBe('/a');
  });
});

describe('clampPage', () => {
  it('never goes past the last page or below 1', () => {
    expect(clampPage(9, 60)).toBe(3);
    expect(clampPage(2, 60)).toBe(2);
    expect(clampPage(5, 0)).toBe(1);
    expect(clampPage(0, 60)).toBe(1);
  });
});

describe('fetchClampedPage', () => {
  const table = (n: number) => (from: number, to: number) =>
    Promise.resolve({
      data: Array.from({ length: n }, (_, i) => i).slice(from, to + 1),
      count: n,
      error: null,
    });

  it('returns the requested page when it exists', async () => {
    const r = await fetchClampedPage(2, table(60));
    expect(r.ok && r.data.page).toBe(2);
    expect(r.ok && r.data.rows.length).toBe(25);
  });
  it('falls back to the last page when the requested one is empty', async () => {
    const r = await fetchClampedPage(99, table(60));
    expect(r.ok && r.data.page).toBe(3);
    expect(r.ok && r.data.rows.length).toBe(10);
  });
  it('recovers from a 416 range error on an empty table or a short one', async () => {
    const out = (n: number) => (from: number, to: number) =>
      from >= Math.max(n, 1)
        ? Promise.resolve({ data: null, count: null, error: { code: 'PGRST103', message: 'r' } })
        : table(n)(from, to);
    const r = await fetchClampedPage(7, out(30));
    expect(r.ok && r.data.page).toBe(1);
    const empty = await fetchClampedPage(7, out(0));
    expect(empty.ok && empty.data).toMatchObject({ page: 1, rows: [], total: 0 });
  });
  it('reports other database errors in plain words', async () => {
    const r = await fetchClampedPage(1, () =>
      Promise.resolve({ data: null, count: null, error: { code: '42501', message: 'x' } }),
    );
    expect(r).toEqual({ ok: false, message: 'You are not allowed to do that.' });
  });
});
