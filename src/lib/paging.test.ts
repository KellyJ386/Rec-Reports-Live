import { describe, expect, it } from 'vitest';
import { buildHref, fetchAllRows, pageCount, pageRange, parsePage, toPaged } from './paging';

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
