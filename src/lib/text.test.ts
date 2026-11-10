import { describe, expect, it } from 'vitest';
import { blankToNull, keyFromName, searchWords, toInt } from './text';

describe('searchWords', () => {
  it('splits into words and keeps names and emails intact', () => {
    expect(searchWords('  Ana   Lopez ')).toEqual(['Ana', 'Lopez']);
    expect(searchWords("o'neil")).toEqual(["o'neil"]);
    expect(searchWords('ana.lopez+x@example.com')).toEqual(['ana.lopez+x@example.com']);
  });
  it('drops characters that could alter a PostgREST filter', () => {
    const words = searchWords('a,b) or (id.eq.1 "x" %*\\');
    for (const w of words) expect(w).not.toMatch(/[,()"%*\\]/);
    expect(searchWords('),or(')).toEqual(['or']);
  });
  it('handles empty input and caps the number of words', () => {
    expect(searchWords(undefined)).toEqual([]);
    expect(searchWords('   ')).toEqual([]);
    expect(searchWords('a b c d e f g')).toHaveLength(5);
  });
});

describe('keyFromName', () => {
  it('makes a lowercase key', () => {
    expect(keyFromName('Front Desk')).toBe('front_desk');
    expect(keyFromName('Café  Lead!')).toBe('cafe_lead');
  });
  it('starts with a letter and stays within 63 characters', () => {
    expect(keyFromName('2nd shift')).toMatch(/^[a-z]/);
    expect(keyFromName('x'.repeat(100))).toHaveLength(63);
  });
});

describe('form value helpers', () => {
  it('blankToNull trims', () => {
    expect(blankToNull('  ')).toBeNull();
    expect(blankToNull(' a ')).toBe('a');
    expect(blankToNull(null)).toBeNull();
  });
  it('toInt accepts whole numbers only', () => {
    expect(toInt('12')).toBe(12);
    expect(toInt('')).toBeNull();
    expect(toInt('1.5')).toBeNull();
    expect(toInt('abc')).toBeNull();
  });
});
