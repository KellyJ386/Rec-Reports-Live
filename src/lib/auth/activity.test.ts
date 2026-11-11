import { describe, expect, it } from 'vitest';
import {
  IDLE_TIMEOUT_SECONDS,
  classifyActivity,
  idleVerdict,
  needsAdminTierLookup,
  signActivity,
} from './activity';

const SECRET = 'unit-test-secret-that-is-long-enough-1234';
const OTHER_SECRET = 'a-different-secret-that-is-long-enough-99';
const USER = '11111111-1111-4111-8111-111111111111';
const OTHER_USER = '22222222-2222-4222-8222-222222222222';
const NOW = 1_800_000_000;

describe('classifyActivity', () => {
  it('is fresh for a genuine recent stamp, including exactly at the limit', () => {
    expect(classifyActivity(signActivity(USER, NOW - 5, SECRET), USER, SECRET, NOW)).toBe('fresh');
    const edge = signActivity(USER, NOW - IDLE_TIMEOUT_SECONDS, SECRET);
    expect(classifyActivity(edge, USER, SECRET, NOW)).toBe('fresh');
  });
  it('is stale one second past the limit', () => {
    const old = signActivity(USER, NOW - IDLE_TIMEOUT_SECONDS - 1, SECRET);
    expect(classifyActivity(old, USER, SECRET, NOW)).toBe('stale');
  });
  it('is missing for no cookie', () => {
    expect(classifyActivity(undefined, USER, SECRET, NOW)).toBe('missing');
    expect(classifyActivity(null, USER, SECRET, NOW)).toBe('missing');
    expect(classifyActivity('', USER, SECRET, NOW)).toBe('missing');
  });
  it('rejects a stamp whose time was edited to look newer', () => {
    const old = signActivity(USER, NOW - 7200, SECRET);
    const mac = old.split('.')[1];
    expect(classifyActivity(`${NOW}.${mac}`, USER, SECRET, NOW)).toBe('invalid');
  });
  it('rejects a changed signature, junk and wrong shapes', () => {
    const good = signActivity(USER, NOW, SECRET);
    const flipped = good.slice(0, -1) + (good.endsWith('A') ? 'B' : 'A');
    expect(classifyActivity(flipped, USER, SECRET, NOW)).toBe('invalid');
    for (const junk of ['abc', '123', `${NOW}.`, `${NOW}.short`, '.', `-1.${'a'.repeat(43)}`]) {
      expect(classifyActivity(junk, USER, SECRET, NOW), junk).toBe('invalid');
    }
  });
  it('rejects a stamp made for another user (wrong-user case)', () => {
    const theirs = signActivity(OTHER_USER, NOW, SECRET);
    expect(classifyActivity(theirs, USER, SECRET, NOW)).toBe('invalid');
  });
  it('rejects a stamp made with another secret', () => {
    expect(classifyActivity(signActivity(USER, NOW, OTHER_SECRET), USER, SECRET, NOW)).toBe(
      'invalid',
    );
  });
  it('rejects a stamp from the future beyond clock skew, accepts small skew', () => {
    expect(classifyActivity(signActivity(USER, NOW + 3600, SECRET), USER, SECRET, NOW)).toBe(
      'invalid',
    );
    expect(classifyActivity(signActivity(USER, NOW + 30, SECRET), USER, SECRET, NOW)).toBe('fresh');
  });
  it('treats the user id case-insensitively but nothing else', () => {
    const stamp = signActivity(USER.toUpperCase(), NOW, SECRET);
    expect(classifyActivity(stamp, USER, SECRET, NOW)).toBe('fresh');
  });
});

describe('idleVerdict', () => {
  it('always allows a fresh stamp', () => {
    expect(idleVerdict('fresh', true)).toBe('allow');
    expect(idleVerdict('fresh', false)).toBe('allow');
  });
  it('signs an admin-tier session out for stale, missing or invalid stamps', () => {
    for (const state of ['stale', 'missing', 'invalid'] as const) {
      expect(idleVerdict(state, true), state).toBe('sign_out');
    }
  });
  it('never signs a non-admin session out', () => {
    for (const state of ['stale', 'missing', 'invalid'] as const) {
      expect(idleVerdict(state, false), state).toBe('allow');
    }
  });
  it('only a fresh stamp skips the admin-tier lookup', () => {
    expect(needsAdminTierLookup('fresh')).toBe(false);
    expect(needsAdminTierLookup('stale')).toBe(true);
    expect(needsAdminTierLookup('missing')).toBe(true);
    expect(needsAdminTierLookup('invalid')).toBe(true);
  });
});
