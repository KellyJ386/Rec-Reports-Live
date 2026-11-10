import { describe, expect, it } from 'vitest';
import { safeNextPath } from './redirect';

describe('safeNextPath', () => {
  it('keeps same-origin relative paths with query and hash', () => {
    expect(safeNextPath('/app/tasks?x=1#top')).toBe('/app/tasks?x=1#top');
    expect(safeNextPath('/reset-password', '/x')).toBe('/reset-password');
  });
  it.each([
    'https://evil.example/app',
    '//evil.example',
    '/\\evil.example',
    '\\\\evil.example',
    'javascript:alert(1)',
    'app/tasks',
    '',
    '/app\r\nSet-Cookie: a=b',
    '/\t/evil.example',
    '///evil.example',
    '/' + 'a'.repeat(3000),
  ])('rejects %j', (bad) => {
    expect(safeNextPath(bad)).toBe('/app');
  });
  it('falls back for null and undefined, honouring a custom fallback', () => {
    expect(safeNextPath(null)).toBe('/app');
    expect(safeNextPath(undefined, '/reset-password')).toBe('/reset-password');
  });
});
