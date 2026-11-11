// Architecture guard: the service-role client bypasses RLS, so only two files may import it
// (besides its own definition). A new importer fails this test and needs a deliberate decision.
import { describe, expect, it } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';

const SRC = join(__dirname, '..');

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return files(full);
    return /\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [full] : [];
  });
}

const importers = files(SRC)
  .filter((f) => /from\s+['"]@\/lib\/supabase\/admin['"]/.test(readFileSync(f, 'utf8')))
  .map((f) => relative(SRC, f).split('\\').join('/'))
  .sort();

describe('service-role client usage', () => {
  it('is imported only by the rate limiter and the provisioning module', () => {
    expect(importers).toEqual(['domains/identity/provisioning.ts', 'lib/rate-limit.ts']);
  });
  it('is never imported under src/app or src/lib/auth', () => {
    expect(importers.filter((f) => f.startsWith('app/') || f.startsWith('lib/auth/'))).toEqual([]);
  });
  it('the rate limiter calls nothing but consume_rate_limit', () => {
    const text = readFileSync(join(SRC, 'lib/rate-limit.ts'), 'utf8');
    expect(text.match(/\.rpc\(\s*'([a-z_]+)'/g)).toEqual([".rpc('consume_rate_limit'"]);
    expect(text).not.toMatch(/\.from\(|\.auth\.|\.storage/);
  });
});
