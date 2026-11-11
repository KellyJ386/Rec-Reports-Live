// Architecture guard: the service-role client bypasses RLS, so only an allowlist of files may
// import it (besides its own definition). A new importer fails this test and needs a deliberate
// decision. The background worker creates it in exactly one file (src/lib/cron/jobs.ts) and hands
// it to the domains' worker ports; request handlers acting for a user may not reach the worker.
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

const ALLOWLIST = ['domains/identity/provisioning.ts', 'lib/cron/jobs.ts', 'lib/rate-limit.ts'];

function importersOf(pattern: RegExp): string[] {
  return files(SRC)
    .filter((f) => pattern.test(readFileSync(f, 'utf8')))
    .map((f) => relative(SRC, f).split('\\').join('/'))
    .sort();
}

describe('service-role client usage', () => {
  it('is imported only by the rate limiter, the provisioning module and the cron composition root', () => {
    expect(importers).toEqual(ALLOWLIST);
  });
  it('is never imported under src/app or src/lib/auth', () => {
    expect(importers.filter((f) => f.startsWith('app/') || f.startsWith('lib/auth/'))).toEqual([]);
  });
  it('is not imported dynamically or re-exported anywhere (the allowlist cannot be sidestepped)', () => {
    const loose = importersOf(
      /(import\(\s*['"]@\/lib\/supabase\/admin['"]|export\s[^;]*from\s+['"]@\/lib\/supabase\/admin['"]|require\(\s*['"]@\/lib\/supabase\/admin)/,
    );
    expect(loose).toEqual([]);
  });
  it('the worker composition root (lib/cron/jobs) is imported only by the cron routes', () => {
    const users = importersOf(/from\s+['"]@\/lib\/cron\/jobs['"]/);
    expect(users.length).toBeGreaterThan(0);
    expect(users.filter((f) => !f.startsWith('app/api/cron/'))).toEqual([]);
  });
  it('no request handler acting for a user (pages, actions, experiences, auth) imports anything from lib/cron', () => {
    const users = importersOf(/from\s+['"]@\/lib\/cron\//);
    const forbidden = users.filter(
      (f) =>
        f.startsWith('app/app/') ||
        f.startsWith('experiences/') ||
        f.startsWith('lib/auth/') ||
        (f.startsWith('app/') && !f.startsWith('app/api/cron/')),
    );
    expect(forbidden).toEqual([]);
  });
  it('the worker modules never create a client themselves', () => {
    const makers = importersOf(/createAdminClient|SUPABASE_SERVICE_ROLE_KEY/).filter((f) =>
      /\/worker\//.test(f),
    );
    expect(makers).toEqual([]);
  });
  it('the rate limiter calls nothing but consume_rate_limit', () => {
    const text = readFileSync(join(SRC, 'lib/rate-limit.ts'), 'utf8');
    expect(text.match(/\.rpc\(\s*'([a-z_]+)'/g)).toEqual([".rpc('consume_rate_limit'"]);
    expect(text).not.toMatch(/\.from\(|\.auth\.|\.storage/);
  });
});
