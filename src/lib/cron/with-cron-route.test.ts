import { describe, expect, it, vi } from 'vitest';
import { verifyCronAuth } from './auth';
import { withCronRoute } from './with-cron-route';

const SECRET = 'a-long-random-test-secret-value-0123456789';
const request = (authorization?: string) =>
  new Request('http://localhost/api/cron/x', {
    headers: authorization === undefined ? {} : { authorization },
  });

describe('verifyCronAuth', () => {
  it('accepts exactly the bearer secret', () => {
    expect(verifyCronAuth(`Bearer ${SECRET}`, SECRET)).toBe(true);
  });
  it('refuses a missing header, a wrong secret, a wrong scheme and near misses', () => {
    expect(verifyCronAuth(null, SECRET)).toBe(false);
    expect(verifyCronAuth('Bearer nope', SECRET)).toBe(false);
    expect(verifyCronAuth(SECRET, SECRET)).toBe(false);
    expect(verifyCronAuth(`Basic ${SECRET}`, SECRET)).toBe(false);
    expect(verifyCronAuth(`Bearer ${SECRET} `, SECRET)).toBe(false);
    expect(verifyCronAuth(`Bearer ${SECRET.slice(0, -1)}`, SECRET)).toBe(false);
    expect(verifyCronAuth('Bearer ', SECRET)).toBe(false);
  });
  it('fails closed when the secret is unset or empty, even for an empty bearer', () => {
    expect(verifyCronAuth(`Bearer ${SECRET}`, undefined)).toBe(false);
    expect(verifyCronAuth(`Bearer ${SECRET}`, '')).toBe(false);
    expect(verifyCronAuth('Bearer ', '')).toBe(false);
  });
  it('refuses a secret shorter than 32 characters, even when it matches', () => {
    const short = 'x'.repeat(31);
    expect(verifyCronAuth(`Bearer ${short}`, short)).toBe(false);
    const ok = 'x'.repeat(32);
    expect(verifyCronAuth(`Bearer ${ok}`, ok)).toBe(true);
  });
});

describe('withCronRoute', () => {
  const quiet = () => undefined;

  it('answers 401 and never runs the job without the header or with a wrong secret', async () => {
    const job = vi.fn(async () => ({ n: 1 }));
    const route = withCronRoute('t', job, { getSecret: () => SECRET, log: quiet });
    for (const header of [undefined, 'Bearer wrong', 'Bearer ']) {
      const res = await route(request(header));
      expect(res.status).toBe(401);
      expect(await res.json()).toEqual({ error: 'unauthorized' });
      expect(res.headers.get('cache-control')).toContain('no-store');
    }
    expect(job).not.toHaveBeenCalled();
  });

  it('refuses everything when CRON_SECRET is not set', async () => {
    const job = vi.fn(async () => ({ n: 1 }));
    const route = withCronRoute('t', job, { getSecret: () => undefined, log: quiet });
    expect((await route(request(`Bearer ${SECRET}`))).status).toBe(401);
    expect((await route(request('Bearer '))).status).toBe(401);
    expect(job).not.toHaveBeenCalled();
  });

  it('runs the job with the right secret and returns counts only, uncached', async () => {
    const route = withCronRoute('t', async () => ({ claimed: 3, budgetExhausted: false }), {
      getSecret: () => SECRET,
      log: quiet,
    });
    const res = await route(request(`Bearer ${SECRET}`));
    expect(res.status).toBe(200);
    expect(res.headers.get('cache-control')).toContain('no-store');
    expect(await res.json()).toMatchObject({
      ok: true,
      job: 't',
      claimed: 3,
      budgetExhausted: false,
    });
  });

  it('turns a failing job into a 500 with an error class, never the message', async () => {
    const logs: unknown[] = [];
    const route = withCronRoute(
      't',
      async () => {
        throw Object.assign(new Error('secret person@example.com in message'), { code: '42501' });
      },
      { getSecret: () => SECRET, log: (r) => logs.push(r) },
    );
    const res = await route(request(`Bearer ${SECRET}`));
    expect(res.status).toBe(500);
    const text = JSON.stringify(await res.json()) + JSON.stringify(logs);
    expect(text).toContain('code_42501');
    expect(text).not.toContain('person@example.com');
  });

  it('never logs the secret or the header', async () => {
    const logs: unknown[] = [];
    const route = withCronRoute('t', async () => ({}), {
      getSecret: () => SECRET,
      log: (r) => logs.push(r),
    });
    await route(request(`Bearer ${SECRET}`));
    await route(request('Bearer wrong-guess'));
    expect(JSON.stringify(logs)).not.toContain(SECRET);
    expect(JSON.stringify(logs)).not.toContain('wrong-guess');
  });
});
