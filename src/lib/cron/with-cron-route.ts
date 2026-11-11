import { verifyCronAuth } from './auth';
import { consoleLogger, errorClass, type Logger } from './error-class';

/** What a job reports back: counts only. No ids, payloads or personal data. */
export type CronSummary = Record<string, number | boolean>;

export interface CronRouteOptions {
  /** Test seam. Defaults to process.env.CRON_SECRET, read on every call. */
  getSecret?: () => string | undefined;
  log?: Logger;
}

const NO_STORE = { 'Cache-Control': 'no-store, max-age=0' } as const;

function json(body: Record<string, unknown>, status: number): Response {
  return Response.json(body, { status, headers: NO_STORE });
}

/**
 * Wraps a cron job as a GET route handler. GET only (Vercel Cron sends GET), never cached,
 * and 401 unless the bearer secret matches. The response is a small JSON object of counts; a
 * failing job answers 500 with an error class, never a message.
 *
 *   export const GET = withCronRoute('drain-outbox', async () => ({ claimed: 3 }));
 */
export function withCronRoute(
  name: string,
  job: () => Promise<CronSummary>,
  options: CronRouteOptions = {},
): (request: Request) => Promise<Response> {
  const log = options.log ?? consoleLogger;
  const getSecret = options.getSecret ?? (() => process.env.CRON_SECRET);

  return async function handler(request: Request): Promise<Response> {
    const secret = getSecret();
    if (!secret) {
      // Refuse, and say why in our own log only (the caller learns nothing about config).
      log({ event: 'cron.refused', job: name, reason: 'secret_not_configured' });
      return json({ error: 'unauthorized' }, 401);
    }
    if (!verifyCronAuth(request.headers.get('authorization'), secret)) {
      log({ event: 'cron.refused', job: name, reason: 'bad_credentials' });
      return json({ error: 'unauthorized' }, 401);
    }

    const started = Date.now();
    try {
      const summary = await job();
      const durationMs = Date.now() - started;
      log({ event: 'cron.done', job: name, durationMs, ...summary });
      return json({ ok: true, job: name, durationMs, ...summary }, 200);
    } catch (error) {
      const cls = errorClass(error);
      log({ event: 'cron.failed', job: name, errorClass: cls, durationMs: Date.now() - started });
      return json({ ok: false, job: name, error: cls }, 500);
    }
  };
}
