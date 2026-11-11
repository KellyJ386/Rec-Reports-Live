import { generateRequestDetails } from 'web-push';
import type { PushSender, VapidConfig } from './channels/push';

/** Carries the HTTP status of a refusal, so the push channel can tell a gone device (404/410). */
export class PushHttpError extends Error {
  readonly statusCode: number;
  constructor(statusCode: number) {
    super(`push service answered ${statusCode}`);
    this.name = 'PushHttpError';
    this.statusCode = statusCode;
  }
}

/**
 * The real PushSender. `web-push` encrypts the payload and signs the VAPID header
 * (`generateRequestDetails`); the HTTP request is made here with `fetch` and an AbortSignal, so
 * a slow push service is really cancelled at the timeout (the library's own `timeout` option only
 * covers an idle socket). VAPID details are passed per call (no global state). The response body
 * is never read or logged.
 */
export function createWebPushSender(
  vapid: VapidConfig,
  fetchImpl: typeof fetch = fetch,
): PushSender {
  return async (target, payload, options) => {
    const details = generateRequestDetails(
      { endpoint: target.endpoint, keys: { p256dh: target.p256dh, auth: target.authSecret } },
      payload,
      { vapidDetails: vapid, TTL: options.ttlSeconds, urgency: options.urgency },
    );
    const response = await fetchImpl(details.endpoint, {
      method: details.method,
      headers: details.headers,
      body: new Uint8Array(details.body),
      signal: AbortSignal.timeout(options.timeoutMs),
      cache: 'no-store',
      redirect: 'error',
    });
    await response.body?.cancel().catch(() => undefined);
    if (response.status < 200 || response.status > 299) throw new PushHttpError(response.status);
  };
}
