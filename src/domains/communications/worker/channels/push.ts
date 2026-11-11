import { OUTBOUND_TIMEOUT_MS } from '@/lib/cron/budget';
import { buildPushPayload } from '../payloads';
import type { DeliveryChannel, DeliveryPort, PushTarget, SendResult } from '../types';

export interface VapidConfig {
  /** `mailto:` or `https:` contact for the push services. */
  subject: string;
  publicKey: string;
  privateKey: string;
}

export interface PushSendOptions {
  urgency: 'normal' | 'high';
  ttlSeconds: number;
  timeoutMs: number;
}

/** Sends one encrypted push. Throws on any non-2xx; the error carries `statusCode` when there was one. */
export type PushSender = (
  target: PushTarget,
  payload: string,
  options: PushSendOptions,
) => Promise<void>;

export interface PushChannelDeps {
  vapid: VapidConfig | null;
  siteUrl: string;
  devices: Pick<DeliveryPort, 'getPushTargets' | 'disablePushSubscription'>;
  send: PushSender;
  timeoutMs?: number;
}

/** Rejects when `promise` takes longer than `ms` (the push library only times out an idle socket). */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error('push timeout')), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

/** A notice that is stale after a day is not worth delivering on a phone that was off. */
const TTL_SECONDS = 24 * 60 * 60;

function statusOf(error: unknown): number | null {
  if (typeof error === 'object' && error !== null) {
    const status = (error as { statusCode?: unknown }).statusCode;
    if (typeof status === 'number') return status;
  }
  return null;
}

/**
 * Web push. One delivery row covers all of a person's devices:
 *  - sent to at least one device: sent (the others that failed are not retried, so nobody gets
 *    the same push twice);
 *  - 404/410 from a push service means the subscription is gone: `disable_push_subscription`,
 *    and if that was every device the delivery fails for good;
 *  - any other error on every device: retry later.
 * With no VAPID keys configured the channel skips.
 */
export function createPushChannel(deps: PushChannelDeps): DeliveryChannel {
  const timeoutMs = deps.timeoutMs ?? OUTBOUND_TIMEOUT_MS;

  return {
    channel: 'push',
    async send({ delivery, notification }): Promise<SendResult> {
      if (!deps.vapid) return { outcome: 'skipped', reason: 'push not configured' };

      const targets = await deps.devices.getPushTargets(delivery.id);
      if (targets.length === 0) return { outcome: 'skipped', reason: 'no push device' };

      const payload = JSON.stringify(buildPushPayload(notification, deps.siteUrl));
      const options: PushSendOptions = {
        urgency: notification.urgency === 'normal' ? 'normal' : 'high',
        ttlSeconds: TTL_SECONDS,
        timeoutMs,
      };

      // In parallel, so one slow device cannot use up the time budget (each call has a timeout).
      const results = await Promise.all(
        targets.map(async (target) => {
          try {
            await withTimeout(deps.send(target, payload, options), timeoutMs);
            return 'sent' as const;
          } catch (error) {
            const status = statusOf(error);
            if (status === 404 || status === 410) {
              try {
                await deps.devices.disablePushSubscription(target.id);
              } catch {
                // Disabling is housekeeping; the next 410 will try again.
              }
              return 'gone' as const;
            }
            return 'error' as const;
          }
        }),
      );

      if (results.includes('sent')) return { outcome: 'sent' };
      if (results.includes('error')) return { outcome: 'retry', error: 'push_error' };
      return { outcome: 'failed', error: 'push_subscription_gone' };
    },
  };
}
