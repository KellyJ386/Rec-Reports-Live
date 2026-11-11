import { consoleLogger, errorClass, type Logger } from '@/lib/cron/error-class';
import type { Delivery, DeliveryChannel, DeliveryPort, SendResult } from './types';

export interface DeliverOptions {
  workerId: string;
  softBudgetMs: number;
  hardBudgetMs: number;
  batchSize: number;
  lockSeconds: number;
  now?: () => number;
  log?: Logger;
}

export interface DeliverSummary {
  claimed: number;
  sent: number;
  skipped: number;
  /** Put back for another try with backoff. */
  retried: number;
  /** Failed for good (permanent error, or the last attempt). */
  failed: number;
  lostClaim: number;
  abandoned: number;
  budgetExhausted: boolean;
}

type ClaimedChannel = 'email' | 'push';
const CLAIM_ORDER: readonly ClaimedChannel[] = ['email', 'push'];

/**
 * Sends the pending email and push deliveries, channel by channel, until none are due or the
 * time budget says stop. Per delivery: read the notification's content (title, summary, link),
 * ask the channel to send, then record the outcome: complete, skip (nothing to send, with a
 * reason), or fail (retry with backoff, or permanent). A delivery whose send throws is retried;
 * one bad delivery never blocks the rest. A crash after a send but before the record repeats the
 * send once the lock expires; the email channel sends an idempotency key so that cannot mail twice.
 */
export async function deliverNotifications(
  port: DeliveryPort,
  channels: Record<ClaimedChannel, DeliveryChannel>,
  options: DeliverOptions,
): Promise<DeliverSummary> {
  const now = options.now ?? Date.now;
  const log = options.log ?? consoleLogger;
  const started = now();
  const summary: DeliverSummary = {
    claimed: 0,
    sent: 0,
    skipped: 0,
    retried: 0,
    failed: 0,
    lostClaim: 0,
    abandoned: 0,
    budgetExhausted: false,
  };
  const exhausted = new Set<ClaimedChannel>();

  while (exhausted.size < CLAIM_ORDER.length) {
    for (const name of CLAIM_ORDER) {
      if (exhausted.has(name)) continue;
      if (now() - started >= options.softBudgetMs) {
        summary.budgetExhausted = true;
        return summary;
      }
      const batch = await port.claim(
        options.workerId,
        options.batchSize,
        options.lockSeconds,
        name,
      );
      summary.claimed += batch.length;
      if (batch.length < options.batchSize) exhausted.add(name);

      for (const [index, delivery] of batch.entries()) {
        if (now() - started >= options.hardBudgetMs) {
          summary.abandoned += batch.length - index;
          summary.budgetExhausted = true;
          return summary;
        }
        await processDelivery(delivery, channels[name], port, options.workerId, summary, log);
      }
    }
  }
  return summary;
}

async function processDelivery(
  delivery: Delivery,
  channel: DeliveryChannel,
  port: DeliveryPort,
  worker: string,
  summary: DeliverSummary,
  log: Logger,
): Promise<void> {
  let result: SendResult;
  try {
    const notification = await port.getNotification(
      delivery.organizationId,
      delivery.notificationId,
    );
    result = notification
      ? await channel.send({ delivery, notification })
      : { outcome: 'skipped', reason: 'notification missing' };
  } catch (error) {
    result = { outcome: 'retry', error: errorClass(error) };
  }

  try {
    if (result.outcome === 'sent') {
      const ok = await port.complete(delivery.id, worker, result.providerMessageId ?? null);
      if (ok) summary.sent += 1;
      else summary.lostClaim += 1;
    } else if (result.outcome === 'skipped') {
      const ok = await port.skip(delivery.id, worker, result.reason);
      if (ok) summary.skipped += 1;
      else summary.lostClaim += 1;
    } else {
      const status = await port.fail(
        delivery.id,
        worker,
        result.error,
        result.outcome === 'failed',
      );
      if (status === 'pending') summary.retried += 1;
      else if (status === 'failed') summary.failed += 1;
      else summary.lostClaim += 1;
      log({
        event: 'delivery.not_sent',
        id: delivery.id,
        channel: delivery.channel,
        outcome: result.outcome,
        errorClass: result.error,
      });
    }
  } catch (error) {
    log({ event: 'delivery.record_failed', id: delivery.id, errorClass: errorClass(error) });
  }
}
