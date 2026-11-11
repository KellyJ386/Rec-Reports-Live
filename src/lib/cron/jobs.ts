import 'server-only';
// The composition root of the background worker, and the ONLY place the service-role client is
// created for it (src/lib/admin-client-usage.test.ts allowlists this file). It hands the client
// to the domains' port factories, which call nothing but the service_role worker functions.
// Only src/app/api/cron/** routes may import this file.
import { randomUUID } from 'node:crypto';
import { createAdminClient } from '@/lib/supabase/admin';
import { getDeliveryEnv, getSiteUrl } from '@/lib/env';
import {
  buildHandlerRegistry,
  createOutboxPort,
  createTaskReader,
  createWorkflowPort,
  drainOutbox,
} from '@/domains/workflows';
import {
  createChannels,
  createDeliveryPort,
  createMessageNotifyHandler,
  createNoticeNotifyHandler,
  createNoticeReader,
  createNotificationPort,
  createWebPushSender,
  deliverNotifications,
} from '@/domains/communications';
import {
  DELIVERY_BATCH_SIZE,
  HARD_BUDGET_MS,
  LOCK_SECONDS,
  OUTBOX_BATCH_SIZE,
  OVERDUE_SWEEP_LIMIT,
  SOFT_BUDGET_MS,
} from './budget';
import { resolveDeliveryConfig } from './delivery-config';
import type { CronSummary } from './with-cron-route';

/** A fresh id per run, so every claim can be traced to the run that holds it. */
function workerId(job: string): string {
  return `${job}:${randomUUID()}`;
}

/** Claims outbox events and runs their handlers (rules -> tasks, notifications). */
export async function runDrainOutbox(): Promise<CronSummary> {
  const client = createAdminClient();
  const notifier = createNotificationPort(client);
  const notices = createNoticeReader(client);
  const registry = buildHandlerRegistry({
    workflows: createWorkflowPort(client),
    tasks: createTaskReader(client),
    notifier,
    external: [
      { type: 'notice.published', handler: createNoticeNotifyHandler({ notices, notifier }) },
      { type: 'message.sent', handler: createMessageNotifyHandler({ notifier }) },
    ],
  });
  const summary = await drainOutbox(createOutboxPort(client), registry, {
    workerId: workerId('drain-outbox'),
    softBudgetMs: SOFT_BUDGET_MS,
    hardBudgetMs: HARD_BUDGET_MS,
    batchSize: OUTBOX_BATCH_SIZE,
    lockSeconds: LOCK_SECONDS,
  });
  return { ...summary };
}

/** Sends pending email and push deliveries. */
export async function runDeliverNotifications(): Promise<CronSummary> {
  const client = createAdminClient();
  const port = createDeliveryPort(client);
  const config = resolveDeliveryConfig(getDeliveryEnv(), getSiteUrl());
  const siteUrl = getSiteUrl();
  const channels = createChannels({
    email: { config: config.email, siteUrl, people: port },
    push: {
      vapid: config.vapid,
      siteUrl,
      devices: port,
      // Only called when VAPID is configured; the channel skips otherwise.
      send: config.vapid
        ? createWebPushSender(config.vapid)
        : async () => {
            throw new Error('push is not configured');
          },
    },
  });
  const summary = await deliverNotifications(port, channels, {
    workerId: workerId('deliver-notifications'),
    softBudgetMs: SOFT_BUDGET_MS,
    hardBudgetMs: HARD_BUDGET_MS,
    batchSize: DELIVERY_BATCH_SIZE,
    lockSeconds: LOCK_SECONDS,
  });
  return { ...summary };
}

/** Emits task.overdue once per overdue task (the drain turns those events into notifications). */
export async function runTaskOverdue(): Promise<CronSummary> {
  const emitted =
    await createWorkflowPort(createAdminClient()).emitOverdueEvents(OVERDUE_SWEEP_LIMIT);
  return { emitted };
}
