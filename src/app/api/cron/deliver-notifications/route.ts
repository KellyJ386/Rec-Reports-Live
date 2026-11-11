import { withCronRoute } from '@/lib/cron/with-cron-route';
import { runDeliverNotifications } from '@/lib/cron/jobs';

// Needs Node (web-push, crypto). Same budgets as drain-outbox (src/lib/cron/budget.ts).
export const runtime = 'nodejs';
export const maxDuration = 60;

export const GET = withCronRoute('deliver-notifications', runDeliverNotifications);
