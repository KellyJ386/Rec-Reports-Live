import { withCronRoute } from '@/lib/cron/with-cron-route';
import { runDrainOutbox } from '@/lib/cron/jobs';

// Needs Node (service client, crypto). The run stops claiming at 35 s and processing at 45 s
// (src/lib/cron/budget.ts), well inside this limit, so a run never dies mid-batch.
export const runtime = 'nodejs';
export const maxDuration = 60;

export const GET = withCronRoute('drain-outbox', runDrainOutbox);
