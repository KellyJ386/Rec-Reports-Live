import { withCronRoute } from '@/lib/cron/with-cron-route';
import { runUncoveredShifts } from '@/lib/cron/jobs';

export const runtime = 'nodejs';
export const maxDuration = 60;

export const GET = withCronRoute('uncovered-shifts', runUncoveredShifts);
