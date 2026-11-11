import 'server-only';
// The rate limiter. This file is the ONLY place under src/app or src/lib/auth's call tree that
// uses the service-role client, and the only thing it calls is the consume_rate_limit RPC
// (service_role only, so the limiter table cannot be written by a signed-in user).
// An architecture test (admin-client-usage.test.ts) fails if another file imports the client.
import { headers } from 'next/headers';
import { createAdminClient } from '@/lib/supabase/admin';
import { getSessionSecret } from '@/lib/env';
import { FAIL_MODE, RATE_LIMITS, type LimitSet, type RateBucket } from './rate-limit-constants';
import { clientIp, planKeys, runPlan, shouldBlock, type LimitOutcome } from './rate-limit-keys';

async function consume(plan: {
  bucket: string;
  key: string;
  max: number;
  windowSeconds: number;
}): Promise<LimitOutcome> {
  try {
    const { data, error } = await createAdminClient().rpc('consume_rate_limit', {
      p_bucket: plan.bucket,
      p_key: plan.key,
      p_max: plan.max,
      p_window_seconds: plan.windowSeconds,
    });
    if (error) {
      console.error('rate-limit: rpc failed', error.code ?? '');
      return 'error';
    }
    return data === true ? 'allowed' : 'limited';
  } catch (error) {
    console.error('rate-limit: call failed', error instanceof Error ? error.name : '');
    return 'error';
  }
}

/**
 * Counts one attempt against the bucket's limits (email+IP pair, email, IP: tight to loose) and
 * says whether to refuse. Stops at the first limit that refuses, so a blocked attacker does not
 * use up the looser, shared counters (see rate-limit-constants.ts). The email is hashed before
 * it leaves this file.
 * Never throws: a failure becomes the endpoint's fail mode (see FAIL_MODE).
 */
export async function rateLimited(
  bucket: RateBucket,
  subject: { email?: string | null } = {},
): Promise<boolean> {
  const limits: LimitSet = RATE_LIMITS[bucket];
  try {
    const secret = getSessionSecret();
    const plan = planKeys({
      bucket,
      limits,
      email: subject.email,
      ip: clientIp(await headers()),
      secret,
    });
    const outcome = plan.length === 0 ? 'error' : await runPlan(plan, consume);
    return shouldBlock(outcome, FAIL_MODE[bucket]);
  } catch (error) {
    console.error('rate-limit: failed', error instanceof Error ? error.name : '');
    return FAIL_MODE[bucket] === 'closed';
  }
}
