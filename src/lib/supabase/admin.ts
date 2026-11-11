import 'server-only';
import { createClient } from '@supabase/supabase-js';
import type { Database } from './database.types';
import { getAdminEnv } from '@/lib/env';

/**
 * Service-role client. It bypasses RLS.
 *
 * For job workers (outbox drain, cron) and admin provisioning ONLY. Never use
 * it in a request handler that acts for a user: use ./server.ts so RLS applies.
 * See docs/ARCHITECTURE.md and docs/SECURITY.md.
 */
export function createAdminClient() {
  // Only the two values it needs, so an unrelated missing setting (SITE_URL, a cron secret)
  // cannot make this client, and so the rate limiter and sign-in, fail.
  const env = getAdminEnv();
  return createClient<Database>(env.NEXT_PUBLIC_SUPABASE_URL, env.SUPABASE_SERVICE_ROLE_KEY, {
    auth: { autoRefreshToken: false, persistSession: false },
  });
}
