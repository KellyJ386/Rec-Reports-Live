// Looks up whether the signed-in user holds admin-tier access, through their own session (RLS
// applies, no service-role client). Used by the proxy and requireUser, and only when the idle
// stamp is not fresh, so it runs about once per 30 idle minutes, not on every request.
import type { SupabaseClient } from '@supabase/supabase-js';
import type { Database } from '@/lib/supabase/database.types';
import { isAdminTier } from './admin-tier';

/** True / false, or true on any error (fail closed: see idleVerdict). */
export async function loadAdminTier(
  supabase: SupabaseClient<Database>,
  userId: string,
): Promise<boolean> {
  try {
    const [needs, platform, accounts] = await Promise.all([
      supabase.rpc('session_needs_mfa'),
      supabase.rpc('is_platform_admin'),
      supabase.from('accounts').select('person_id').eq('user_id', userId).is('disabled_at', null),
    ]);
    if (needs.error || platform.error || accounts.error) return true;
    if (needs.data === true || platform.data === true) return true;
    const personIds = (accounts.data ?? []).map((a) => a.person_id);
    if (personIds.length === 0) return false;
    const assignments = await supabase
      .from('role_assignments')
      .select('role_id, location_id')
      .in('person_id', personIds);
    if (assignments.error) return true;
    const roleIds = [...new Set((assignments.data ?? []).map((a) => a.role_id))];
    if (roleIds.length === 0) return false;
    const roles = await supabase.from('roles').select('id, rank').in('id', roleIds);
    if (roles.error) return true;
    const rankById = new Map((roles.data ?? []).map((r) => [r.id, r.rank]));
    const ranks = (assignments.data ?? []).flatMap((a) => {
      const base = rankById.get(a.role_id);
      return base === undefined ? [] : [base + (a.location_id === null ? 10 : 0)];
    });
    return isAdminTier({ needsMfa: false, isPlatformAdmin: false, ranks });
  } catch {
    return true;
  }
}
