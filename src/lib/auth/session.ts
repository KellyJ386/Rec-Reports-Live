import 'server-only';
import { cache } from 'react';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import { z } from 'zod';
import { createClient } from '@/lib/supabase/server';
import {
  accountRowSchema,
  assignmentRowSchema,
  buildSessionContext,
  locationRowSchema,
  orgRowSchema,
  roleRowSchema,
  type Membership,
  type SessionContext,
} from './context';
import { hasRecentAuthentication } from './recent-auth';
import { ACTIVE_ORG_COOKIE, selectActiveOrganization } from './active-org';
import { enforceIdleTimeout } from './activity-server';
import { getMfaState } from './mfa-server';

export type AuthUser = { id: string; email: string | null };

function fail(what: string, error: { code?: string } | null): never {
  // Log the failing step and code only: never row data or user input.
  console.error(`auth: ${what} failed`, error?.code ?? '');
  throw new Error(`auth: ${what} failed`);
}

/**
 * The signed-in user, or a redirect to /sign-in. Uses auth.getUser(), which
 * asks the Supabase Auth server to validate the session (so a revoked session
 * is rejected), not just the local cookie. Cached per request.
 */
export const requireUser = cache(async (): Promise<AuthUser> => {
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getUser();
  if (error || !data.user) redirect('/sign-in');
  // Admin-tier sessions that have been idle for 30 minutes end here (the proxy normally does
  // it first). May redirect.
  await enforceIdleTimeout(supabase, data.user.id);
  return { id: data.user.id, email: data.user.email ?? null };
});

/**
 * For /reset-password: the caller has a validated session that came from a recovery link or a
 * recent sign-in (the JWT's `amr` claim, checked by getClaims), else a redirect to
 * /forgot-password. Not cached: the action calls it again.
 */
export async function requireRecentAuthentication(): Promise<AuthUser> {
  const user = await requireUser();
  const supabase = await createClient();
  const { data, error } = await supabase.auth.getClaims();
  if (error || !hasRecentAuthentication(data?.claims, Math.floor(Date.now() / 1000))) {
    redirect('/forgot-password');
  }
  return user;
}

/**
 * Who the caller is and what they hold, read from the database through the
 * caller's own session (RLS applies; no service-role client). Cached per request.
 */
export const getSessionContext = cache(async (): Promise<SessionContext> => {
  const user = await requireUser();
  const supabase = await createClient();

  const [mfa, adminRes, orgIdsRes, accountsRes] = await Promise.all([
    getMfaState(),
    supabase.rpc('is_platform_admin'),
    supabase.rpc('auth_org_ids'),
    supabase
      .from('accounts')
      .select('organization_id, person_id')
      .eq('user_id', user.id)
      .is('disabled_at', null),
  ]);
  if (adminRes.error) fail('is_platform_admin', adminRes.error);
  if (orgIdsRes.error) fail('auth_org_ids', orgIdsRes.error);
  if (accountsRes.error) fail('accounts', accountsRes.error);

  const isPlatformAdmin = adminRes.data === true;
  const memberOrgIds = z.array(z.guid()).parse(orgIdsRes.data ?? []);
  const accounts = z.array(accountRowSchema).parse(accountsRes.data ?? []);
  const personIds = accounts.map((a) => a.person_id);

  const [orgsRes, assignmentsRes] = await Promise.all([
    memberOrgIds.length
      ? supabase.from('organizations').select('id, name').in('id', memberOrgIds)
      : Promise.resolve({ data: [], error: null }),
    personIds.length
      ? supabase
          .from('role_assignments')
          .select('organization_id, person_id, role_id, location_id')
          .in('person_id', personIds)
      : Promise.resolve({ data: [], error: null }),
  ]);
  if (orgsRes.error) fail('organizations', orgsRes.error);
  if (assignmentsRes.error) fail('role_assignments', assignmentsRes.error);

  const assignments = z.array(assignmentRowSchema).parse(assignmentsRes.data ?? []);
  const roleIds = [...new Set(assignments.map((a) => a.role_id))];
  const locationIds = [
    ...new Set(assignments.flatMap((a) => (a.location_id ? [a.location_id] : []))),
  ];

  const [rolesRes, locationsRes] = await Promise.all([
    roleIds.length
      ? supabase.from('roles').select('id, key, name, rank, archived_at').in('id', roleIds)
      : Promise.resolve({ data: [], error: null }),
    locationIds.length
      ? supabase.from('locations').select('id, name, archived_at').in('id', locationIds)
      : Promise.resolve({ data: [], error: null }),
  ]);
  if (rolesRes.error) fail('roles', rolesRes.error);
  if (locationsRes.error) fail('locations', locationsRes.error);

  return buildSessionContext({
    user,
    isPlatformAdmin,
    aal: mfa.aal,
    needsMfa: mfa.needsMfa,
    mfaStep: mfa.step,
    memberOrgIds,
    organizations: z.array(orgRowSchema).parse(orgsRes.data ?? []),
    accounts,
    assignments,
    roles: z.array(roleRowSchema).parse(rolesRes.data ?? []),
    locations: z.array(locationRowSchema).parse(locationsRes.data ?? []),
  });
});

/**
 * The organization the user is working in. The cookie is a preference only;
 * it is re-checked against the real memberships on every call. Null when the
 * user has several memberships and no valid choice yet (or none at all).
 */
export const getActiveOrganization = cache(async (): Promise<Membership | null> => {
  const ctx = await getSessionContext();
  const jar = await cookies();
  return selectActiveOrganization(ctx.memberships, jar.get(ACTIVE_ORG_COOKIE)?.value);
});
