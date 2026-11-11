import 'server-only';
import { cache } from 'react';
import { notFound, redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { getSessionContext } from './session';
import type { Membership } from './context';
import { mfaStepPath } from './mfa';
import {
  guidSchema,
  moduleKeySchema,
  modulePermissionLevels,
  type ModulePermissionLevel,
} from './schemas';

/**
 * Every decision below is made by the database through the caller's own
 * session: auth_org_ids() / has_role() / has_permission() read auth.uid() from
 * the JWT. Arguments are only the question being asked ("may I act in this
 * org/location/module?"), never an identity or a claim. A malformed argument,
 * an RPC error or a "false" all deny (fail closed) with notFound(), which does
 * not reveal whether the organization exists.
 *
 * Two-step sign-in: the database ignores admin-tier access (and a voluntary factor is not yet
 * proven) until the session is aal2. When that is why a person has no access, refusing with
 * a 404 would be a dead end, so requireOrgMember (which every other guard calls first)
 * redirects to the second step instead: /sign-in/verify with a verified factor, /app/security
 * to set one up. This runs before any membership lookup, so it reveals nothing about orgs.
 */

const hasRole = cache(
  async (orgId: string, locationId: string | null, roleKey: string): Promise<boolean> => {
    const supabase = await createClient();
    const { data, error } = await supabase.rpc('has_role', {
      p_organization_id: orgId,
      p_location_id: locationId,
      p_role_key: roleKey,
    });
    if (error) {
      console.error('auth: has_role failed', error.code ?? '');
      return false;
    }
    return data === true;
  },
);

const hasPermission = cache(
  async (
    orgId: string,
    locationId: string | null,
    moduleKey: string,
    level: ModulePermissionLevel,
  ): Promise<boolean> => {
    const supabase = await createClient();
    const { data, error } = await supabase.rpc('has_permission', {
      p_organization_id: orgId,
      p_location_id: locationId,
      p_module_key: moduleKey,
      p_min_level: level,
    });
    if (error) {
      console.error('auth: has_permission failed', error.code ?? '');
      return false;
    }
    return data === true;
  },
);

function validGuid(value: string | null | undefined): value is string {
  return guidSchema.safeParse(value).success;
}

/** The caller is a member of `orgId` (per auth_org_ids()). Returns the membership. */
export async function requireOrgMember(orgId: string): Promise<Membership> {
  if (!validGuid(orgId)) notFound();
  const ctx = await getSessionContext();
  const secondStep = mfaStepPath(ctx.mfaStep);
  if (secondStep) redirect(secondStep);
  const membership = ctx.memberships.find((m) => m.organizationId === orgId);
  if (!membership) notFound();
  return membership;
}

/** Admin of the organization (locationId omitted) or of that location. Platform admins pass. */
export async function requireAdmin(orgId: string, locationId?: string | null): Promise<Membership> {
  const membership = await requireOrgMember(orgId);
  const loc = locationId ?? null;
  if (loc !== null && !validGuid(loc)) notFound();
  if (!(await hasRole(orgId, loc, 'admin'))) notFound();
  return membership;
}

/** The caller holds at least `level` on `moduleKey` in the scope (null location = org scope). */
export async function requireModulePermission(
  orgId: string,
  locationId: string | null,
  moduleKey: string,
  level: ModulePermissionLevel,
): Promise<Membership> {
  const membership = await requireOrgMember(orgId);
  if (
    (locationId !== null && !validGuid(locationId)) ||
    !moduleKeySchema.safeParse(moduleKey).success ||
    !modulePermissionLevels.includes(level)
  ) {
    notFound();
  }
  if (!(await hasPermission(orgId, locationId, moduleKey, level))) notFound();
  return membership;
}

/** Shorthand for level 'admin' on a module. */
export function requireModuleAdmin(
  orgId: string,
  locationId: string | null,
  moduleKey: string,
): Promise<Membership> {
  return requireModulePermission(orgId, locationId, moduleKey, 'admin');
}
