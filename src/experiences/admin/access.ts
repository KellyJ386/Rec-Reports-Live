import 'server-only';
// What the signed-in user may open under /app/admin. Used to choose which links to show and
// to guard each page. These checks ask the database (has_role / has_permission) through the
// user's own session, the same questions the require* guards in src/lib/auth ask, but answer
// true/false so a link can be hidden. Every Server Action still calls a require* guard and
// the database (RLS) has the final say.
import { cache } from 'react';
import { notFound, redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { getActiveOrganization, getSessionContext, requireOrgMember } from '@/lib/auth';
import type { PermissionLevel } from '@/domains/identity';

export type AdminAccess = {
  /** Admin role at organization scope (or platform admin). */
  isOrgAdmin: boolean;
  /** Admin of the organization or of at least one location. */
  canLocations: boolean;
  /** locations_spaces >= edit at organization scope or some location. */
  canSpaces: boolean;
  /** locations_spaces >= edit at organization scope (space kinds). */
  canSpaceKinds: boolean;
  /** people_roles >= edit somewhere (can see people; assign job titles). */
  canPeople: boolean;
  /** people_roles = admin somewhere (add people, change roles and overrides). */
  canPeopleAdmin: boolean;
  /** audit_log >= view somewhere. */
  canAudit: boolean;
};

const hasRole = cache(async (orgId: string, locationId: string | null, role: string) => {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('has_role', {
    p_organization_id: orgId,
    p_location_id: locationId,
    p_role_key: role,
  });
  if (error) return false;
  return data === true;
});

const hasPermission = cache(
  async (orgId: string, locationId: string | null, moduleKey: string, level: PermissionLevel) => {
    const supabase = await createClient();
    const { data, error } = await supabase.rpc('has_permission', {
      p_organization_id: orgId,
      p_location_id: locationId,
      p_module_key: moduleKey,
      p_min_level: level,
    });
    if (error) return false;
    return data === true;
  },
);

async function myLocationIds(orgId: string): Promise<string[]> {
  const ctx = await getSessionContext();
  const ids = ctx.roleAssignments
    .filter((a) => a.organizationId === orgId && a.locationId !== null)
    .map((a) => a.locationId as string);
  return [...new Set(ids)];
}

async function permissionAnywhere(
  orgId: string,
  moduleKey: string,
  level: PermissionLevel,
): Promise<boolean> {
  const locations = await myLocationIds(orgId);
  const checks = [
    hasPermission(orgId, null, moduleKey, level),
    ...locations.map((id) => hasPermission(orgId, id, moduleKey, level)),
  ];
  return (await Promise.all(checks)).some(Boolean);
}

export const getAdminAccess = cache(async (orgId: string): Promise<AdminAccess> => {
  const locations = await myLocationIds(orgId);
  const [isOrgAdmin, locationAdmin, canSpaces, canSpaceKinds, canPeople, canPeopleAdmin, canAudit] =
    await Promise.all([
      hasRole(orgId, null, 'admin'),
      Promise.all(locations.map((id) => hasRole(orgId, id, 'admin'))).then((r) => r.some(Boolean)),
      permissionAnywhere(orgId, 'locations_spaces', 'edit'),
      hasPermission(orgId, null, 'locations_spaces', 'edit'),
      permissionAnywhere(orgId, 'people_roles', 'edit'),
      permissionAnywhere(orgId, 'people_roles', 'admin'),
      permissionAnywhere(orgId, 'audit_log', 'view'),
    ]);
  return {
    isOrgAdmin,
    canLocations: isOrgAdmin || locationAdmin,
    canSpaces,
    canSpaceKinds,
    canPeople,
    canPeopleAdmin,
    canAudit,
  };
});

export type AdminContext = { orgId: string; orgName: string; access: AdminAccess };

/**
 * For pages: the active organization (or back to /app to choose one), the caller's
 * membership, and the access flags. Pass `area` to answer 404 unless that flag is true.
 */
export async function requireAdminArea(area?: keyof AdminAccess): Promise<AdminContext> {
  const active = await getActiveOrganization();
  if (!active) redirect('/app');
  await requireOrgMember(active.organizationId);
  const access = await getAdminAccess(active.organizationId);
  if (area && !access[area]) notFound();
  return { orgId: active.organizationId, orgName: active.organizationName, access };
}

/** For actions that act on a person without a known scope: people_roles = admin somewhere, else 404. */
export async function requirePeopleAdmin(orgId: string): Promise<void> {
  await requireOrgMember(orgId);
  if (!(await getAdminAccess(orgId)).canPeopleAdmin) notFound();
}
