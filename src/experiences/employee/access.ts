import 'server-only';
// What the signed-in person may do on the staff screens under /app. Like the admin access
// file, these checks only choose what to show; every Server Action still calls a require*
// guard and the database (RLS and the RPCs) has the final say.
import { cache } from 'react';
import { redirect } from 'next/navigation';
import { createClient } from '@/lib/supabase/server';
import { getActiveOrganization, redirectIfMfaPending, requireOrgMember } from '@/lib/auth';
import { permissionAnywhere } from '@/experiences/admin/access';
import { listPersonJobTitles } from '@/domains/identity';
import { listAllLocations } from '@/domains/organizations';
import type { PermissionLevelName, TitleScope } from '@/domains/workflows';

export type StaffAccess = {
  /** tasks >= view somewhere: sees "My work". */
  tasks: boolean;
  /** tasks >= edit somewhere: may start work and make a task. */
  tasksEdit: boolean;
  /** communications >= view somewhere: sees notices and messages. */
  comms: boolean;
  /** communications >= edit somewhere: may write messages. */
  commsEdit: boolean;
};

export const getStaffAccess = cache(async (orgId: string): Promise<StaffAccess> => {
  const [tasks, tasksEdit, comms, commsEdit] = await Promise.all([
    permissionAnywhere(orgId, 'tasks', 'view'),
    permissionAnywhere(orgId, 'tasks', 'edit'),
    permissionAnywhere(orgId, 'communications', 'view'),
    permissionAnywhere(orgId, 'communications', 'edit'),
  ]);
  return { tasks, tasksEdit, comms, commsEdit };
});

export type StaffContext = {
  orgId: string;
  orgName: string;
  /** The caller's person in this organization; null for a platform admin with no account here. */
  personId: string | null;
  access: StaffAccess;
};

/** For staff pages: the active organization and the caller's person, or a redirect. */
export async function requireStaffArea(): Promise<StaffContext> {
  await redirectIfMfaPending();
  const active = await getActiveOrganization();
  if (!active) redirect('/app');
  const membership = await requireOrgMember(active.organizationId);
  const access = await getStaffAccess(active.organizationId);
  return {
    orgId: active.organizationId,
    orgName: active.organizationName,
    personId: membership.personId,
    access,
  };
}

/** The caller's job titles as (title, location) pairs; a null location means "everywhere". */
export async function getMyTitleScopes(orgId: string, personId: string): Promise<TitleScope[]> {
  const res = await listPersonJobTitles(orgId, personId);
  if (!res.ok) return [];
  return res.data.map((r) => ({ job_title_id: r.job_title_id, location_id: r.location_id }));
}

export type LocationInfo = { id: string; name: string; timezone: string };

/** Every location (including archived ones, which old tasks may still name) by id. */
export async function getLocationMap(orgId: string): Promise<Map<string, LocationInfo>> {
  const res = await listAllLocations(orgId, { includeArchived: true });
  const rows = res.ok ? res.data : [];
  return new Map(rows.map((l) => [l.id, { id: l.id, name: l.name, timezone: l.timezone }]));
}

const levelAt = cache(async (orgId: string, locationId: string): Promise<PermissionLevelName> => {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('effective_permission', {
    p_organization_id: orgId,
    p_location_id: locationId,
    p_module_key: 'tasks',
  });
  if (error) return 'none';
  return data === 'view' || data === 'edit' || data === 'admin' ? data : 'none';
});

/** The caller's tasks level at each location, asked of the database (cached for the request). */
export async function getTaskLevels(
  orgId: string,
  locationIds: readonly string[],
): Promise<Map<string, PermissionLevelName>> {
  const unique = [...new Set(locationIds)];
  const levels = await Promise.all(unique.map((id) => levelAt(orgId, id)));
  return new Map(unique.map((id, i) => [id, levels[i] ?? 'none']));
}
