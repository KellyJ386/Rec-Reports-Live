import { z } from 'zod';
import { isAdminTier } from './admin-tier';
import type { Aal, MfaStep } from './mfa';

const id = z.guid();

export const orgRowSchema = z.object({ id, name: z.string() });
export const accountRowSchema = z.object({ organization_id: id, person_id: id });
export const assignmentRowSchema = z.object({
  organization_id: id,
  person_id: id,
  role_id: id,
  location_id: id.nullable(),
});
export const roleRowSchema = z.object({
  id,
  key: z.string(),
  name: z.string(),
  rank: z.number().int(),
  archived_at: z.string().nullable(),
});
export const locationRowSchema = z.object({
  id,
  name: z.string(),
  archived_at: z.string().nullable(),
});

export type Membership = {
  organizationId: string;
  organizationName: string;
  /** The caller's person in this organization; null for a platform admin with no account there. */
  personId: string | null;
};

export type RoleAssignment = {
  organizationId: string;
  personId: string;
  /** null = organization scope */
  locationId: string | null;
  locationName: string | null;
  roleKey: string;
  roleName: string;
  /** Effective rank: roles.rank, plus 10 at organization scope (docs/SECURITY.md). */
  rank: number;
};

export type SessionContext = {
  userId: string;
  email: string | null;
  isPlatformAdmin: boolean;
  /** The session's assurance level from the verified JWT; null if absent. */
  aal: Aal | null;
  /** The database says this session holds admin-tier access it is ignoring (not aal2). */
  needsMfa: boolean;
  /** Which second-step screen is still owed (code or set-up), or 'none'. */
  mfaStep: MfaStep;
  /** Holds admin-tier access (rank >= 80): two-step sign-in and 30-minute idle sign-out apply. */
  adminTier: boolean;
  memberships: Membership[];
  roleAssignments: RoleAssignment[];
};

export type ContextRows = {
  user: { id: string; email: string | null };
  isPlatformAdmin: boolean;
  aal: Aal | null;
  needsMfa: boolean;
  mfaStep: MfaStep;
  /** Result of public.auth_org_ids(): the database's own list of member organizations. */
  memberOrgIds: readonly string[];
  organizations: readonly z.infer<typeof orgRowSchema>[];
  accounts: readonly z.infer<typeof accountRowSchema>[];
  assignments: readonly z.infer<typeof assignmentRowSchema>[];
  roles: readonly z.infer<typeof roleRowSchema>[];
  locations: readonly z.infer<typeof locationRowSchema>[];
};

/**
 * Pure: turns rows fetched through the user's own session into a SessionContext.
 * Membership comes from the database's auth_org_ids(); this function never
 * grants anything that list did not. Only the caller's own assignments are kept
 * (RLS also shows colleagues' rows), and archived roles/locations are dropped.
 */
export function buildSessionContext(rows: ContextRows): SessionContext {
  const memberIds = new Set(rows.memberOrgIds);
  const personByOrg = new Map(rows.accounts.map((a) => [a.organization_id, a.person_id]));
  const myPersonIds = new Set(rows.accounts.map((a) => a.person_id));
  const rolesById = new Map(rows.roles.map((r) => [r.id, r]));
  const locationsById = new Map(rows.locations.map((l) => [l.id, l]));

  const memberships: Membership[] = rows.organizations
    .filter((o) => memberIds.has(o.id))
    .map((o) => ({
      organizationId: o.id,
      organizationName: o.name,
      personId: personByOrg.get(o.id) ?? null,
    }))
    .sort((a, b) => a.organizationName.localeCompare(b.organizationName));

  const roleAssignments: RoleAssignment[] = [];
  for (const a of rows.assignments) {
    if (!memberIds.has(a.organization_id)) continue;
    if (!myPersonIds.has(a.person_id) || personByOrg.get(a.organization_id) !== a.person_id) {
      continue;
    }
    const role = rolesById.get(a.role_id);
    if (!role || role.archived_at) continue;
    let locationName: string | null = null;
    if (a.location_id) {
      const loc = locationsById.get(a.location_id);
      if (!loc || loc.archived_at) continue;
      locationName = loc.name;
    }
    roleAssignments.push({
      organizationId: a.organization_id,
      personId: a.person_id,
      locationId: a.location_id,
      locationName,
      roleKey: role.key,
      roleName: role.name,
      rank: role.rank + (a.location_id === null ? 10 : 0),
    });
  }
  roleAssignments.sort(
    (a, b) =>
      b.rank - a.rank ||
      (a.locationName ?? '').localeCompare(b.locationName ?? '') ||
      a.roleKey.localeCompare(b.roleKey),
  );

  return {
    userId: rows.user.id,
    email: rows.user.email,
    isPlatformAdmin: rows.isPlatformAdmin,
    aal: rows.aal,
    needsMfa: rows.needsMfa,
    mfaStep: rows.mfaStep,
    adminTier: isAdminTier({
      needsMfa: rows.needsMfa,
      isPlatformAdmin: rows.isPlatformAdmin,
      ranks: roleAssignments.map((a) => a.rank),
    }),
    memberships,
    roleAssignments,
  };
}
