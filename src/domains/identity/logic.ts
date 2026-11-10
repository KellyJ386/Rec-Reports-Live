// Pure logic for the identity domain. What a person can actually do is decided by the database
// (effective_permission / person_effective_permission); nothing here re-implements those rules.
export type PermissionLevel = 'none' | 'view' | 'edit' | 'admin';

const LEVEL_ORDER: Record<PermissionLevel, number> = { none: 0, view: 1, edit: 2, admin: 3 };

/** True when `level` is higher than `limit` (none < view < edit < admin). */
export function levelExceeds(level: PermissionLevel, limit: PermissionLevel): boolean {
  return LEVEL_ORDER[level] > LEVEL_ORDER[limit];
}

/** Effective rank of one assignment: the role's rank, plus 10 at organization scope. */
export function assignmentRank(roleRank: number, locationId: string | null): number {
  return roleRank + (locationId === null ? 10 : 0);
}

/** Roles that may appear in an "add role" picker: not archived, never super_admin. */
export function assignableRoles<R extends { key: string; archived_at: string | null }>(
  roles: readonly R[],
): R[] {
  return roles.filter((r) => r.key !== 'super_admin' && r.archived_at === null);
}

/** Org scope is allowed only for the system admin role; every other role needs a location. */
export function scopeProblem(
  roleKey: string,
  isSystemRole: boolean,
  locationId: string | null,
): string | null {
  if (locationId === null && !(isSystemRole && roleKey === 'admin')) {
    return 'Only the admin role can cover the whole organization. Pick a location.';
  }
  return null;
}

export function displayName(p: {
  first_name: string;
  last_name: string;
  preferred_name: string | null;
}): string {
  const first = p.preferred_name?.trim() ? p.preferred_name.trim() : p.first_name;
  return `${first} ${p.last_name}`.trim();
}

/**
 * Whether removing assignment `id` would leave the person with no active assignment. An
 * assignment is active when its role is not archived and, if location scoped, its location
 * is not archived.
 */
export function isLastActiveAssignment(
  assignments: ReadonlyArray<{
    id: string;
    location_id: string | null;
    role: { archived_at?: string | null } | null;
  }>,
  id: string,
  archivedLocationIds: ReadonlySet<string>,
): boolean {
  const active = assignments.filter(
    (a) =>
      a.role !== null &&
      !a.role.archived_at &&
      (a.location_id === null || !archivedLocationIds.has(a.location_id)),
  );
  return active.length > 0 && active.every((a) => a.id === id);
}

/** Map key for one cell of the effective-level table: a scope (null = organization) and a module. */
export function effectiveLevelKey(locationId: string | null, moduleKey: string): string {
  return `${locationId ?? 'org'}|${moduleKey}`;
}
