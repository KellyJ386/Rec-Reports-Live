// Pure logic for the identity domain. Mirrors the rules in docs/SECURITY.md so the admin
// screens can show what a person's access works out to. The database function
// effective_permission() is the authority; it only answers for the signed-in caller, so for
// another person the screens compute the same rules from rows an admin may read.
export type PermissionLevel = 'none' | 'view' | 'edit' | 'admin';

const ORDER: Record<PermissionLevel, number> = { none: 0, view: 1, edit: 2, admin: 3 };

export function maxLevel(a: PermissionLevel, b: PermissionLevel): PermissionLevel {
  return ORDER[a] >= ORDER[b] ? a : b;
}

export function levelAtLeast(level: PermissionLevel, min: PermissionLevel): boolean {
  return ORDER[level] >= ORDER[min];
}

export type AccessAssignment = { roleId: string; locationId: string | null };
export type AccessOverride = {
  moduleKey: string;
  locationId: string | null;
  level: PermissionLevel;
};
/** roleId -> moduleKey -> default level */
export type RoleDefaults = Readonly<Record<string, Readonly<Record<string, PermissionLevel>>>>;

/**
 * Effective level of one person for a module in a scope (locationId null = organization scope):
 * 1. no assignment covering the scope -> none
 * 2. an override for that module at that location -> its level
 * 3. an override for that module with no location -> its level
 * 4. the highest default among the roles covering the scope; none if there are none
 * An assignment covers organization scope only if it is organization scoped; it covers a
 * location if it is organization scoped or at that location. Platform admins are not modelled.
 */
export function computeEffectiveLevel(
  data: {
    assignments: readonly AccessAssignment[];
    overrides: readonly AccessOverride[];
    defaults: RoleDefaults;
  },
  locationId: string | null,
  moduleKey: string,
): PermissionLevel {
  const covering = data.assignments.filter(
    (a) => a.locationId === null || (locationId !== null && a.locationId === locationId),
  );
  if (covering.length === 0) return 'none';

  const exact = data.overrides.find(
    (o) => o.moduleKey === moduleKey && o.locationId === locationId,
  );
  if (exact) return exact.level;
  const orgWide = data.overrides.find((o) => o.moduleKey === moduleKey && o.locationId === null);
  if (orgWide) return orgWide.level;

  let best: PermissionLevel = 'none';
  for (const a of covering) {
    const level = data.defaults[a.roleId]?.[moduleKey];
    if (level) best = maxLevel(best, level);
  }
  return best;
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
