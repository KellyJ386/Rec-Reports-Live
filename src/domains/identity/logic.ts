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

// ---- inviting people (login accounts) ----

export type AccountState = 'none' | 'active' | 'disabled';

/** What the Login section of a person's page offers. Archived people get nothing. */
export type InviteView = 'archived' | 'no_email' | 'can_invite' | 'can_resend' | 'disabled';

export function inviteView(input: {
  archived: boolean;
  email: string | null | undefined;
  account: AccountState;
}): InviteView {
  if (input.archived) return 'archived';
  if (input.account === 'disabled') return 'disabled';
  if (input.account === 'active') return 'can_resend';
  return input.email && input.email.trim() !== '' ? 'can_invite' : 'no_email';
}

export const INVITE_EXISTS_MESSAGE =
  'That email already has a login. Ask a platform admin to link it.';
export const INVITE_RATE_LIMITED_MESSAGE =
  'Too many emails were sent to that address. Try again later.';
export const INVITE_BAD_EMAIL_MESSAGE =
  'That email address does not look right. Fix it and try again.';
export const INVITE_UNAVAILABLE_MESSAGE =
  'Could not send the invite right now. Try again in a moment.';
export const INVITE_ACCEPTED_MESSAGE = 'They have already accepted the invite.';
export const INVITE_EMAIL_CHANGED_MESSAGE =
  'The email on this person changed after the invite. Ask a platform admin to fix the login.';
export const INVITE_NOT_ALLOWED_MESSAGE = 'You are not allowed to create a login for this person.';

export const INVITE_NOT_LINKED_MESSAGE = 'Invite sent but not linked. Try again.';

/**
 * After the accounts insert fails: may this call delete the auth user it just got back from
 * inviteUserByEmail? Only a user this call created, and only while nothing points at it.
 * `accounts.user_id` cascades from auth.users, so deleting a user that another organization
 * linked in the meantime would delete THEIR login. So all of these must hold:
 * - the user was created after this call began (a user that existed before is not ours);
 * - it has never been confirmed or signed in;
 * - a fresh read, taken immediately before deleting, found no account row for it.
 * `linkedAccountCount` is null when that fresh read failed: leave the user in place.
 * Anything unparseable counts as "not ours". Pure, so it is unit tested.
 */
export function inviteCleanupDecision(input: {
  userCreatedAt: string | null | undefined;
  callStartedAtMs: number;
  confirmedAt: string | null | undefined;
  lastSignInAt: string | null | undefined;
  linkedAccountCount: number | null;
}): 'delete' | 'leave' {
  if (!input.userCreatedAt) return 'leave';
  const created = Date.parse(input.userCreatedAt);
  if (!Number.isFinite(created) || created <= input.callStartedAtMs) return 'leave';
  if (input.confirmedAt || input.lastSignInAt) return 'leave';
  if (input.linkedAccountCount !== 0) return 'leave';
  return 'delete';
}

export type InviteErrorKind = 'exists' | 'rate_limited' | 'invalid_email' | 'unavailable';

/** Sorts a Supabase Auth admin error into something we can say in a sentence. */
export function classifyInviteError(
  error: { code?: string | null; status?: number | null } | null | undefined,
): InviteErrorKind {
  const code = error?.code ?? '';
  const status = error?.status ?? null;
  if (['email_exists', 'user_already_exists', 'identity_already_exists'].includes(code)) {
    return 'exists';
  }
  if (['over_email_send_rate_limit', 'over_request_rate_limit'].includes(code) || status === 429) {
    return 'rate_limited';
  }
  if (['email_address_invalid', 'validation_failed'].includes(code)) return 'invalid_email';
  return 'unavailable';
}

export function inviteErrorMessage(kind: InviteErrorKind): string {
  switch (kind) {
    case 'exists':
      return INVITE_EXISTS_MESSAGE;
    case 'rate_limited':
      return INVITE_RATE_LIMITED_MESSAGE;
    case 'invalid_email':
      return INVITE_BAD_EMAIL_MESSAGE;
    default:
      return INVITE_UNAVAILABLE_MESSAGE;
  }
}

/**
 * May an invite be sent again to the auth user already linked to this person? Only while they
 * have never accepted it, and only to the address the invite originally went to.
 */
export function reinviteDecision(input: {
  authEmail: string | null | undefined;
  personEmail: string | null | undefined;
  confirmedAt: string | null | undefined;
  lastSignInAt: string | null | undefined;
}): 'ok' | 'accepted' | 'email_changed' {
  if (input.confirmedAt || input.lastSignInAt) return 'accepted';
  const a = (input.authEmail ?? '').trim().toLowerCase();
  const p = (input.personEmail ?? '').trim().toLowerCase();
  return a !== '' && a === p ? 'ok' : 'email_changed';
}

/**
 * A freshly invited auth user may be linked to this person only when it has never been
 * confirmed or signed in AND no account row anywhere already points at it. Anything else is an
 * existing login, and linking it automatically would be an account-takeover path.
 */
export function mayLinkInvitedUser(input: {
  confirmedAt: string | null | undefined;
  lastSignInAt: string | null | undefined;
  linkedAccountPersonIds: readonly string[];
  personId: string;
}): boolean {
  if (input.confirmedAt || input.lastSignInAt) return false;
  return input.linkedAccountPersonIds.every((id) => id === input.personId);
}
