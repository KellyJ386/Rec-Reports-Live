// Plain-language mapping of database refusals. Pure: no Supabase imports, so it is unit tested.
// The database is the authority (RLS, triggers, constraints). When it says no, the user gets a
// short sentence here, never the raw SQL error.

export type DbErrorLike = {
  code?: string | null;
  message?: string | null;
  details?: string | null;
  hint?: string | null;
};

export type Result<T> = { ok: true; data: T } | { ok: false; message: string };

export type ErrorContext = {
  /** Shown for a unique violation (23505), e.g. "A location with that name already exists." */
  unique?: string;
  /** Shown for a foreign key violation (23503). */
  foreignKey?: string;
  /** Shown when no row matched. */
  notFound?: string;
};

/**
 * Row-level security refuses a role assignment without saying why (several rules can apply),
 * so the admin screens work out the likely reasons themselves and use these sentences.
 */
export const GRANT_EXCEEDS_ERROR =
  "That role includes access you don't have yourself, so you can't give it.";
export const NO_ROLES_YET_ERROR =
  'That person has no roles yet. Only an organization admin can give them their first one.';

export const GENERIC_ERROR = 'Something went wrong. Try again.';
export const DENIED_ERROR = 'You are not allowed to do that.';
export const NO_CHANGE_ERROR =
  'Nothing was changed. It may have been removed, or you may not be allowed to change it.';

// Trigger messages raised by our migrations, matched by a lowercase fragment.
const TRIGGER_MESSAGES: ReadonlyArray<readonly [string, string]> = [
  ['a sub-space cannot have its own', 'A sub-space cannot have sub-spaces of its own.'],
  ['cannot become a sub-space', 'This space has sub-spaces, so it cannot become a sub-space.'],
  ['cannot be changed', 'That field cannot be changed once it is saved.'],
  ['invalid iana time zone', 'Pick a time zone from the list.'],
  [
    'only the admin role can be organization scoped',
    'Only the admin role can cover the whole organization. Pick a location.',
  ],
  ['role is archived', 'That role is archived, so it cannot be given to anyone.'],
  ['role belongs to another organization', 'That role is not available in this organization.'],
  ['super_admin is granted', 'That role cannot be given here.'],
  ['not allowed to give that role', 'You are not allowed to give that role in that place.'],
  ['not allowed to add people', 'You are not allowed to add people here.'],
  // Added with the security review migration (20261111000600); fragments match its texts.
  [
    "remove a person's last role",
    "Only an organization admin can remove a person's last role. Archive the person instead.",
  ],
  [
    'archive or restore a location',
    'Only an organization admin can archive or restore a location.',
  ],
  ['must be given at a location', 'That role must be given at a location. Pick one.'],
  ['role cannot be assigned', 'That role cannot be given here.'],
  ['nothing to change', 'Nothing to change: that is already their role there.'],
  ['not a member of this organization', 'That person is not in this organization.'],
  ['not signed in', 'Your session has expired. Sign in again.'],
  ['organization and role are required', 'Choose a role.'],
  // Phase 2 (tasks, notices, messages, jobs): texts raised by the RPCs and triggers in
  // migrations 20261112000200 to 000500. The two "only a manager" texts come first because
  // they are 42501 errors that would otherwise read as a plain "not allowed".
  [
    'only a manager can assign tasks to others',
    'Only a manager can give a task to someone else. You can keep it for yourself or leave it unassigned.',
  ],
  ['only a manager can reopen a cancelled task', 'Only a manager can reopen a cancelled task.'],
  [
    'that person cannot be given tasks at this location',
    'That person cannot be given tasks at this location.',
  ],
  ['unknown job title', 'That job title is not available.'],
  ['unknown space at this location', 'That space is not at this location.'],
  ['invalid priority', 'Pick a priority from the list.'],
  ['only an open task can be started', 'Only a task that has not been started can be started.'],
  ['this task is already closed', 'This task is already closed.'],
  ['only a closed task can be reopened', 'Only a finished or cancelled task can be reopened.'],
  [
    'a closed task cannot be reassigned',
    'A finished or cancelled task cannot be given to someone else.',
  ],
  ['note is too long', 'That note is too long. Keep it under 2000 characters.'],
  ['reason is too long', 'That reason is too long. Keep it under 2000 characters.'],
  ['a comment needs 1 to 2000 characters', 'A comment needs 1 to 2000 characters.'],
  [
    'that task template belongs to a different location',
    'That task template belongs to a different location.',
  ],
  ['that task template is archived', 'That task template is archived, so a rule cannot use it.'],
  ['choose who the notice is for first', 'Choose who the notice is for first.'],
  ['only a draft can be published', 'Only a draft notice can be published.'],
  [
    'the notice would expire before it is shown',
    'The notice would expire before it is shown. Pick a later expiry.',
  ],
  ['this notice is already archived', 'This notice is already archived.'],
  ['choose 1 to 50 people', 'Choose 1 to 50 people.'],
  ['a message needs 1 to 4000 characters', 'A message needs 1 to 4000 characters.'],
  [
    'you cannot message one or more of these people',
    'You cannot message one or more of those people.',
  ],
  ['only failed events can be retried', 'Only a failed job can be retried.'],
  ['too many at once', 'Too many at once. Try fewer.'],
];

export function mapDbError(
  error: DbErrorLike | null | undefined,
  context: ErrorContext = {},
): string {
  if (!error) return GENERIC_ERROR;
  const message = (error.message ?? '').toLowerCase();
  const code = error.code ?? '';

  for (const [fragment, text] of TRIGGER_MESSAGES) {
    if (message.includes(fragment)) return text;
  }
  if (code === '42501' || message.includes('row-level security')) return DENIED_ERROR;
  switch (code) {
    case '23505':
      return context.unique ?? 'That already exists.';
    case '23503':
      return context.foreignKey ?? 'That is missing, or it is still in use.';
    case '23514':
      return 'One of the values is not allowed.';
    case '23502':
      return 'A required value is missing.';
    case '22P02':
    case '22007':
    case '22008':
    case '22003':
    case '22023':
    case '22001':
      return 'A value is not in the right format.';
    case 'PGRST116':
      return context.notFound ?? 'That could not be found.';
    case 'PGRST301':
    case 'PGRST303':
      return 'Your session has expired. Sign in again.';
    default:
      return GENERIC_ERROR;
  }
}

export function ok<T>(data: T): Result<T> {
  return { ok: true, data };
}

/** A failed Result for a database error. Logs only the error code, never row data. */
export function failure(
  error: DbErrorLike | null | undefined,
  context: ErrorContext = {},
): { ok: false; message: string } {
  const text = mapDbError(error, context);
  if (text === GENERIC_ERROR) console.error('database error', error?.code ?? '');
  return { ok: false, message: text };
}

export function fail(message: string): { ok: false; message: string } {
  return { ok: false, message };
}

/**
 * Turns the rows a write returned into a Result. A write that touched zero rows is a
 * failure: RLS hides rows it refuses, so "0 rows" is how a refusal looks.
 */
export function requireChanged<T>(
  rows: readonly T[] | null | undefined,
  message: string = NO_CHANGE_ERROR,
): Result<number> {
  if (!rows || rows.length === 0) return fail(message);
  return ok(rows.length);
}
