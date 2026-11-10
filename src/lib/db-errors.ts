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
  ['not signed in', 'Your session has expired. Sign in again.'],
  ['organization and role are required', 'Choose a role.'],
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
