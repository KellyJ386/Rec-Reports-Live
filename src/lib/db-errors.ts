// Plain-language mapping of database refusals. Pure: no Supabase imports, so it is unit tested.
// The database is the authority (RLS, triggers, constraints). When it says no, the user gets a
// short sentence here, never the raw SQL error.

export type DbErrorLike = {
  code?: string | null;
  message?: string | null;
  details?: string | null;
  hint?: string | null;
  /** HTTP status, when the caller has it (PostgREST answers 429 for a rate limit). */
  status?: number | null;
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

export const TOO_FAST_ERROR = "You're doing that too fast. Wait a minute and try again.";
export const GENERIC_ERROR = 'Something went wrong. Try again.';
export const DENIED_ERROR = 'You are not allowed to do that.';
export const NO_CHANGE_ERROR =
  'Nothing was changed. It may have been removed, or you may not be allowed to change it.';

// Trigger messages raised by our migrations, matched by a lowercase fragment.
const TRIGGER_MESSAGES: ReadonlyArray<readonly [string, string]> = [
  // Staff scheduling texts that contain a shorter older fragment ("cannot be changed", "note is
  // too long") come first.
  ['a cancelled shift cannot be', 'A cancelled shift cannot be changed.'],
  ['the note is too long', 'That note is too long. Keep it under 500 characters.'],
  ['the reason is too long', 'That reason is too long. Keep it under 500 characters.'],
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
  // Review fixes (20261112000600). The rate limit is matched before the codes below.
  ['slow down', TOO_FAST_ERROR],
  ['invalid due time', 'That due time is not valid. Pick a real date and time.'],
  ['invalid publish time', 'That publish time is not valid. Pick a real date and time.'],
  ['this push service is not supported', "This device's push service is not supported."],
  [
    'event chain is too deep',
    'That rule would trigger too many tasks in a row, so it was stopped.',
  ],
  ['finite_', 'That date or time is not valid. Pick a real one.'],
  [
    'rules can be on for one kind of event',
    'There are already 20 rules turned on for that event. Turn one off first.',
  ],
  [
    'a rule for overdue tasks needs a template',
    'A rule for overdue tasks needs a task template that is due at least 1 minute later.',
  ],
  [
    'a rule for overdue tasks uses this template',
    'A rule for overdue tasks uses this template, so it must be due at least 1 minute later.',
  ],
  ['retried too many times', 'That job was already retried 3 times. Ask support for help.'],

  // Staff scheduling (20261113000100, 20261113000200). Rule refusals first: their messages are stable.
  [
    'you cannot override the rules for yourself',
    'You cannot override the rules for yourself. Ask another schedule admin.',
  ],
  ['you cannot take this shift', 'You cannot take this shift.'],
  [
    'a schedule holds at most 2000 shifts',
    'That week already has the most shifts it can hold (2000). Remove some first.',
  ],
  ['that person cannot work at this location', 'That person cannot work at this location.'],
  ['that person already has a shift at that time', 'That person already has a shift at that time.'],
  ['that person has approved time off then', 'That person has approved time off then.'],
  [
    'that person is missing a required qualification',
    'That person is missing a required qualification.',
  ],
  ['only a schedule admin can override', 'Only a schedule admin can assign anyway.'],
  ['you cannot decide your own', 'You cannot decide your own request.'],
  ['you cannot change your own qualifications', 'You cannot change your own qualifications.'],
  ['you cannot swap with that person', 'You cannot swap with that person.'],
  [
    'the shift changed since the swap was offered',
    'The shift changed after the swap was offered. Start again.',
  ],
  [
    'changed since the drop was requested',
    'The shift changed after the drop was requested. Start again.',
  ],
  ['this shift is no longer open', 'Someone else already took this shift.'],
  [
    'that person has shifts on those days',
    'That person has shifts on those days. Give those shifts to someone else first.',
  ],
  [
    'another schedule already covers part of that week',
    'Another schedule already covers part of that week.',
  ],
  ['a week must start on', "A week must start on the organization's first day of the week."],
  ['invalid week', 'Pick a real week.'],
  ['a shift needs a start and an end', 'A shift needs a start and an end.'],
  [
    'a shift ends after it starts and lasts at most 24 hours',
    'A shift must end after it starts and last at most 24 hours.',
  ],
  ['the shift must start during the schedule week', 'The shift must start during that week.'],
  ['unknown position at this location', 'That position is not available at this location.'],
  ['notes are too long', 'Those notes are too long. Keep them under 1000 characters.'],
  ['a name needs 1 to 100 characters', 'A name needs 1 to 100 characters.'],
  ['a position with that name already exists', 'A position with that name already exists.'],
  [
    'a qualification with that name already exists',
    'A qualification with that name already exists.',
  ],
  ['unknown qualification', 'That qualification is not available.'],
  ['at most 20 qualifications', 'A position can need at most 20 qualifications.'],
  [
    'a position still requires this qualification',
    'A position still needs this qualification. Change the position first.',
  ],
  ['the location of a position cannot change', 'The location of a position cannot change.'],
  ['a template covers 1 day or 7 days', 'A template covers 1 day or 7 days.'],
  ['the length of a template cannot change', 'The length of a template cannot change.'],
  ['that day is outside the template', 'That day is outside the template.'],
  ['that day is outside the week', 'That day is outside the week.'],
  [
    'a shift needs a start time and 15 minutes to 24 hours',
    'A shift needs a start time and 15 minutes to 24 hours.',
  ],
  ['a template holds at most 200 shifts', 'A template holds at most 200 shifts.'],
  ['that template belongs to another location', 'That template belongs to another location.'],
  ['that template is archived', 'That template is archived, so a rule cannot use it.'],
  [
    'a template can only be added to a draft schedule',
    'A template can only be added to a draft schedule.',
  ],
  ['this schedule is already published', 'This schedule is already published.'],
  ['this shift is already cancelled', 'This shift is already cancelled.'],
  ['this shift cannot be swapped now', 'This shift cannot be swapped now.'],
  ['this shift cannot be dropped now', 'This shift cannot be dropped now.'],
  ['that shift cannot be part of this swap', 'That shift cannot be part of this swap.'],
  ['this shift already has an open swap or drop', 'This shift already has an open swap or drop.'],
  ['this swap is no longer open', 'This swap is no longer open.'],
  ['this request is not waiting for a decision', 'This request is not waiting for a decision.'],
  ['this request is already closed', 'This request is already closed.'],
  ['you already asked for this shift', 'You already asked for this shift.'],
  ['accept or decline', 'Choose accept or decline.'],
  ['approve or deny', 'Choose approve or deny.'],
  ['invalid day', 'Pick a day of the week.'],
  ['invalid kind', 'Pick a kind from the list.'],
  ['invalid dates', 'Those dates are not valid.'],
  ['the end must be after the start', 'The end must be after the start.'],
  ['at most 100 availability windows', 'You can save at most 100 availability times.'],
  [
    'choose a first and last day, at most a year apart',
    'Choose a first and last day, at most a year apart.',
  ],
  ['those days are too far in the past or future', 'Those days are too far in the past or future.'],
  ['this request can no longer be cancelled', 'This request can no longer be cancelled.'],
];

const RULE_DETAIL_TEXT: Readonly<Record<string, string>> = {
  not_member: 'That person cannot work at this location.',
  overlap: 'That person already has a shift at that time.',
  time_off: 'That person has approved time off then.',
  qualification: 'That person is missing a required qualification.',
  stale: 'That changed while you were looking. Reload and try again.',
  unavailable: 'You cannot take this shift.',
  too_many_shifts: 'That week already has the most shifts it can hold (2000). Remove some first.',
  has_shifts: 'That person has shifts on those days. Give those shifts to someone else first.',
};

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
  // A 23514 from the schedule rules carries the rule code in DETAIL.
  if (code === '23514') {
    const rule = RULE_DETAIL_TEXT[(error.details ?? '').trim()];
    if (rule) return rule;
  }
  if (code === 'PT429' || code === '429' || error.status === 429) return TOO_FAST_ERROR;
  if (code === '54000') return 'That is over the limit. Remove something and try again.';
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
