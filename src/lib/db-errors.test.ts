import { describe, expect, it } from 'vitest';
import {
  DENIED_ERROR,
  GENERIC_ERROR,
  GRANT_EXCEEDS_ERROR,
  NO_CHANGE_ERROR,
  NO_ROLES_YET_ERROR,
  TOO_FAST_ERROR,
  mapDbError,
  requireChanged,
} from './db-errors';

describe('mapDbError', () => {
  it('maps 42501 and RLS messages to a permission message', () => {
    expect(mapDbError({ code: '42501', message: 'x' })).toBe(DENIED_ERROR);
    expect(
      mapDbError({
        code: '42501',
        message: 'new row violates row-level security policy for table "spaces"',
      }),
    ).toBe(DENIED_ERROR);
    expect(mapDbError({ message: 'violates row-level security policy' })).toBe(DENIED_ERROR);
  });

  it('uses the caller context for unique and foreign key violations', () => {
    expect(mapDbError({ code: '23505' }, { unique: 'That name is taken.' })).toBe(
      'That name is taken.',
    );
    expect(mapDbError({ code: '23505' })).toBe('That already exists.');
    expect(mapDbError({ code: '23503' }, { foreignKey: 'In use.' })).toBe('In use.');
    expect(mapDbError({ code: '23503' })).toMatch(/still in use/);
  });

  it('maps known trigger messages even though they arrive as check violations', () => {
    expect(
      mapDbError({ code: '23514', message: 'a sub-space cannot have its own sub-spaces' }),
    ).toBe('A sub-space cannot have sub-spaces of its own.');
    expect(
      mapDbError({
        code: '23514',
        message: 'only the admin role can be organization scoped; manager needs a location',
      }),
    ).toMatch(/Only the admin role/);
    expect(mapDbError({ code: '23514', message: 'role is archived' })).toMatch(/archived/);
    expect(mapDbError({ code: '23514', message: 'locations.timezone cannot be changed' })).toMatch(
      /cannot be changed/,
    );
    expect(mapDbError({ code: '23514', message: 'something else' })).toBe(
      'One of the values is not allowed.',
    );
  });

  it('maps the people RPC refusals', () => {
    expect(
      mapDbError({ code: '42501', message: 'not allowed to give that role in that scope' }),
    ).toMatch(/not allowed to give that role/);
    expect(mapDbError({ code: '42501', message: 'not signed in' })).toMatch(/Sign in again/);
  });

  it('maps the task, notice, message and job refusals', () => {
    expect(
      mapDbError({ code: '42501', message: 'only a manager can assign tasks to others' }),
    ).toMatch(/Only a manager can give a task/);
    expect(mapDbError({ code: '22023', message: 'this task is already closed' })).toBe(
      'This task is already closed.',
    );
    expect(mapDbError({ code: '22023', message: 'only an open task can be started' })).toMatch(
      /can be started/,
    );
    expect(
      mapDbError({ code: '22023', message: 'that person cannot be given tasks at this location' }),
    ).toMatch(/cannot be given tasks/);
    expect(mapDbError({ code: '22023', message: 'choose who the notice is for first' })).toBe(
      'Choose who the notice is for first.',
    );
    expect(
      mapDbError({ code: '22023', message: 'the notice would expire before it is shown' }),
    ).toMatch(/later expiry/);
    expect(
      mapDbError({ code: '42501', message: 'you cannot message one or more of these people' }),
    ).toMatch(/cannot message/);
    expect(mapDbError({ code: '22023', message: 'only failed events can be retried' })).toMatch(
      /failed job/,
    );
    expect(mapDbError({ code: '23514', message: 'that task template is archived' })).toMatch(
      /archived/,
    );
    // A plain refusal still reads as "not allowed".
    expect(mapDbError({ code: '42501', message: 'not allowed' })).toBe(DENIED_ERROR);
  });

  it('never leaks raw SQL text', () => {
    const text = mapDbError({
      code: 'XX000',
      message: 'relation "public.people" does not exist at character 15',
    });
    expect(text).toBe(GENERIC_ERROR);
    expect(text).not.toMatch(/relation|public\./);
    expect(mapDbError(null)).toBe(GENERIC_ERROR);
  });

  it('maps format errors and session expiry', () => {
    expect(mapDbError({ code: '22P02' })).toMatch(/format/);
    expect(mapDbError({ code: 'PGRST301' })).toMatch(/Sign in again/);
    expect(mapDbError({ code: 'PGRST116' }, { notFound: 'Gone.' })).toBe('Gone.');
  });
});

describe('requireChanged', () => {
  it('fails when zero rows changed', () => {
    expect(requireChanged([])).toEqual({ ok: false, message: NO_CHANGE_ERROR });
    expect(requireChanged(null)).toEqual({ ok: false, message: NO_CHANGE_ERROR });
  });
  it('succeeds with the row count', () => {
    expect(requireChanged([{ id: 1 }])).toEqual({ ok: true, data: 1 });
  });
});

describe('mapDbError: security review refusals', () => {
  it('explains the last-role and location archive refusals from the migration', () => {
    expect(
      mapDbError({
        code: '42501',
        message:
          "only an organization admin can remove a person's last role; archive the person instead",
      }),
    ).toMatch(/last role/);
    expect(
      mapDbError({
        code: '42501',
        message: 'only an organization admin can archive or restore a location',
      }),
    ).toBe('Only an organization admin can archive or restore a location.');
  });
  it('explains replace_role_assignment refusals', () => {
    expect(mapDbError({ code: '22023', message: 'nothing to change' })).toMatch(
      /Nothing to change/,
    );
    expect(mapDbError({ code: '23514', message: 'this role must be given at a location' })).toMatch(
      /at a location/,
    );
    expect(mapDbError({ code: '23514', message: 'this role is archived' })).toMatch(/archived/);
  });
  it('keeps the grant refusal sentence exactly as agreed', () => {
    expect(GRANT_EXCEEDS_ERROR).toBe(
      "That role includes access you don't have yourself, so you can't give it.",
    );
    expect(NO_ROLES_YET_ERROR).toMatch(/no roles yet/);
  });
  it('falls back to the plain permission message for other 42501 refusals', () => {
    expect(mapDbError({ code: '42501', message: 'permission denied for table people' })).toBe(
      DENIED_ERROR,
    );
  });
});

describe('mapDbError: review fixes (migration 000600)', () => {
  it('maps the rate limit however it arrives, to one sentence', () => {
    const text = "You're doing that too fast. Wait a minute and try again.";
    expect(TOO_FAST_ERROR).toBe(text);
    expect(mapDbError({ code: 'PT429', message: 'slow down' })).toBe(text);
    expect(mapDbError({ code: '429', message: 'x' })).toBe(text);
    expect(mapDbError({ status: 429, message: 'anything' })).toBe(text);
    expect(mapDbError({ message: 'Slow down' })).toBe(text);
  });

  it('maps the new 22023 messages to short plain text', () => {
    expect(mapDbError({ code: '22023', message: 'invalid due time' })).toBe(
      'That due time is not valid. Pick a real date and time.',
    );
    expect(mapDbError({ code: '22023', message: 'invalid publish time' })).toBe(
      'That publish time is not valid. Pick a real date and time.',
    );
    expect(
      mapDbError({ code: '22023', message: 'the notice would expire before it is shown' }),
    ).toBe('The notice would expire before it is shown. Pick a later expiry.');
    expect(mapDbError({ code: '22023', message: 'this push service is not supported' })).toBe(
      "This device's push service is not supported.",
    );
    expect(
      mapDbError({
        code: '22023',
        message: 'this job has been retried too many times; ask support',
      }),
    ).toBe('That job was already retried 3 times. Ask support for help.');
  });

  it('maps the rule caps and the chain limit (54000, 23514)', () => {
    expect(mapDbError({ code: '54000', message: 'event chain is too deep' })).toMatch(
      /too many tasks/,
    );
    expect(mapDbError({ code: '54000', message: 'something else' })).toMatch(/over the limit/);
    expect(
      mapDbError({ code: '23514', message: 'at most 20 rules can be on for one kind of event' }),
    ).toBe('There are already 20 rules turned on for that event. Turn one off first.');
    expect(
      mapDbError({
        code: '23514',
        message: 'a rule for overdue tasks needs a template that is due at least 1 minute later',
      }),
    ).toMatch(/at least 1 minute/);
    expect(
      mapDbError({
        code: '23514',
        message: 'new row for relation "tasks" violates check constraint "finite_due_at"',
      }),
    ).toBe('That date or time is not valid. Pick a real one.');
  });
});

describe('mapDbError: staff scheduling', () => {
  it('maps the assignment rules from the message and from DETAIL', () => {
    expect(
      mapDbError({
        code: '23514',
        message: 'that person has approved time off then',
        details: 'time_off',
      }),
    ).toBe('That person has approved time off then.');
    expect(mapDbError({ code: '23514', message: 'x', details: 'overlap' })).toBe(
      'That person already has a shift at that time.',
    );
    expect(mapDbError({ code: '23514', message: 'x', details: 'qualification' })).toMatch(
      /qualification/,
    );
    expect(mapDbError({ code: '23514', message: 'x', details: 'not_member' })).toMatch(
      /cannot work at this location/,
    );
    expect(mapDbError({ code: '23514', message: 'x', details: 'stale' })).toMatch(/Reload/);
    expect(mapDbError({ code: '23514', message: 'x', details: 'has_shifts' })).toMatch(/shifts/);
  });

  it('maps the exchange and time off refusals', () => {
    expect(mapDbError({ code: '23514', message: 'this shift is no longer open' })).toBe(
      'Someone else already took this shift.',
    );
    expect(
      mapDbError({
        code: '23514',
        message: 'that person has shifts on those days; reassign them first',
      }),
    ).toMatch(/Give those shifts/);
    expect(mapDbError({ code: '23514', message: 'you cannot swap with that person' })).toBe(
      'You cannot swap with that person.',
    );
  });

  it('maps the 42501 variants without sounding like a plain "not allowed"', () => {
    expect(mapDbError({ code: '42501', message: 'only a schedule admin can override' })).toBe(
      'Only a schedule admin can assign anyway.',
    );
    expect(mapDbError({ code: '42501', message: 'you cannot decide your own swap' })).toBe(
      'You cannot decide your own request.',
    );
    expect(mapDbError({ code: '42501', message: 'you cannot decide your own request' })).toBe(
      'You cannot decide your own request.',
    );
    expect(
      mapDbError({ code: '42501', message: 'you cannot change your own qualifications' }),
    ).toBe('You cannot change your own qualifications.');
    expect(mapDbError({ code: '42501', message: 'not allowed' })).toBe(DENIED_ERROR);
  });

  it('maps the 22023 messages, and keeps the older "cannot be changed" text apart', () => {
    for (const message of [
      'invalid week',
      "a week must start on the organization's first day of the week",
      'a shift needs a start and an end',
      'a shift ends after it starts and lasts at most 24 hours',
      'the shift must start during the schedule week',
      'unknown position at this location',
      'notes are too long',
      'a name needs 1 to 100 characters',
      'a position with that name already exists',
      'at most 20 qualifications',
      'a template covers 1 day or 7 days',
      'a template holds at most 200 shifts',
      'a template can only be added to a draft schedule',
      'this schedule is already published',
      'this shift is already cancelled',
      'this swap is no longer open',
      'you already asked for this shift',
      'accept or decline',
      'approve or deny',
      'invalid dates',
      'at most 100 availability windows',
      'those days are too far in the past or future',
      'this request can no longer be cancelled',
    ]) {
      const text = mapDbError({ code: '22023', message });
      expect(text, message).not.toBe('A value is not in the right format.');
      expect(text, message).not.toBe(GENERIC_ERROR);
    }
    expect(mapDbError({ code: '22023', message: 'a cancelled shift cannot be changed' })).toBe(
      'A cancelled shift cannot be changed.',
    );
    expect(mapDbError({ code: '22023', message: 'the note is too long' })).toMatch(/500/);
    expect(mapDbError({ code: '22023', message: 'the reason is too long' })).toMatch(/500/);
  });

  it('maps the rate limit', () => {
    expect(mapDbError({ code: 'PT429', message: 'slow down' })).toBe(TOO_FAST_ERROR);
  });
});
