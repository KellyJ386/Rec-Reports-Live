import { describe, expect, it } from 'vitest';
import {
  DENIED_ERROR,
  GENERIC_ERROR,
  GRANT_EXCEEDS_ERROR,
  NO_CHANGE_ERROR,
  NO_ROLES_YET_ERROR,
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
