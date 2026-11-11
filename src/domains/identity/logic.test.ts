import { describe, expect, it } from 'vitest';
import {
  assignableRoles,
  assignmentRank,
  isLastActiveAssignment,
  levelExceeds,
  displayName,
  effectiveLevelKey,
  scopeProblem,
  classifyInviteError,
  inviteCleanupDecision,
  inviteErrorMessage,
  inviteView,
  mayLinkInvitedUser,
  reinviteDecision,
} from './logic';

const LOC_A = 'loc-a';

describe('role helpers', () => {
  it('adds 10 to the rank at organization scope', () => {
    expect(assignmentRank(80, null)).toBe(90);
    expect(assignmentRank(80, LOC_A)).toBe(80);
  });
  it('drops super_admin and archived roles from the picker', () => {
    const roles = [
      { key: 'super_admin', archived_at: null },
      { key: 'admin', archived_at: null },
      { key: 'x', archived_at: '2026-01-01' },
    ];
    expect(assignableRoles(roles).map((r) => r.key)).toEqual(['admin']);
  });
  it('only admin may be organization scoped', () => {
    expect(scopeProblem('admin', true, null)).toBeNull();
    expect(scopeProblem('manager', true, null)).not.toBeNull();
    expect(scopeProblem('admin', false, null)).not.toBeNull();
    expect(scopeProblem('manager', true, LOC_A)).toBeNull();
  });
  it('shows the preferred name first', () => {
    expect(displayName({ first_name: 'Robert', last_name: 'Lee', preferred_name: 'Bob' })).toBe(
      'Bob Lee',
    );
    expect(displayName({ first_name: 'Robert', last_name: 'Lee', preferred_name: ' ' })).toBe(
      'Robert Lee',
    );
  });
});

describe('isLastActiveAssignment', () => {
  const role = { archived_at: null };
  const first = { id: 'a', location_id: 'loc-a', role };
  const rows = [first, { id: 'b', location_id: 'loc-b', role }];
  it('is false while another active assignment remains', () => {
    expect(isLastActiveAssignment(rows, 'a', new Set())).toBe(false);
  });
  it('is true for the only assignment', () => {
    expect(isLastActiveAssignment([first], 'a', new Set())).toBe(true);
  });
  it('ignores assignments on archived roles or archived locations', () => {
    expect(isLastActiveAssignment(rows, 'a', new Set(['loc-b']))).toBe(true);
    expect(
      isLastActiveAssignment(
        [first, { id: 'c', location_id: null, role: { archived_at: '2026-01-01' } }],
        'a',
        new Set(),
      ),
    ).toBe(true);
  });
  it('is false when the assignment itself is not active (nothing left to lose)', () => {
    expect(isLastActiveAssignment(rows, 'a', new Set(['loc-a', 'loc-b']))).toBe(false);
  });
});

describe('effectiveLevelKey', () => {
  it('separates organization scope from locations', () => {
    expect(effectiveLevelKey(null, 'tasks')).toBe('org|tasks');
    expect(effectiveLevelKey('loc-a', 'tasks')).toBe('loc-a|tasks');
  });
});

describe('levelExceeds', () => {
  it('orders none < view < edit < admin', () => {
    expect(levelExceeds('admin', 'edit')).toBe(true);
    expect(levelExceeds('edit', 'edit')).toBe(false);
    expect(levelExceeds('view', 'admin')).toBe(false);
    expect(levelExceeds('view', 'none')).toBe(true);
  });
});

describe('inviteView', () => {
  it('offers an invite only to unarchived people with an email and no account', () => {
    expect(inviteView({ archived: false, email: 'a@b.co', account: 'none' })).toBe('can_invite');
    expect(inviteView({ archived: false, email: null, account: 'none' })).toBe('no_email');
    expect(inviteView({ archived: false, email: '  ', account: 'none' })).toBe('no_email');
  });
  it('offers resend for an active account and enable for a disabled one', () => {
    expect(inviteView({ archived: false, email: 'a@b.co', account: 'active' })).toBe('can_resend');
    expect(inviteView({ archived: false, email: null, account: 'disabled' })).toBe('disabled');
  });
  it('offers nothing for an archived person', () => {
    expect(inviteView({ archived: true, email: 'a@b.co', account: 'none' })).toBe('archived');
    expect(inviteView({ archived: true, email: 'a@b.co', account: 'active' })).toBe('archived');
  });
});

describe('classifyInviteError and inviteErrorMessage', () => {
  it('recognises an existing login and says to ask a platform admin', () => {
    for (const code of ['email_exists', 'user_already_exists']) {
      const kind = classifyInviteError({ code, status: 422 });
      expect(kind).toBe('exists');
      expect(inviteErrorMessage(kind)).toBe(
        'That email already has a login. Ask a platform admin to link it.',
      );
    }
  });
  it('recognises rate limits and bad addresses', () => {
    expect(classifyInviteError({ code: 'over_email_send_rate_limit' })).toBe('rate_limited');
    expect(classifyInviteError({ status: 429 })).toBe('rate_limited');
    expect(classifyInviteError({ code: 'email_address_invalid' })).toBe('invalid_email');
  });
  it('says unavailable for everything else and never echoes detail', () => {
    expect(classifyInviteError(null)).toBe('unavailable');
    expect(classifyInviteError({ code: 'unexpected_failure', status: 500 })).toBe('unavailable');
    expect(inviteErrorMessage('unavailable')).not.toMatch(/unexpected/);
  });
});

describe('reinviteDecision', () => {
  const base = {
    authEmail: 'A@B.co',
    personEmail: 'a@b.co',
    confirmedAt: null,
    lastSignInAt: null,
  };
  it('allows an unaccepted invite to the same address, ignoring case', () => {
    expect(reinviteDecision(base)).toBe('ok');
  });
  it('refuses once accepted or signed in', () => {
    expect(reinviteDecision({ ...base, confirmedAt: '2027-01-01T00:00:00Z' })).toBe('accepted');
    expect(reinviteDecision({ ...base, lastSignInAt: '2027-01-01T00:00:00Z' })).toBe('accepted');
  });
  it('refuses when the person email no longer matches the auth user', () => {
    expect(reinviteDecision({ ...base, personEmail: 'new@b.co' })).toBe('email_changed');
    expect(reinviteDecision({ ...base, authEmail: null })).toBe('email_changed');
  });
});

describe('mayLinkInvitedUser', () => {
  const P = '11111111-1111-4111-8111-111111111111';
  const OTHER = '22222222-2222-4222-8222-222222222222';
  const base = { confirmedAt: null, lastSignInAt: null, linkedAccountPersonIds: [], personId: P };
  it('links a brand-new unconfirmed user, and a retry that already points at this person', () => {
    expect(mayLinkInvitedUser(base)).toBe(true);
    expect(mayLinkInvitedUser({ ...base, linkedAccountPersonIds: [P] })).toBe(true);
  });
  it('never links a confirmed or signed-in user (account takeover)', () => {
    expect(mayLinkInvitedUser({ ...base, confirmedAt: '2027-01-01T00:00:00Z' })).toBe(false);
    expect(mayLinkInvitedUser({ ...base, lastSignInAt: '2027-01-01T00:00:00Z' })).toBe(false);
  });
  it('never links a user that already belongs to another person', () => {
    expect(mayLinkInvitedUser({ ...base, linkedAccountPersonIds: [OTHER] })).toBe(false);
    expect(mayLinkInvitedUser({ ...base, linkedAccountPersonIds: [P, OTHER] })).toBe(false);
  });
});

describe('inviteCleanupDecision', () => {
  const START = Date.parse('2027-03-01T10:00:00.000Z');
  const base = {
    userCreatedAt: '2027-03-01T10:00:02.000Z',
    callStartedAtMs: START,
    confirmedAt: null,
    lastSignInAt: null,
    linkedAccountCount: 0,
  };
  it('deletes only a user created after this call began that nothing points at', () => {
    expect(inviteCleanupDecision(base)).toBe('delete');
  });
  it('leaves a user that existed before the call, or was created at the same instant', () => {
    expect(inviteCleanupDecision({ ...base, userCreatedAt: '2027-01-01T00:00:00Z' })).toBe('leave');
    expect(inviteCleanupDecision({ ...base, userCreatedAt: '2027-03-01T10:00:00.000Z' })).toBe(
      'leave',
    );
  });
  it('leaves a user another organization linked in the meantime', () => {
    expect(inviteCleanupDecision({ ...base, linkedAccountCount: 1 })).toBe('leave');
    expect(inviteCleanupDecision({ ...base, linkedAccountCount: 3 })).toBe('leave');
  });
  it('leaves the user when the fresh check failed or the dates cannot be read', () => {
    expect(inviteCleanupDecision({ ...base, linkedAccountCount: null })).toBe('leave');
    expect(inviteCleanupDecision({ ...base, userCreatedAt: null })).toBe('leave');
    expect(inviteCleanupDecision({ ...base, userCreatedAt: undefined })).toBe('leave');
    expect(inviteCleanupDecision({ ...base, userCreatedAt: 'not a date' })).toBe('leave');
  });
  it('leaves a user that has confirmed or signed in', () => {
    expect(inviteCleanupDecision({ ...base, confirmedAt: '2027-03-01T10:00:03Z' })).toBe('leave');
    expect(inviteCleanupDecision({ ...base, lastSignInAt: '2027-03-01T10:00:03Z' })).toBe('leave');
  });
});
