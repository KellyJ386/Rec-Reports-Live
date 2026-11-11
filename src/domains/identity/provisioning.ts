import 'server-only';
// Creating a login for a person. This is the one place in the app that uses the service-role
// client to create Supabase Auth users, so it is deliberately narrow:
//
// - The CALLER must already have been authorised: the Server Action checks the guard and then
//   can_manage_person_account() through the caller's own session. Nothing here re-decides who
//   may invite, and nothing here is reachable except through that action.
// - It never links an existing auth user to a person. If the email already has a login, it
//   stops. (Linking by email would let anyone who can type an email address into a person
//   record take over that user's access.)
// - The two writes (auth user, then accounts row) are safe to retry. See inviteAccount.
import { z } from 'zod';
import { createAdminClient } from '@/lib/supabase/admin';
import { getSiteUrl } from '@/lib/env';
import { fail, ok, type Result } from '@/lib/db-errors';
import {
  INVITE_ACCEPTED_MESSAGE,
  INVITE_EMAIL_CHANGED_MESSAGE,
  INVITE_EXISTS_MESSAGE,
  classifyInviteError,
  inviteErrorMessage,
  mayLinkInvitedUser,
  reinviteDecision,
} from './logic';

const emailSchema = z.email();
const GENERIC = 'Could not finish the invite. Try again.';

type AdminClient = ReturnType<typeof createAdminClient>;

/**
 * Sends an invite email that leads to /auth/confirm (type invite) and then to choosing a
 * password, and makes sure the person has an `accounts` row for the resulting login.
 *
 * - Person has no account: invite the address. Existing login at that address, even one that
 *   is only half-created: refuse. New unconfirmed user nobody else points at: insert the
 *   accounts row. If that insert fails, delete the just-created auth user so a retry starts
 *   clean. If it was already inserted (a double click or a retry that got further), carry on.
 * - Person already has an account: resend, but only to the same address and only while the
 *   invite has not been accepted.
 */
export async function inviteAccount(input: {
  organizationId: string;
  personId: string;
  email: string;
}): Promise<Result<'invited' | 'resent'>> {
  const email = emailSchema.safeParse(input.email.trim());
  if (!email.success) return fail(inviteErrorMessage('invalid_email'));
  const admin = createAdminClient();
  const redirectTo = `${getSiteUrl()}/auth/confirm`;

  const existing = await admin
    .from('accounts')
    .select('user_id, organization_id')
    .eq('person_id', input.personId)
    .maybeSingle();
  if (existing.error) {
    console.error('provisioning: read account failed', existing.error.code ?? '');
    return fail(GENERIC);
  }
  if (existing.data) {
    if (existing.data.organization_id !== input.organizationId) return fail(GENERIC);
    return resend(admin, existing.data.user_id, email.data, redirectTo);
  }
  return firstInvite(admin, input, email.data, redirectTo);
}

async function resend(
  admin: AdminClient,
  userId: string,
  personEmail: string,
  redirectTo: string,
): Promise<Result<'resent'>> {
  const found = await admin.auth.admin.getUserById(userId);
  if (found.error || !found.data.user) {
    console.error('provisioning: read auth user failed', found.error?.code ?? '');
    return fail(GENERIC);
  }
  const user = found.data.user;
  const decision = reinviteDecision({
    authEmail: user.email,
    personEmail,
    confirmedAt: user.email_confirmed_at ?? user.confirmed_at,
    lastSignInAt: user.last_sign_in_at,
  });
  if (decision === 'accepted') return fail(INVITE_ACCEPTED_MESSAGE);
  if (decision === 'email_changed') return fail(INVITE_EMAIL_CHANGED_MESSAGE);

  const sent = await admin.auth.admin.inviteUserByEmail(user.email as string, { redirectTo });
  if (sent.error) {
    console.error('provisioning: resend failed', sent.error.code ?? '');
    return fail(inviteErrorMessage(classifyInviteError(sent.error)));
  }
  return ok('resent');
}

async function firstInvite(
  admin: AdminClient,
  input: { organizationId: string; personId: string },
  email: string,
  redirectTo: string,
): Promise<Result<'invited'>> {
  const invited = await admin.auth.admin.inviteUserByEmail(email, { redirectTo });
  if (invited.error || !invited.data.user) {
    console.error('provisioning: invite failed', invited.error?.code ?? '');
    return fail(inviteErrorMessage(classifyInviteError(invited.error)));
  }
  const user = invited.data.user;

  const linked = await admin.from('accounts').select('person_id').eq('user_id', user.id);
  if (linked.error) {
    console.error('provisioning: read links failed', linked.error.code ?? '');
    return fail(GENERIC);
  }
  const safe = mayLinkInvitedUser({
    confirmedAt: user.email_confirmed_at ?? user.confirmed_at,
    lastSignInAt: user.last_sign_in_at,
    linkedAccountPersonIds: linked.data.map((r) => r.person_id),
    personId: input.personId,
  });
  // An existing login. Do not touch it, and do not delete it.
  if (!safe) return fail(INVITE_EXISTS_MESSAGE);

  const inserted = await admin.from('accounts').insert({
    organization_id: input.organizationId,
    person_id: input.personId,
    user_id: user.id,
  });
  if (!inserted.error) return ok('invited');

  // Unique violation: another request linked this person first. Fine if it is this same user.
  if (inserted.error.code === '23505') {
    const again = await admin
      .from('accounts')
      .select('user_id')
      .eq('person_id', input.personId)
      .maybeSingle();
    if (again.data?.user_id === user.id) return ok('invited');
    return fail(INVITE_EXISTS_MESSAGE);
  }

  console.error('provisioning: link failed', inserted.error.code ?? '');
  // The auth user is brand new and unlinked (checked above): remove it so a retry starts clean.
  const removed = await admin.auth.admin.deleteUser(user.id);
  if (removed.error) console.error('provisioning: cleanup failed', removed.error.code ?? '');
  return fail(GENERIC);
}
