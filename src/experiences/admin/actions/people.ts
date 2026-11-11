'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireModulePermission } from '@/lib/auth';
import { blankToNull } from '@/lib/text';
import {
  INVITE_NOT_ALLOWED_MESSAGE,
  canManagePersonAccount,
  createPersonWithAssignment,
  getAccountStatus,
  getPerson,
  inviteAccount,
  setAccountDisabled,
  getRole,
  personCreateSchema,
  personUpdateSchema,
  scopeProblem,
  setPersonArchived,
  updatePerson,
} from '@/domains/identity';
import { requirePeopleAdmin } from '../access';
import {
  BAD_ID,
  NOT_CONFIRMED,
  activeOrgId,
  bad,
  confirmed,
  fromResult,
  good,
  guid,
  optionalGuid,
  str,
  zodProblem,
  type AdminFormState,
} from './helpers';

function personFields(formData: FormData) {
  return {
    first_name: str(formData, 'first_name'),
    last_name: str(formData, 'last_name'),
    preferred_name: str(formData, 'preferred_name'),
    email: blankToNull(formData.get('email')),
    phone: str(formData, 'phone'),
    employee_number: str(formData, 'employee_number'),
  };
}

/** Add a person with their first role and location in one step (database function). */
export async function createPersonAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const roleId = guid(formData, 'role_id');
  const locationId = optionalGuid(formData, 'location_id');
  if (!roleId) return bad(formData, 'Pick a role.');
  if (locationId === undefined) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, 'people_roles', 'admin');

  const parsed = personCreateSchema.safeParse({
    organization_id: orgId,
    ...personFields(formData),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);

  const role = await getRole(orgId, roleId);
  if (!role.ok) return bad(formData, role.message);
  if (!role.data) return bad(formData, 'Pick a role.');
  const problem = scopeProblem(role.data.key, role.data.organization_id === null, locationId);
  if (problem) return bad(formData, problem);

  const result = await createPersonWithAssignment({
    ...parsed.data,
    role_id: roleId,
    location_id: locationId,
  });
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/admin/people');
  redirect(`/app/admin/people/${result.data.id}`);
}

export async function updatePersonAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requirePeopleAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const parsed = personUpdateSchema.safeParse(personFields(formData));
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updatePerson(orgId, id, parsed.data);
  if (result.ok) {
    revalidatePath('/app/admin/people');
    revalidatePath(`/app/admin/people/${id}`);
  }
  return fromResult(formData, result, 'Saved.');
}

export async function archivePersonAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requirePeopleAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setPersonArchived(orgId, id, true);
  if (result.ok) {
    revalidatePath('/app/admin/people');
    revalidatePath(`/app/admin/people/${id}`);
  }
  return result.ok ? good('Archived.') : fromResult(formData, result, '');
}

export async function restorePersonAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requirePeopleAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const result = await setPersonArchived(orgId, id, false);
  if (result.ok) {
    revalidatePath('/app/admin/people');
    revalidatePath(`/app/admin/people/${id}`);
  }
  return fromResult(formData, result, 'Restored.');
}

/**
 * Send (or resend) the invite email for a person. Order matters: guard, then the database's own
 * answer to "may I create a login for this person" through the caller's session, and only then
 * the provisioning module, which holds the service-role client.
 */
export async function sendInviteAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requirePeopleAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);

  const person = await getPerson(orgId, id);
  if (!person.ok) return bad(formData, person.message);
  if (!person.data) return bad(formData, BAD_ID);
  if (person.data.archived_at) return bad(formData, 'Restore this person first.');
  const email = person.data.email?.trim();
  if (!email) return bad(formData, 'Add an email address first, then save.');

  const account = await getAccountStatus(orgId, id);
  if (!account.ok) return bad(formData, account.message);
  if (account.data === 'disabled') return bad(formData, 'Turn the login on first.');

  if (!(await canManagePersonAccount(orgId, id))) {
    return bad(formData, INVITE_NOT_ALLOWED_MESSAGE);
  }

  const result = await inviteAccount({ organizationId: orgId, personId: id, email });
  if (!result.ok) return bad(formData, result.message);
  revalidatePath(`/app/admin/people/${id}`);
  return good(
    result.data === 'resent' ? `Invite sent again to ${email}.` : `Invite sent to ${email}.`,
  );
}

async function setLogin(formData: FormData, disabled: boolean): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requirePeopleAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  if (disabled && !confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  // RLS applies the tier rule; a refusal comes back as "nothing changed".
  const result = await setAccountDisabled(orgId, id, disabled);
  if (result.ok) revalidatePath(`/app/admin/people/${id}`);
  return fromResult(formData, result, disabled ? 'Login turned off.' : 'Login turned on.');
}

export async function disableLoginAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  return setLogin(formData, true);
}

export async function enableLoginAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  return setLogin(formData, false);
}
