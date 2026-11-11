'use server';

// Roles, role assignments, job titles and permission overrides.
import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireAdmin, requireModulePermission } from '@/lib/auth';
import { keyFromName, toInt, blankToNull } from '@/lib/text';
import {
  DENIED_ERROR,
  GRANT_EXCEEDS_ERROR,
  NO_ROLES_YET_ERROR,
  type Result,
} from '@/lib/db-errors';
import { moduleKeySchema } from '@/lib/auth/schemas';
import { getLocation, listAllLocations } from '@/domains/organizations';
import {
  addPersonJobTitle,
  addRoleAssignment,
  createJobTitle,
  createRole,
  getRole,
  getRoleGrantExcess,
  isLastActiveAssignment,
  jobTitleCreateSchema,
  jobTitleUpdateSchema,
  listPersonJobTitles,
  listRoleAssignments,
  listUserPermissions,
  permissionLevelSchema,
  personJobTitleCreateSchema,
  removePersonJobTitle,
  removeRoleAssignment,
  replaceRoleAssignment,
  removeUserPermission,
  roleAssignmentCreateSchema,
  roleCreateSchema,
  roleUpdateSchema,
  scopeProblem,
  setJobTitleArchived,
  setRoleArchived,
  setRoleDefault,
  setUserPermission,
  updateJobTitle,
  updateRole,
  userPermissionCreateSchema,
} from '@/domains/identity';
import {
  BAD_ID,
  NOT_CONFIRMED,
  activeOrgId,
  bad,
  confirmed,
  fromResult,
  guid,
  optionalGuid,
  str,
  zodProblem,
  type AdminFormState,
} from './helpers';

const MODULE = 'people_roles';

function refreshPerson(personId: string) {
  revalidatePath(`/app/admin/people/${personId}/access`);
  revalidatePath(`/app/admin/people/${personId}`);
}

// ---- role assignments ----

/**
 * Why a role cannot be given at a place, as a plain sentence, or null when it can. The role
 * and location are loaded through the organization-filtered services, so another
 * organization's ids are "not found".
 */
/**
 * A refusal from row-level security is just "denied". After one on a role assignment, work out
 * the likely reason so the message is useful: the role includes access the caller does not
 * have, or the person has no roles yet (only an organization admin can give the first one).
 */
async function explainAssignmentDenial(
  orgId: string,
  personId: string,
  roleId: string,
  locationId: string | null,
  result: Result<unknown>,
): Promise<Result<unknown>> {
  if (result.ok || result.message !== DENIED_ERROR) return result;
  if ((await getRoleGrantExcess(orgId, roleId, locationId)).length > 0) {
    return { ok: false, message: GRANT_EXCEEDS_ERROR };
  }
  const existing = await listRoleAssignments(orgId, personId);
  if (existing.ok && existing.data.length === 0) {
    return { ok: false, message: NO_ROLES_YET_ERROR };
  }
  return result;
}

async function assignmentTargetProblem(
  orgId: string,
  roleId: string,
  locationId: string | null,
): Promise<string | null> {
  const role = await getRole(orgId, roleId);
  if (!role.ok) return role.message;
  if (!role.data) return 'Pick a role.';
  if (role.data.archived_at) return 'That role is archived, so it cannot be given to anyone.';
  const scope = scopeProblem(role.data.key, role.data.organization_id === null, locationId);
  if (scope) return scope;
  if (locationId !== null) {
    const location = await getLocation(orgId, locationId);
    if (!location.ok) return location.message;
    if (!location.data) return BAD_ID;
    if (location.data.archived_at) {
      return 'That location is archived. Restore it first, or pick another location.';
    }
  }
  return null;
}

export async function addAssignmentAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const personId = guid(formData, 'person_id');
  const roleId = guid(formData, 'role_id');
  const locationId = optionalGuid(formData, 'location_id');
  if (!personId) return bad(formData, BAD_ID);
  if (!roleId) return bad(formData, 'Pick a role.');
  if (locationId === undefined) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, MODULE, 'admin');

  const problem = await assignmentTargetProblem(orgId, roleId, locationId);
  if (problem) return bad(formData, problem);

  const parsed = roleAssignmentCreateSchema.safeParse({
    organization_id: orgId,
    person_id: personId,
    role_id: roleId,
    location_id: locationId,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await explainAssignmentDenial(
    orgId,
    personId,
    roleId,
    locationId,
    await addRoleAssignment(parsed.data),
  );
  if (result.ok) refreshPerson(personId);
  return fromResult(formData, result, 'Role added.');
}

/** Changes one assignment's role and place in a single database call (never zero roles in between). */
export async function changeAssignmentAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  const personId = guid(formData, 'person_id');
  const roleId = guid(formData, 'role_id');
  const locationId = optionalGuid(formData, 'location_id');
  if (!id || !personId) return bad(formData, BAD_ID);
  if (!roleId) return bad(formData, 'Pick a role.');
  if (locationId === undefined) return bad(formData, BAD_ID);
  // The current scope comes from the stored row, not from the form.
  const rows = await listRoleAssignments(orgId, personId);
  if (!rows.ok) return bad(formData, rows.message);
  const row = rows.data.find((r) => r.id === id);
  if (!row) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, row.location_id, MODULE, 'admin');
  await requireModulePermission(orgId, locationId, MODULE, 'admin');

  const problem = await assignmentTargetProblem(orgId, roleId, locationId);
  if (problem) return bad(formData, problem);
  if (roleId === row.role_id && locationId === row.location_id) {
    return bad(formData, 'Nothing to change: that is already their role there.');
  }
  const result = await explainAssignmentDenial(
    orgId,
    personId,
    roleId,
    locationId,
    await replaceRoleAssignment(id, roleId, locationId),
  );
  if (result.ok) refreshPerson(personId);
  return fromResult(formData, result, 'Role changed.');
}

export async function removeAssignmentAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  const personId = guid(formData, 'person_id');
  if (!id || !personId) return bad(formData, BAD_ID);
  // The scope to guard comes from the stored row, not from the form.
  const rows = await listRoleAssignments(orgId, personId);
  if (!rows.ok) return bad(formData, rows.message);
  const row = rows.data.find((r) => r.id === id);
  if (!row) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, row.location_id, MODULE, 'admin');
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);

  // Removing the last active role locks the person out of the organization: the page asks
  // for a separate, explicit confirmation and the server checks that it was given.
  const locations = await listAllLocations(orgId, { includeArchived: true });
  if (!locations.ok) return bad(formData, locations.message);
  const archived = new Set(locations.data.filter((l) => l.archived_at).map((l) => l.id));
  if (isLastActiveAssignment(rows.data, id, archived) && formData.get('confirm_last') !== 'yes') {
    return bad(
      formData,
      'This is their last role. Removing it means they will lose access to the organization. Reload the page and confirm that.',
    );
  }
  const result = await removeRoleAssignment(orgId, id);
  if (result.ok) refreshPerson(personId);
  return fromResult(formData, result, 'Role removed.');
}

// ---- person job titles ----

export async function addPersonJobTitleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const personId = guid(formData, 'person_id');
  const titleId = guid(formData, 'job_title_id');
  const locationId = optionalGuid(formData, 'location_id');
  if (!personId) return bad(formData, BAD_ID);
  if (!titleId) return bad(formData, 'Pick a job title.');
  if (locationId === undefined) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, MODULE, 'edit');
  const parsed = personJobTitleCreateSchema.safeParse({
    organization_id: orgId,
    person_id: personId,
    job_title_id: titleId,
    location_id: locationId,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await addPersonJobTitle(parsed.data);
  if (result.ok) refreshPerson(personId);
  return fromResult(formData, result, 'Job title added.');
}

export async function removePersonJobTitleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  const personId = guid(formData, 'person_id');
  if (!id || !personId) return bad(formData, BAD_ID);
  const rows = await listPersonJobTitles(orgId, personId);
  if (!rows.ok) return bad(formData, rows.message);
  const row = rows.data.find((r) => r.id === id);
  if (!row) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, row.location_id, MODULE, 'edit');
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await removePersonJobTitle(orgId, id);
  if (result.ok) refreshPerson(personId);
  return fromResult(formData, result, 'Job title removed.');
}

// ---- permission overrides ----

export async function setOverrideAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const personId = guid(formData, 'person_id');
  const locationId = optionalGuid(formData, 'location_id');
  if (!personId) return bad(formData, BAD_ID);
  if (locationId === undefined) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, locationId, MODULE, 'admin');
  const parsed = userPermissionCreateSchema.safeParse({
    organization_id: orgId,
    person_id: personId,
    location_id: locationId,
    module_key: str(formData, 'module_key'),
    level: str(formData, 'level'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await setUserPermission(parsed.data);
  if (result.ok) refreshPerson(personId);
  return fromResult(formData, result, 'Override saved.');
}

export async function removeOverrideAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  const personId = guid(formData, 'person_id');
  if (!id || !personId) return bad(formData, BAD_ID);
  const rows = await listUserPermissions(orgId, personId);
  if (!rows.ok) return bad(formData, rows.message);
  const row = rows.data.find((r) => r.id === id);
  if (!row) return bad(formData, BAD_ID);
  await requireModulePermission(orgId, row.location_id, MODULE, 'admin');
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await removeUserPermission(orgId, id);
  if (result.ok) refreshPerson(personId);
  return fromResult(formData, result, 'Override removed.');
}

// ---- job title list (organization admin) ----

export async function createJobTitleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const parsed = jobTitleCreateSchema.safeParse({
    organization_id: orgId,
    name: str(formData, 'name'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createJobTitle(parsed.data);
  if (result.ok) revalidatePath('/app/admin/job-titles');
  return fromResult(formData, result, 'Job title added.');
}

export async function renameJobTitleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const parsed = jobTitleUpdateSchema.safeParse({ name: str(formData, 'name') });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateJobTitle(orgId, id, parsed.data);
  if (result.ok) revalidatePath('/app/admin/job-titles');
  return fromResult(formData, result, 'Saved.');
}

export async function archiveJobTitleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setJobTitleArchived(orgId, id, true);
  if (result.ok) revalidatePath('/app/admin/job-titles');
  return fromResult(formData, result, 'Archived.');
}

export async function restoreJobTitleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const result = await setJobTitleArchived(orgId, id, false);
  if (result.ok) revalidatePath('/app/admin/job-titles');
  return fromResult(formData, result, 'Restored.');
}

// ---- custom roles (organization admin) ----

export async function createRoleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const name = str(formData, 'name');
  const parsed = roleCreateSchema.safeParse({
    organization_id: orgId,
    key: keyFromName(name, 63),
    name,
    description: str(formData, 'description'),
    rank: toInt(formData.get('rank')) ?? Number.NaN,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createRole(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/admin/roles');
  redirect(`/app/admin/roles/${result.data.id}`);
}

export async function updateRoleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const parsed = roleUpdateSchema.safeParse({
    name: str(formData, 'name'),
    description: str(formData, 'description'),
    rank: toInt(formData.get('rank')) ?? Number.NaN,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateRole(orgId, id, parsed.data);
  if (result.ok) {
    revalidatePath('/app/admin/roles');
    revalidatePath(`/app/admin/roles/${id}`);
  }
  return fromResult(formData, result, 'Saved.');
}

export async function archiveRoleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setRoleArchived(orgId, id, true);
  if (result.ok) {
    revalidatePath('/app/admin/roles');
    revalidatePath(`/app/admin/roles/${id}`);
  }
  return fromResult(formData, result, 'Archived.');
}

export async function restoreRoleAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const result = await setRoleArchived(orgId, id, false);
  if (result.ok) {
    revalidatePath('/app/admin/roles');
    revalidatePath(`/app/admin/roles/${id}`);
  }
  return fromResult(formData, result, 'Restored.');
}

/** Saves the default level for every module on one custom role, from one form. */
export async function saveRoleDefaultsAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const roleId = guid(formData, 'id');
  if (!roleId) return bad(formData, BAD_ID);

  // One change per module, keyed by module key. A repeated key is ignored (first one wins).
  const changes = new Map<string, 'none' | 'view' | 'edit' | 'admin'>();
  for (const [name, value] of formData.entries()) {
    if (!name.startsWith('level:') || typeof value !== 'string') continue;
    const moduleKey = name.slice('level:'.length);
    const key = moduleKeySchema.safeParse(moduleKey);
    const level = permissionLevelSchema.safeParse(value);
    if (!key.success || !level.success) return bad(formData, BAD_ID);
    if (changes.has(key.data)) continue;
    // Only send levels the person changed (the form also posts what was there before).
    if (blankToNull(formData.get(`was:${key.data}`)) === level.data) continue;
    changes.set(key.data, level.data);
  }
  if (changes.size === 0) return bad(formData, 'No levels were changed.');

  const total = changes.size;
  let saved = 0;
  for (const [moduleKey, level] of changes) {
    const result = await setRoleDefault(orgId, roleId, moduleKey, level);
    if (!result.ok) {
      revalidatePath(`/app/admin/roles/${roleId}`);
      return bad(
        formData,
        saved === 0
          ? `${result.message} Nothing was saved.`
          : `${result.message} ${saved} of ${total} change(s) were saved; the rest were not. Reload the page to see which.`,
      );
    }
    saved += 1;
  }
  revalidatePath(`/app/admin/roles/${roleId}`);
  return fromResult(
    formData,
    { ok: true, data: saved },
    saved === 1 ? 'Saved 1 change.' : `Saved ${saved} changes.`,
  );
}
