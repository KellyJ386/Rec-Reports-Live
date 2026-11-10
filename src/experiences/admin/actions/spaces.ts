'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireModulePermission } from '@/lib/auth';
import { blankToNull, keyFromName, toInt } from '@/lib/text';
import { zonedLocalToUtc } from '@/lib/time';
import { getLocation } from '@/domains/organizations';
import {
  addClosure,
  addSpaceHours,
  createSpace,
  createSpaceKind,
  hoursTimes,
  removeClosure,
  removeSpaceHours,
  setSpaceArchived,
  setSpaceKindArchived,
  spaceClosureCreateSchema,
  spaceCreateSchema,
  spaceHourCreateSchema,
  spaceKindCreateSchema,
  spaceKindUpdateSchema,
  spaceUpdateSchema,
  updateSpace,
  updateSpaceKind,
} from '@/domains/resources';
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

const MODULE = 'locations_spaces';

/** Org + location from the form, after the guard: locations_spaces >= edit at that location. */
async function spaceScope(formData: FormData) {
  const orgId = await activeOrgId();
  const locationId = guid(formData, 'location_id');
  if (!locationId) return null;
  await requireModulePermission(orgId, locationId, MODULE, 'edit');
  return { orgId, locationId };
}

function refresh(locationId: string, spaceId?: string) {
  revalidatePath(`/app/admin/locations/${locationId}/spaces`);
  if (spaceId) revalidatePath(`/app/admin/locations/${locationId}/spaces/${spaceId}`);
}

function capacity(formData: FormData): number | null | 'bad' {
  const text = blankToNull(formData.get('capacity'));
  if (text === null) return null;
  const n = toInt(text);
  return n === null ? 'bad' : n;
}

// ---- spaces ----

export async function createSpaceAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  if (!scope) return bad(formData, BAD_ID);
  const kind = guid(formData, 'space_kind_id');
  const parent = optionalGuid(formData, 'parent_space_id');
  const cap = capacity(formData);
  if (!kind) return bad(formData, 'Pick a kind.');
  if (parent === undefined) return bad(formData, BAD_ID);
  if (cap === 'bad') return bad(formData, 'Capacity must be a whole number.');
  const parsed = spaceCreateSchema.safeParse({
    organization_id: scope.orgId,
    location_id: scope.locationId,
    space_kind_id: kind,
    parent_space_id: parent,
    name: str(formData, 'name'),
    description: str(formData, 'description'),
    capacity: cap,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createSpace(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  refresh(scope.locationId);
  redirect(`/app/admin/locations/${scope.locationId}/spaces/${result.data.id}`);
}

export async function updateSpaceAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  const id = guid(formData, 'id');
  if (!scope || !id) return bad(formData, BAD_ID);
  const kind = guid(formData, 'space_kind_id');
  const parent = optionalGuid(formData, 'parent_space_id');
  const cap = capacity(formData);
  if (!kind) return bad(formData, 'Pick a kind.');
  if (parent === undefined) return bad(formData, BAD_ID);
  if (cap === 'bad') return bad(formData, 'Capacity must be a whole number.');
  const parsed = spaceUpdateSchema.safeParse({
    space_kind_id: kind,
    parent_space_id: parent,
    name: str(formData, 'name'),
    description: str(formData, 'description'),
    capacity: cap,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateSpace(scope.orgId, scope.locationId, id, parsed.data);
  if (result.ok) refresh(scope.locationId, id);
  return fromResult(formData, result, 'Saved.');
}

export async function archiveSpaceAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  const id = guid(formData, 'id');
  if (!scope || !id) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setSpaceArchived(scope.orgId, scope.locationId, id, true);
  if (result.ok) refresh(scope.locationId, id);
  return fromResult(formData, result, 'Archived.');
}

export async function restoreSpaceAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  const id = guid(formData, 'id');
  if (!scope || !id) return bad(formData, BAD_ID);
  const result = await setSpaceArchived(scope.orgId, scope.locationId, id, false);
  if (result.ok) refresh(scope.locationId, id);
  return fromResult(formData, result, 'Restored.');
}

// ---- weekly hours ----

/** Adds the same hours to every ticked weekday. Stops at the first refusal and says which day. */
export async function addHoursAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  const spaceId = guid(formData, 'space_id');
  if (!scope || !spaceId) return bad(formData, BAD_ID);

  const days = formData
    .getAll('day')
    .map((d) => toInt(d))
    .filter((d): d is number => d !== null);
  if (days.length === 0) return bad(formData, 'Tick at least one day.');
  const times = hoursTimes({
    opens: blankToNull(formData.get('opens_at')),
    closes: blankToNull(formData.get('closes_at')),
    closesAtMidnight: formData.get('closes_at_midnight') === 'yes',
  });
  if (!times) return bad(formData, 'Enter an opening and a closing time.');

  let added = 0;
  for (const day of [...new Set(days)].sort((a, b) => a - b)) {
    const parsed = spaceHourCreateSchema.safeParse({
      organization_id: scope.orgId,
      location_id: scope.locationId,
      space_id: spaceId,
      day_of_week: day,
      ...times,
      effective_from: blankToNull(formData.get('effective_from')),
      effective_to: blankToNull(formData.get('effective_to')),
    });
    if (!parsed.success) return zodProblem(formData, parsed.error);
    const result = await addSpaceHours(parsed.data);
    if (!result.ok) {
      refresh(scope.locationId, spaceId);
      return bad(
        formData,
        added > 0 ? `${result.message} (${added} earlier day(s) were added.)` : result.message,
      );
    }
    added += 1;
  }
  refresh(scope.locationId, spaceId);
  return good(added === 1 ? 'Hours added.' : `Hours added for ${added} days.`);
}

export async function removeHoursAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  const id = guid(formData, 'id');
  const spaceId = guid(formData, 'space_id');
  if (!scope || !id || !spaceId) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await removeSpaceHours(scope.orgId, scope.locationId, id);
  if (result.ok) refresh(scope.locationId, spaceId);
  return fromResult(formData, result, 'Removed.');
}

// ---- closures ----

export async function addClosureAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  if (!scope) return bad(formData, BAD_ID);
  const spaceId = optionalGuid(formData, 'space_id');
  if (spaceId === undefined) return bad(formData, BAD_ID);

  const location = await getLocation(scope.orgId, scope.locationId);
  if (!location.ok) return bad(formData, location.message);
  if (!location.data) return bad(formData, BAD_ID);
  const tz = location.data.timezone;
  const starts = zonedLocalToUtc(str(formData, 'starts_at'), tz);
  const ends = zonedLocalToUtc(str(formData, 'ends_at'), tz);
  if (!starts) return bad(formData, 'Enter when the closure starts.');
  if (!ends) return bad(formData, 'Enter when the closure ends.');

  const parsed = spaceClosureCreateSchema.safeParse({
    organization_id: scope.orgId,
    location_id: scope.locationId,
    space_id: spaceId,
    starts_at: starts,
    ends_at: ends,
    reason: str(formData, 'reason'),
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await addClosure(parsed.data);
  if (result.ok) revalidatePath(`/app/admin/locations/${scope.locationId}/closures`);
  return fromResult(formData, result, 'Closure added.');
}

export async function removeClosureAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const scope = await spaceScope(formData);
  const id = guid(formData, 'id');
  if (!scope || !id) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await removeClosure(scope.orgId, scope.locationId, id);
  if (result.ok) revalidatePath(`/app/admin/locations/${scope.locationId}/closures`);
  return fromResult(formData, result, 'Removed.');
}

// ---- space kinds (organization scope) ----

async function kindOrg(): Promise<string> {
  const orgId = await activeOrgId();
  await requireModulePermission(orgId, null, MODULE, 'edit');
  return orgId;
}

export async function createSpaceKindAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await kindOrg();
  const name = str(formData, 'name');
  const parsed = spaceKindCreateSchema.safeParse({
    organization_id: orgId,
    key: keyFromName(name, 63),
    name,
  });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createSpaceKind(parsed.data);
  if (result.ok) revalidatePath('/app/admin/space-kinds');
  return fromResult(formData, result, 'Kind added.');
}

export async function renameSpaceKindAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await kindOrg();
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const parsed = spaceKindUpdateSchema.safeParse({ name: str(formData, 'name') });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateSpaceKind(orgId, id, parsed.data);
  if (result.ok) revalidatePath('/app/admin/space-kinds');
  return fromResult(formData, result, 'Saved.');
}

export async function archiveSpaceKindAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await kindOrg();
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setSpaceKindArchived(orgId, id, true);
  if (result.ok) revalidatePath('/app/admin/space-kinds');
  return fromResult(formData, result, 'Archived.');
}

export async function restoreSpaceKindAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await kindOrg();
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  const result = await setSpaceKindArchived(orgId, id, false);
  if (result.ok) revalidatePath('/app/admin/space-kinds');
  return fromResult(formData, result, 'Restored.');
}
