'use server';

import { redirect } from 'next/navigation';
import { revalidatePath } from 'next/cache';
import { requireAdmin } from '@/lib/auth';
import { blankToNull } from '@/lib/text';
import {
  createLocation,
  locationCreateSchema,
  locationUpdateSchema,
  setLocationArchived,
  updateLocation,
} from '@/domains/organizations';
import {
  BAD_ID,
  NOT_CONFIRMED,
  activeOrgId,
  bad,
  confirmed,
  fromResult,
  good,
  guid,
  str,
  zodProblem,
  type AdminFormState,
} from './helpers';

function fields(formData: FormData) {
  return {
    name: str(formData, 'name'),
    code: blankToNull(formData.get('code')),
    timezone: str(formData, 'timezone'),
    address: str(formData, 'address'),
    phone: str(formData, 'phone'),
  };
}

export async function createLocationAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const parsed = locationCreateSchema.safeParse({ organization_id: orgId, ...fields(formData) });
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await createLocation(parsed.data);
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/admin/locations');
  redirect(`/app/admin/locations/${result.data.id}`);
}

export async function updateLocationAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  await requireAdmin(orgId, id);
  const parsed = locationUpdateSchema.safeParse(fields(formData));
  if (!parsed.success) return zodProblem(formData, parsed.error);
  const result = await updateLocation(orgId, id, parsed.data);
  if (!result.ok) return bad(formData, result.message);
  revalidatePath('/app/admin/locations');
  revalidatePath(`/app/admin/locations/${id}`);
  return good('Saved.');
}

export async function archiveLocationAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  await requireAdmin(orgId, id);
  if (!confirmed(formData)) return bad(formData, NOT_CONFIRMED);
  const result = await setLocationArchived(orgId, id, true);
  if (result.ok) {
    revalidatePath('/app/admin/locations');
    revalidatePath(`/app/admin/locations/${id}`);
  }
  return fromResult(formData, result, 'Archived.');
}

export async function restoreLocationAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  const id = guid(formData, 'id');
  if (!id) return bad(formData, BAD_ID);
  await requireAdmin(orgId, id);
  const result = await setLocationArchived(orgId, id, false);
  if (result.ok) {
    revalidatePath('/app/admin/locations');
    revalidatePath(`/app/admin/locations/${id}`);
  }
  return fromResult(formData, result, 'Restored.');
}
