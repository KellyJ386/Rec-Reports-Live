'use server';

import { revalidatePath } from 'next/cache';
import { requireAdmin } from '@/lib/auth';
import { toInt } from '@/lib/text';
import {
  organizationSettingsUpdateSchema,
  organizationUpdateSchema,
  updateOrganization,
  updateOrganizationSettings,
} from '@/domains/organizations';
import { activeOrgId, bad, good, str, zodProblem, type AdminFormState } from './helpers';

export async function updateSettingsAction(
  _previous: AdminFormState,
  formData: FormData,
): Promise<AdminFormState> {
  const orgId = await activeOrgId();
  await requireAdmin(orgId);
  const name = organizationUpdateSchema.safeParse({ name: str(formData, 'name') });
  if (!name.success) return zodProblem(formData, name.error);
  const week = toInt(formData.get('week_starts_on'));
  const settings = organizationSettingsUpdateSchema.safeParse({
    default_timezone: str(formData, 'default_timezone'),
    ...(week === null ? {} : { week_starts_on: week }),
  });
  if (!settings.success) return zodProblem(formData, settings.error);

  const renamed = await updateOrganization(orgId, name.data);
  if (!renamed.ok) return bad(formData, `${renamed.message} Nothing was saved.`);
  // The name is saved from here on. Refresh either way so the page shows what is stored.
  revalidatePath('/app/admin', 'layout');
  revalidatePath('/app');
  const saved = await updateOrganizationSettings(orgId, settings.data);
  if (!saved.ok) {
    return bad(
      formData,
      `The organization name was saved. The time zone and week start were not saved: ${saved.message}`,
    );
  }
  return good('Saved.');
}
