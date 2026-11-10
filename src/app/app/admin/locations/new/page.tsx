import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { createLocationAction } from '@/experiences/admin/actions/locations';
import { LocationFields } from '@/experiences/admin/fields';
import { getOrganizationSettings } from '@/domains/organizations';

export default async function NewLocationPage() {
  const { orgId } = await requireAdminArea('isOrgAdmin');
  const settings = await getOrganizationSettings(orgId);
  const defaultTimezone = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  return (
    <main>
      <h1>Add a location</h1>
      <p>
        <Link href="/app/admin/locations">Back to locations</Link>
      </p>
      <ActionForm action={createLocationAction} submitLabel="Add location">
        <LocationFields defaultTimezone={defaultTimezone} />
      </ActionForm>
    </main>
  );
}
