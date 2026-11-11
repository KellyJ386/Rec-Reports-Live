import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireAdmin } from '@/lib/auth';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  archiveLocationAction,
  restoreLocationAction,
  updateLocationAction,
} from '@/experiences/admin/actions/locations';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { LocationFields } from '@/experiences/admin/fields';
import { guidParam } from '@/experiences/admin/page-params';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { getLocation } from '@/domains/organizations';

export default async function LocationPage({
  params,
}: {
  params: Promise<{ locationId: string }>;
}) {
  const locationId = guidParam((await params).locationId);
  const { orgId, access } = await requireAdminArea('canLocations');
  // Admin of this location (or of the organization), not merely of some other location.
  await requireAdmin(orgId, locationId);
  const result = await getLocation(orgId, locationId);
  if (!result.ok) return <ErrorMessage message={result.message} />;
  const location = result.data;
  if (!location) notFound();

  return (
    <main>
      <h1>
        {location.name}
        <ArchivedMark archivedAt={location.archived_at} />
      </h1>
      <p>
        <Link href="/app/admin/locations">All locations</Link>
        {' | '}
        <Link href={`/app/admin/locations/${location.id}/spaces`}>Spaces</Link>
        {' | '}
        <Link href={`/app/admin/locations/${location.id}/closures`}>Closures</Link>
      </p>

      <h2>Details</h2>
      <ActionForm action={updateLocationAction} submitLabel="Save">
        <input type="hidden" name="id" value={location.id} />
        <LocationFields location={location} defaultTimezone={location.timezone} />
      </ActionForm>

      {access.isOrgAdmin ? (
        <>
          <h2>{location.archived_at ? 'Restore' : 'Archive'}</h2>
          {location.archived_at ? (
            <ActionForm action={restoreLocationAction} submitLabel="Restore this location">
              <input type="hidden" name="id" value={location.id} />
            </ActionForm>
          ) : (
            <>
              <p>An archived location is hidden from pickers. You can restore it later.</p>
              <ConfirmAction
                action={archiveLocationAction}
                label="Archive this location"
                question="Yes, archive this location"
                fields={{ id: location.id }}
              />
            </>
          )}
        </>
      ) : (
        <p>Only an organization admin can archive or restore a location.</p>
      )}
    </main>
  );
}
