import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireModulePermission } from '@/lib/auth';
import { parsePage } from '@/lib/paging';
import { formatInZone } from '@/lib/time';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { addClosureAction, removeClosureAction } from '@/experiences/admin/actions/spaces';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { guidParam } from '@/experiences/admin/page-params';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { getLocation } from '@/domains/organizations';
import { listClosures, listSpaces } from '@/domains/resources';

export default async function ClosuresPage({
  params,
  searchParams,
}: {
  params: Promise<{ locationId: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const locationId = guidParam((await params).locationId);
  const page = parsePage((await searchParams).page);
  const { orgId } = await requireAdminArea('canSpaces');
  await requireModulePermission(orgId, locationId, 'locations_spaces', 'edit');

  const [location, closures, spaces] = await Promise.all([
    getLocation(orgId, locationId),
    listClosures(orgId, locationId, page),
    listSpaces(orgId, locationId),
  ]);
  if (!location.ok) return <ErrorMessage message={location.message} />;
  if (!location.data) notFound();
  if (!closures.ok) return <ErrorMessage message={closures.message} />;
  if (!spaces.ok) return <ErrorMessage message={spaces.message} />;

  const tz = location.data.timezone;
  const spaceName = new Map(spaces.data.map((s) => [s.id, s.name]));
  const base = `/app/admin/locations/${locationId}`;

  return (
    <main>
      <h1>Closures at {location.data.name}</h1>
      <p>
        <Link href={base}>Back to this location</Link>
        {' | '}
        <Link href={`${base}/spaces`}>Spaces</Link>
      </p>
      <p>All times are local time at this location ({tz}).</p>

      {closures.data.rows.length === 0 ? (
        <p>No closures.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th scope="col">What is closed</th>
                <th scope="col">From</th>
                <th scope="col">Until</th>
                <th scope="col">Reason</th>
                <th scope="col">Remove</th>
              </tr>
            </thead>
            <tbody>
              {closures.data.rows.map((c) => (
                <tr key={c.id}>
                  <td>
                    {c.space_id ? (spaceName.get(c.space_id) ?? 'A space') : 'The whole location'}
                  </td>
                  <td>{formatInZone(c.starts_at, tz)}</td>
                  <td>{formatInZone(c.ends_at, tz)}</td>
                  <td>{c.reason ?? ''}</td>
                  <td>
                    <ConfirmAction
                      action={removeClosureAction}
                      label="Remove"
                      question="Yes, remove this closure"
                      fields={{ id: c.id, location_id: locationId }}
                    />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            path={`${base}/closures`}
            page={closures.data.page}
            total={closures.data.total}
            pageSize={closures.data.pageSize}
          />
        </>
      )}

      <h2>Add a closure</h2>
      <ActionForm action={addClosureAction} submitLabel="Add closure">
        <input type="hidden" name="location_id" value={locationId} />
        <p>
          <label>
            What is closed{' '}
            <select name="space_id" defaultValue="">
              <option value="">The whole location</option>
              {spaces.data
                .filter((s) => s.archived_at === null)
                .map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name}
                  </option>
                ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            From ({tz}) <input type="datetime-local" name="starts_at" required />
          </label>
        </p>
        <p>
          <label>
            Until ({tz}) <input type="datetime-local" name="ends_at" required />
          </label>
        </p>
        <p>
          <label>
            Reason (optional) <input name="reason" maxLength={500} />
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
