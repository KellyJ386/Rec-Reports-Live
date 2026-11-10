import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireModulePermission } from '@/lib/auth';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { createSpaceAction } from '@/experiences/admin/actions/spaces';
import { guidParam } from '@/experiences/admin/page-params';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { getLocation } from '@/domains/organizations';
import { groupSpaces, listSpaceKinds, listSpaces, parentChoices } from '@/domains/resources';

export default async function SpacesPage({ params }: { params: Promise<{ locationId: string }> }) {
  const locationId = guidParam((await params).locationId);
  const { orgId } = await requireAdminArea('canSpaces');
  await requireModulePermission(orgId, locationId, 'locations_spaces', 'edit');

  const [location, spaces, kinds] = await Promise.all([
    getLocation(orgId, locationId),
    listSpaces(orgId, locationId),
    listSpaceKinds(orgId, { includeArchived: true }),
  ]);
  if (!location.ok) return <ErrorMessage message={location.message} />;
  if (!location.data) notFound();
  if (!spaces.ok) return <ErrorMessage message={spaces.message} />;
  if (!kinds.ok) return <ErrorMessage message={kinds.message} />;

  const kindName = new Map(kinds.data.map((k) => [k.id, k.name]));
  const groups = groupSpaces(spaces.data);
  const activeKinds = kinds.data.filter((k) => k.archived_at === null);
  const parents = parentChoices(spaces.data);
  const base = `/app/admin/locations/${locationId}`;

  return (
    <main>
      <h1>Spaces at {location.data.name}</h1>
      <p>
        <Link href={base}>Back to this location</Link>
        {' | '}
        <Link href={`${base}/closures`}>Closures</Link>
      </p>

      {groups.length === 0 ? (
        <p>No spaces yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Space</th>
              <th scope="col">Kind</th>
              <th scope="col">Capacity</th>
            </tr>
          </thead>
          <tbody>
            {groups.flatMap(({ space, children }) => [
              <tr key={space.id}>
                <td>
                  <Link href={`${base}/spaces/${space.id}`}>{space.name}</Link>
                  <ArchivedMark archivedAt={space.archived_at} />
                </td>
                <td>{kindName.get(space.space_kind_id) ?? ''}</td>
                <td>{space.capacity ?? ''}</td>
              </tr>,
              ...children.map((c) => (
                <tr key={c.id}>
                  <td>
                    &nbsp;&nbsp;&mdash; <Link href={`${base}/spaces/${c.id}`}>{c.name}</Link>
                    <ArchivedMark archivedAt={c.archived_at} />
                  </td>
                  <td>{kindName.get(c.space_kind_id) ?? ''}</td>
                  <td>{c.capacity ?? ''}</td>
                </tr>
              )),
            ])}
          </tbody>
        </table>
      )}

      <h2>Add a space</h2>
      <ActionForm action={createSpaceAction} submitLabel="Add space">
        <input type="hidden" name="location_id" value={locationId} />
        <p>
          <label>
            Name <input name="name" required maxLength={200} />
          </label>
        </p>
        <p>
          <label>
            Kind{' '}
            <select name="space_kind_id" required defaultValue="">
              <option value="" disabled>
                Choose one
              </option>
              {activeKinds.map((k) => (
                <option key={k.id} value={k.id}>
                  {k.name}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Part of (optional){' '}
            <select name="parent_space_id" defaultValue="">
              <option value="">Nothing: a top-level space</option>
              {parents.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Capacity (optional){' '}
            <input name="capacity" type="number" min={0} step={1} inputMode="numeric" />
          </label>
        </p>
        <p>
          <label>
            Notes (optional) <input name="description" maxLength={2000} />
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
