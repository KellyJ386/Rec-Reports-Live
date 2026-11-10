import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ArchivedMark, ErrorMessage, Pager } from '@/experiences/admin/ui';
import { parsePage } from '@/lib/paging';
import { listLocations } from '@/domains/organizations';

export default async function LocationsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, access } = await requireAdminArea('canLocations');
  const page = parsePage((await searchParams).page);
  const result = await listLocations(orgId, page);

  return (
    <main>
      <h1>Locations</h1>
      {access.isOrgAdmin ? (
        <p>
          <Link href="/app/admin/locations/new">Add a location</Link>
        </p>
      ) : null}
      {!result.ok ? (
        <ErrorMessage message={result.message} />
      ) : result.data.rows.length === 0 ? (
        <p>No locations yet.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Code</th>
                <th scope="col">Time zone</th>
                <th scope="col">Spaces and hours</th>
              </tr>
            </thead>
            <tbody>
              {result.data.rows.map((l) => (
                <tr key={l.id}>
                  <td>
                    <Link href={`/app/admin/locations/${l.id}`}>{l.name}</Link>
                    <ArchivedMark archivedAt={l.archived_at} />
                  </td>
                  <td>{l.code ?? ''}</td>
                  <td>{l.timezone}</td>
                  <td>
                    <Link href={`/app/admin/locations/${l.id}/spaces`}>Spaces</Link>
                    {' | '}
                    <Link href={`/app/admin/locations/${l.id}/closures`}>Closures</Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            path="/app/admin/locations"
            page={result.data.page}
            total={result.data.total}
            pageSize={result.data.pageSize}
          />
        </>
      )}
    </main>
  );
}
