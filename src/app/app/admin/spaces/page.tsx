import Link from 'next/link';
import { getManageableSpaceLocations, requireAdminArea } from '@/experiences/admin/access';
import { ErrorMessage } from '@/experiences/admin/ui';

export default async function SpacesIndexPage() {
  const { orgId } = await requireAdminArea('canSpaces');
  const result = await getManageableSpaceLocations(orgId);

  return (
    <main>
      <h1>Spaces and closures</h1>
      <p>The locations where you can manage spaces, hours and closures.</p>
      {!result.ok ? (
        <ErrorMessage message={result.message} />
      ) : result.data.length === 0 ? (
        <p>You do not manage spaces at any location right now.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Location</th>
              <th scope="col">Spaces and hours</th>
            </tr>
          </thead>
          <tbody>
            {result.data.map((l) => (
              <tr key={l.id}>
                <td>{l.name}</td>
                <td>
                  <Link href={`/app/admin/locations/${l.id}/spaces`}>Spaces</Link>
                  {' | '}
                  <Link href={`/app/admin/locations/${l.id}/closures`}>Closures</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
