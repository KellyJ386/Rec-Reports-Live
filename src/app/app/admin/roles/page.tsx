import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { createRoleAction } from '@/experiences/admin/actions/roles-access';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { listRoles } from '@/domains/identity';

export default async function RolesPage() {
  const { orgId, access } = await requireAdminArea('canPeople');
  const roles = await listRoles(orgId, { includeArchived: true });

  return (
    <main>
      <h1>Roles</h1>
      <p>
        A role sets what a person can do by default. A higher rank outranks a lower one: nobody can
        change someone of equal or higher rank. Giving a role for the whole organization adds 10 to
        its rank.
      </p>
      {!roles.ok ? (
        <ErrorMessage message={roles.message} />
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Role</th>
              <th scope="col">Rank</th>
              <th scope="col">Kind</th>
            </tr>
          </thead>
          <tbody>
            {roles.data.map((r) => (
              <tr key={r.id}>
                <td>
                  <Link href={`/app/admin/roles/${r.id}`}>{r.name}</Link>
                  <ArchivedMark archivedAt={r.archived_at} />
                </td>
                <td>{r.rank}</td>
                <td>{r.organization_id === null ? 'Built in' : 'Custom'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {access.isOrgAdmin ? (
        <>
          <h2>Add a custom role</h2>
          <p>A custom role has a rank from 1 to 79. Add its default access on the next screen.</p>
          <ActionForm action={createRoleAction} submitLabel="Add role">
            <p>
              <label>
                Name <input name="name" required maxLength={100} />
              </label>
            </p>
            <p>
              <label>
                Rank (1 to 79){' '}
                <input
                  name="rank"
                  type="number"
                  min={1}
                  max={79}
                  step={1}
                  required
                  inputMode="numeric"
                />
              </label>
            </p>
            <p>
              <label>
                What it is for (optional) <input name="description" maxLength={1000} />
              </label>
            </p>
          </ActionForm>
        </>
      ) : null}
    </main>
  );
}
