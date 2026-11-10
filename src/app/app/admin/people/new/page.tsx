import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { createPersonAction } from '@/experiences/admin/actions/people';
import { PersonFields } from '@/experiences/admin/fields';
import { ErrorMessage } from '@/experiences/admin/ui';
import { assignableRoles, listRoles } from '@/domains/identity';
import { listAllLocations } from '@/domains/organizations';

export default async function NewPersonPage() {
  const { orgId } = await requireAdminArea('canPeopleAdmin');
  const [roles, locations] = await Promise.all([listRoles(orgId), listAllLocations(orgId)]);
  if (!roles.ok) return <ErrorMessage message={roles.message} />;
  if (!locations.ok) return <ErrorMessage message={locations.message} />;

  return (
    <main>
      <h1>Add a person</h1>
      <p>
        <Link href="/app/admin/people">Back to people</Link>
      </p>
      <p>This adds the person and their first role together. You can add more roles afterwards.</p>
      <ActionForm action={createPersonAction} submitLabel="Add person">
        <PersonFields />
        <p>
          <label>
            Role{' '}
            <select name="role_id" required defaultValue="">
              <option value="" disabled>
                Choose one
              </option>
              {assignableRoles(roles.data).map((r) => (
                <option key={r.id} value={r.id}>
                  {r.name} (rank {r.rank})
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Where{' '}
            <select name="location_id" defaultValue="">
              <option value="">Whole organization (admin role only)</option>
              {locations.data.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
