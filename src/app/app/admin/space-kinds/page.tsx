import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  archiveSpaceKindAction,
  createSpaceKindAction,
  renameSpaceKindAction,
  restoreSpaceKindAction,
} from '@/experiences/admin/actions/spaces';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { listSpaceKinds } from '@/domains/resources';

export default async function SpaceKindsPage() {
  const { orgId } = await requireAdminArea('canSpaceKinds');
  const kinds = await listSpaceKinds(orgId, { includeArchived: true });

  return (
    <main>
      <h1>Space kinds</h1>
      <p>
        A kind is a label for a type of space, such as pool, gym or court. It applies to the whole
        organization.
      </p>
      {!kinds.ok ? (
        <ErrorMessage message={kinds.message} />
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Kind</th>
              <th scope="col">Rename</th>
              <th scope="col">Archive or restore</th>
            </tr>
          </thead>
          <tbody>
            {kinds.data.map((k) => (
              <tr key={k.id}>
                <td>
                  {k.name}
                  <ArchivedMark archivedAt={k.archived_at} />
                </td>
                <td>
                  <ActionForm action={renameSpaceKindAction} submitLabel="Rename">
                    <input type="hidden" name="id" value={k.id} />
                    <label>
                      New name <input name="name" defaultValue={k.name} required maxLength={100} />
                    </label>
                  </ActionForm>
                </td>
                <td>
                  {k.archived_at ? (
                    <ActionForm action={restoreSpaceKindAction} submitLabel="Restore">
                      <input type="hidden" name="id" value={k.id} />
                    </ActionForm>
                  ) : (
                    <ConfirmAction
                      action={archiveSpaceKindAction}
                      label="Archive"
                      question={`Yes, archive ${k.name}`}
                      fields={{ id: k.id }}
                    />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h2>Add a kind</h2>
      <ActionForm action={createSpaceKindAction} submitLabel="Add kind">
        <p>
          <label>
            Name <input name="name" required maxLength={100} />
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
