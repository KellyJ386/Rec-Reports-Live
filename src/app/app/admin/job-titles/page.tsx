import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  archiveJobTitleAction,
  createJobTitleAction,
  renameJobTitleAction,
  restoreJobTitleAction,
} from '@/experiences/admin/actions/roles-access';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { listJobTitles } from '@/domains/identity';

export default async function JobTitlesPage() {
  const { orgId } = await requireAdminArea('isOrgAdmin');
  const titles = await listJobTitles(orgId, { includeArchived: true });

  return (
    <main>
      <h1>Job titles</h1>
      <p>
        Job titles decide who gets a task or message, such as Lifeguard or Front Desk. They do not
        give anyone access.
      </p>
      {!titles.ok ? (
        <ErrorMessage message={titles.message} />
      ) : titles.data.length === 0 ? (
        <p>No job titles yet.</p>
      ) : (
        <table>
          <thead>
            <tr>
              <th scope="col">Job title</th>
              <th scope="col">Rename</th>
              <th scope="col">Archive or restore</th>
            </tr>
          </thead>
          <tbody>
            {titles.data.map((t) => (
              <tr key={t.id}>
                <td>
                  {t.name}
                  <ArchivedMark archivedAt={t.archived_at} />
                </td>
                <td>
                  <ActionForm action={renameJobTitleAction} submitLabel="Rename">
                    <input type="hidden" name="id" value={t.id} />
                    <label>
                      New name <input name="name" defaultValue={t.name} required maxLength={100} />
                    </label>
                  </ActionForm>
                </td>
                <td>
                  {t.archived_at ? (
                    <ActionForm action={restoreJobTitleAction} submitLabel="Restore">
                      <input type="hidden" name="id" value={t.id} />
                    </ActionForm>
                  ) : (
                    <ConfirmAction
                      action={archiveJobTitleAction}
                      label="Archive"
                      question={`Yes, archive ${t.name}`}
                      fields={{ id: t.id }}
                    />
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <h2>Add a job title</h2>
      <ActionForm action={createJobTitleAction} submitLabel="Add job title">
        <p>
          <label>
            Name <input name="name" required maxLength={100} />
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
