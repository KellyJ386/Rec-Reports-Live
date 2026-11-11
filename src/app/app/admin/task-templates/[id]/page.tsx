import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { requireAdminArea } from '@/experiences/admin/access';
import {
  archiveTaskTemplateAction,
  restoreTaskTemplateAction,
  updateTaskTemplateAction,
} from '@/experiences/admin/actions/task-templates';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { guidParam } from '@/experiences/admin/page-params';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { TaskTemplateFields } from '@/experiences/admin/workflow-fields';
import { firstParam } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import { getPersonNames, listJobTitles, listPeople } from '@/domains/identity';
import { getLocation } from '@/domains/organizations';
import { getTaskTemplate } from '@/domains/workflows';

export const metadata = { title: 'Task template | Rec Reports' };

export default async function TaskTemplatePage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canTasks');
  const id = guidParam((await params).id);
  const search = (firstParam((await searchParams).q) ?? '').trim().slice(0, 100);
  const res = await getTaskTemplate(orgId, id);
  if (!res.ok) {
    return (
      <main>
        <h1>Task template</h1>
        <ErrorMessage message={res.message} />
      </main>
    );
  }
  if (!res.data) notFound();
  const template = res.data;

  const words = searchWords(search);
  const [titles, location, current, people] = await Promise.all([
    listJobTitles(orgId, { includeArchived: true }),
    template.location_id ? getLocation(orgId, template.location_id) : Promise.resolve(null),
    template.assign_person_id
      ? getPersonNames(orgId, [template.assign_person_id])
      : Promise.resolve(null),
    words.length > 0
      ? listPeople(orgId, { page: 1, words, status: 'active' })
      : Promise.resolve(null),
  ]);
  const currentPerson =
    template.assign_person_id && current && current.ok
      ? {
          id: template.assign_person_id,
          name: current.data[template.assign_person_id] ?? 'Someone',
        }
      : template.assign_person_id
        ? { id: template.assign_person_id, name: 'Someone' }
        : null;
  const where = template.location_id
    ? location && location.ok && location.data
      ? `${location.data.name} only`
      : 'One location'
    : 'All locations';

  return (
    <main>
      <h1>
        {template.title}
        <ArchivedMark archivedAt={template.archived_at} />
      </h1>
      <p>
        <Link href="/app/admin/task-templates">Back to task templates</Link>
      </p>
      <p>Where it applies: {where}. This cannot be changed after the template is made.</p>

      <form method="get" action={`/app/admin/task-templates/${template.id}`}>
        <p>
          <label>
            To give the task to a different person, find them first{' '}
            <input name="q" defaultValue={search} maxLength={100} />
          </label>{' '}
          <button type="submit">Search</button>
        </p>
        {people && people.ok && people.data.rows.length === 0 ? <p>Nobody matches.</p> : null}
      </form>

      <ActionForm action={updateTaskTemplateAction} submitLabel="Save changes">
        <input type="hidden" name="id" value={template.id} />
        <TaskTemplateFields
          template={template}
          titles={titles.ok ? titles.data : []}
          currentPerson={currentPerson}
          matches={people && people.ok ? people.data.rows : []}
        />
      </ActionForm>

      <h2>{template.archived_at ? 'Restore' : 'Archive'}</h2>
      {template.archived_at ? (
        <ActionForm action={restoreTaskTemplateAction} submitLabel="Restore">
          <input type="hidden" name="id" value={template.id} />
        </ActionForm>
      ) : (
        <ConfirmAction
          action={archiveTaskTemplateAction}
          label="Archive"
          question="Yes, archive this template. Rules that use it stop making tasks."
          fields={{ id: template.id }}
        />
      )}
    </main>
  );
}
