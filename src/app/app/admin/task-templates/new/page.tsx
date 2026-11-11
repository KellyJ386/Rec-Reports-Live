import Link from 'next/link';
import { ActionForm } from '@/experiences/admin/action-form';
import { getLocationsWithPermission, requireAdminArea } from '@/experiences/admin/access';
import { createTaskTemplateAction } from '@/experiences/admin/actions/task-templates';
import { ErrorMessage } from '@/experiences/admin/ui';
import { ScopeSelect, TaskTemplateFields } from '@/experiences/admin/workflow-fields';
import { firstParam } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import { listJobTitles, listPeople } from '@/domains/identity';

export const metadata = { title: 'New task template | Rec Reports' };

export default async function NewTaskTemplatePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canTasks');
  const search = (firstParam((await searchParams).q) ?? '').trim().slice(0, 100);
  const words = searchWords(search);
  const [places, titles, people] = await Promise.all([
    getLocationsWithPermission(orgId, 'tasks', 'admin'),
    listJobTitles(orgId),
    words.length > 0
      ? listPeople(orgId, { page: 1, words, status: 'active' })
      : Promise.resolve(null),
  ]);
  if (!places.ok) {
    return (
      <main>
        <h1>New task template</h1>
        <ErrorMessage message={places.message} />
      </main>
    );
  }

  return (
    <main>
      <h1>New task template</h1>
      <p>
        <Link href="/app/admin/task-templates">Back to task templates</Link>
      </p>
      <form method="get" action="/app/admin/task-templates/new">
        <p>
          <label>
            To give the task to one person, find them first{' '}
            <input name="q" defaultValue={search} maxLength={100} />
          </label>{' '}
          <button type="submit">Search</button>
        </p>
        {people && people.ok && people.data.rows.length === 0 ? <p>Nobody matches.</p> : null}
      </form>
      <ActionForm action={createTaskTemplateAction} submitLabel="Save template">
        <ScopeSelect allowAll={places.orgWide} locations={places.data} />
        <TaskTemplateFields
          titles={titles.ok ? titles.data : []}
          currentPerson={null}
          matches={people && people.ok ? people.data.rows : []}
        />
      </ActionForm>
    </main>
  );
}
