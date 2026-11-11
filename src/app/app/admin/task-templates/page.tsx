import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ArchivedMark, ErrorMessage, Pager } from '@/experiences/admin/ui';
import { firstParam, parsePage } from '@/lib/paging';
import { listAllLocations } from '@/domains/organizations';
import { describeOffset, listTaskTemplates, priorityLabel } from '@/domains/workflows';

export const metadata = { title: 'Task templates | Rec Reports' };

export default async function TaskTemplatesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canTasks');
  const sp = await searchParams;
  const includeArchived = firstParam(sp.archived) === '1';
  const [res, locations] = await Promise.all([
    listTaskTemplates(orgId, { includeArchived }, parsePage(sp.page)),
    listAllLocations(orgId, { includeArchived: true }),
  ]);
  const locationName = new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : []);

  return (
    <main>
      <h1>Task templates</h1>
      <p>
        A template is a task that workflow rules can make for you.{' '}
        <Link href="/app/admin/task-templates/new">New template</Link> |{' '}
        <Link href="/app/admin/workflow-rules">Workflow rules</Link>
      </p>
      <p>
        {includeArchived ? (
          <Link href="/app/admin/task-templates">Hide archived</Link>
        ) : (
          <Link href="/app/admin/task-templates?archived=1">Show archived</Link>
        )}
      </p>
      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && res.data.rows.length === 0 ? <p>There are no task templates yet.</p> : null}
      {res.ok && res.data.rows.length > 0 ? (
        <>
          <table>
            <thead>
              <tr>
                <th scope="col">Template</th>
                <th scope="col">Where</th>
                <th scope="col">Priority</th>
                <th scope="col">Due</th>
              </tr>
            </thead>
            <tbody>
              {res.data.rows.map((t) => (
                <tr key={t.id}>
                  <td>
                    <Link href={`/app/admin/task-templates/${t.id}`}>{t.title}</Link>
                    <ArchivedMark archivedAt={t.archived_at} />
                  </td>
                  <td>
                    {t.location_id
                      ? (locationName.get(t.location_id) ?? 'A location')
                      : 'All locations'}
                  </td>
                  <td>{priorityLabel(t.default_priority)}</td>
                  <td>{describeOffset(t.due_offset_minutes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            path="/app/admin/task-templates"
            page={res.data.page}
            total={res.data.total}
            pageSize={res.data.pageSize}
            params={{ archived: includeArchived ? '1' : undefined }}
          />
        </>
      ) : null}
    </main>
  );
}
