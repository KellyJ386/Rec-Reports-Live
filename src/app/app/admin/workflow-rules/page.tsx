import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ArchivedMark, ErrorMessage, Pager } from '@/experiences/admin/ui';
import { firstParam, parsePage } from '@/lib/paging';
import { listAllLocations } from '@/domains/organizations';
import {
  describeCondition,
  eventTypeLabel,
  listTemplateChoices,
  listWorkflowRules,
} from '@/domains/workflows';

export const metadata = { title: 'Workflow rules | Rec Reports' };

export default async function WorkflowRulesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canTasks');
  const sp = await searchParams;
  const includeArchived = firstParam(sp.archived) === '1';
  const [res, templates, locations] = await Promise.all([
    listWorkflowRules(orgId, { includeArchived }, parsePage(sp.page)),
    listTemplateChoices(orgId),
    listAllLocations(orgId, { includeArchived: true }),
  ]);
  const templateTitle = new Map(templates.ok ? templates.data.map((t) => [t.id, t.title]) : []);
  const locationName = new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : []);

  return (
    <main>
      <h1>Workflow rules</h1>
      <p>
        A rule makes a task by itself when something happens, such as a booking being confirmed.{' '}
        <Link href="/app/admin/workflow-rules/new">New rule</Link> |{' '}
        <Link href="/app/admin/task-templates">Task templates</Link>
      </p>
      <p>A new rule starts switched off. It does nothing until you switch it on.</p>
      <p>
        {includeArchived ? (
          <Link href="/app/admin/workflow-rules">Hide archived</Link>
        ) : (
          <Link href="/app/admin/workflow-rules?archived=1">Show archived</Link>
        )}
      </p>
      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && res.data.rows.length === 0 ? <p>There are no rules yet.</p> : null}
      {res.ok && res.data.rows.length > 0 ? (
        <>
          <table>
            <thead>
              <tr>
                <th scope="col">Rule</th>
                <th scope="col">State</th>
                <th scope="col">When</th>
                <th scope="col">Only when</th>
                <th scope="col">Makes this task</th>
                <th scope="col">Where</th>
              </tr>
            </thead>
            <tbody>
              {res.data.rows.map((r) => (
                <tr key={r.id}>
                  <td>
                    <Link href={`/app/admin/workflow-rules/${r.id}`}>{r.name}</Link>
                    <ArchivedMark archivedAt={r.archived_at} />
                  </td>
                  <td>{r.enabled ? 'Switched on' : 'Switched off'}</td>
                  <td>{eventTypeLabel(r.event_type)}</td>
                  <td>{describeCondition(r.condition)}</td>
                  <td>{templateTitle.get(r.task_template_id) ?? 'A template'}</td>
                  <td>
                    {r.location_id
                      ? (locationName.get(r.location_id) ?? 'A location')
                      : 'All locations'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            path="/app/admin/workflow-rules"
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
