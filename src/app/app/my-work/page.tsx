import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import {
  getLocationMap,
  getMyTitleScopes,
  getTaskLevels,
  requireStaffArea,
} from '@/experiences/employee/access';
import { currentTimeMs } from '@/experiences/employee/clock';
import { StaffNav, TaskItem } from '@/experiences/employee/ui';
import { firstParam, parsePage } from '@/lib/paging';
import { getPersonNames, listJobTitles } from '@/domains/identity';
import {
  availableTaskActions,
  groupByDueBucket,
  listMyWork,
  type TaskRow,
} from '@/domains/workflows';

export const metadata = { title: 'My work | Rec Reports' };

export default async function MyWorkPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.tasks) notFound();
  const sp = await searchParams;
  const view = firstParam(sp.view) === 'done' ? 'done' : 'open';
  const page = parsePage(sp.page);

  if (!personId) {
    return (
      <main>
        <h1>My work</h1>
        <StaffNav access={access} />
        <p>
          You do not have a staff profile in this organization, so there is no work for you here.
        </p>
      </main>
    );
  }

  const [titles, locations] = await Promise.all([
    getMyTitleScopes(orgId, personId),
    getLocationMap(orgId),
  ]);
  const res = await listMyWork(orgId, personId, titles, view, page);
  const rows: TaskRow[] = res.ok ? res.data.rows : [];

  const [levels, names, jobTitles] = await Promise.all([
    getTaskLevels(
      orgId,
      rows.map((t) => t.location_id),
    ),
    getPersonNames(
      orgId,
      rows.flatMap((t) => (t.assigned_person_id ? [t.assigned_person_id] : [])),
    ),
    listJobTitles(orgId, { includeArchived: true }),
  ]);
  const personName = (id: string | null) => (id && names.ok ? (names.data[id] ?? 'Someone') : null);
  const titleName = (id: string | null) =>
    id && jobTitles.ok ? (jobTitles.data.find((j) => j.id === id)?.name ?? 'A job title') : null;

  const renderTask = (t: TaskRow) => {
    const loc = locations.get(t.location_id);
    return (
      <TaskItem
        key={t.id}
        task={t}
        context={{
          locationName: loc?.name ?? 'A location',
          timezone: loc?.timezone ?? 'UTC',
          assigneeName: personName(t.assigned_person_id),
          jobTitleName: titleName(t.assigned_job_title_id),
        }}
        actions={availableTaskActions(t.status, levels.get(t.location_id) ?? 'none')}
      />
    );
  };

  const groups =
    view === 'open'
      ? groupByDueBucket(
          rows,
          (t) => t.due_at,
          (t) => locations.get(t.location_id)?.timezone ?? 'UTC',
          currentTimeMs(),
        )
      : [];

  return (
    <main>
      <h1>My work</h1>
      <StaffNav access={access} />
      <p>
        {view === 'open' ? (
          <>
            Open tasks. <Link href="/app/my-work?view=done">Show finished tasks</Link>
          </>
        ) : (
          <>
            Finished tasks. <Link href="/app/my-work">Show open tasks</Link>
          </>
        )}
        {access.tasksEdit ? (
          <>
            {' '}
            | <Link href="/app/tasks/new">New task</Link>
          </>
        ) : null}
      </p>
      <p>
        Open tasks are the ones given to you, to one of your job titles, or to nobody yet. Times are
        in each location&apos;s time zone.
      </p>

      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && rows.length === 0 ? (
        <p>{view === 'open' ? 'You have no open tasks.' : 'You have no finished tasks yet.'}</p>
      ) : null}

      {view === 'open'
        ? groups.map((g) => (
            <section key={g.bucket}>
              <h2>{g.label}</h2>
              <ul>{g.items.map(renderTask)}</ul>
            </section>
          ))
        : rows.length > 0 && <ul>{rows.map(renderTask)}</ul>}

      {res.ok ? (
        <Pager
          path="/app/my-work"
          page={res.data.page}
          total={res.data.total}
          pageSize={res.data.pageSize}
          params={{ view: view === 'done' ? 'done' : undefined }}
        />
      ) : null}
    </main>
  );
}
