import Link from 'next/link';
import { getLocationsWithPermission, requireAdminArea } from '@/experiences/admin/access';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { dueText } from '@/experiences/employee/ui';
import { firstParam, parsePage } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import { getPersonNames, listJobTitles, listPeople } from '@/domains/identity';
import {
  BOARD_STATUS_OPTIONS,
  describeAssignee,
  listBoardTasks,
  parseBoardFilters,
  priorityLabel,
  statusLabel,
  type BoardQuery,
} from '@/domains/workflows';

export const metadata = { title: 'Tasks | Rec Reports' };

export default async function TaskBoardPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canTasks');
  const sp = await searchParams;
  const page = parsePage(sp.page);
  const filters = parseBoardFilters(sp);

  const places = await getLocationsWithPermission(orgId, 'tasks', 'admin');
  if (!places.ok) {
    return (
      <main>
        <h1>Tasks</h1>
        <ErrorMessage message={places.message} />
      </main>
    );
  }
  const locations = places.data;
  const location = locations.find((l) => l.id === firstParam(sp.location)) ?? locations[0];
  if (!location) {
    return (
      <main>
        <h1>Tasks</h1>
        <p>You do not manage tasks at any location.</p>
      </main>
    );
  }

  // The assignee filter is a name search; it resolves to the people the database lets you see.
  let assignee: BoardQuery['assignee'] = { kind: 'any' };
  let assigneeProblem: string | null = null;
  if (filters.assignee === 'nobody') assignee = { kind: 'nobody' };
  if (filters.assignee === 'search') {
    const words = searchWords(filters.assigneeSearch);
    if (words.length === 0) {
      assigneeProblem = 'Type at least two letters of a name.';
    } else {
      const people = await listPeople(orgId, { page: 1, words, status: 'all' });
      assignee = { kind: 'people', ids: people.ok ? people.data.rows.map((p) => p.id) : [] };
      if (people.ok && people.data.rows.length === 0) assigneeProblem = 'Nobody has that name.';
    }
  }

  const [titles, res] = await Promise.all([
    listJobTitles(orgId, { includeArchived: true }),
    listBoardTasks(
      orgId,
      {
        locationId: location.id,
        status: filters.status,
        assignee,
        jobTitleId: filters.jobTitleId,
        overdue: filters.overdue,
      },
      page,
    ),
  ]);
  const rows = res.ok ? res.data.rows : [];
  const names = await getPersonNames(
    orgId,
    rows.flatMap((t) => (t.assigned_person_id ? [t.assigned_person_id] : [])),
  );

  const pagerParams = {
    location: location.id,
    status: filters.status === 'active' ? undefined : filters.status,
    aq: filters.assigneeSearch || undefined,
    assignee: filters.assignee === 'nobody' ? 'nobody' : undefined,
    title: filters.jobTitleId ?? undefined,
    overdue: filters.overdue ? '1' : undefined,
  };

  return (
    <main>
      <h1>Tasks</h1>
      <p>
        <Link href={`/app/tasks/new?location=${location.id}`}>New task</Link>
      </p>

      <form method="get" action="/app/admin/tasks">
        <p>
          <label>
            Location{' '}
            <select name="location" defaultValue={location.id}>
              {locations.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </label>{' '}
          <label>
            Show{' '}
            <select name="status" defaultValue={filters.status}>
              {BOARD_STATUS_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Given to (name){' '}
            <input name="aq" defaultValue={filters.assigneeSearch} maxLength={100} />
          </label>{' '}
          <label>
            <input
              type="checkbox"
              name="assignee"
              value="nobody"
              defaultChecked={filters.assignee === 'nobody'}
            />{' '}
            Nobody is assigned
          </label>{' '}
          <label>
            Job title{' '}
            <select name="title" defaultValue={filters.jobTitleId ?? ''}>
              <option value="">Any</option>
              {titles.ok
                ? titles.data.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.name}
                    </option>
                  ))
                : null}
            </select>
          </label>{' '}
          <label>
            <input type="checkbox" name="overdue" value="1" defaultChecked={filters.overdue} />{' '}
            Overdue only
          </label>{' '}
          <button type="submit">Show</button>
        </p>
      </form>
      <p>
        Times are shown in the time zone of {location.name}: {location.timezone}.
      </p>

      {assigneeProblem ? <ErrorMessage message={assigneeProblem} /> : null}
      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && rows.length === 0 ? <p>No tasks match.</p> : null}
      {rows.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th scope="col">Task</th>
              <th scope="col">Status</th>
              <th scope="col">Priority</th>
              <th scope="col">Due</th>
              <th scope="col">Given to</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((t) => (
              <tr key={t.id}>
                <td>
                  <Link href={`/app/tasks/${t.id}`}>{t.title}</Link>
                </td>
                <td>{statusLabel(t.status)}</td>
                <td>{priorityLabel(t.priority)}</td>
                <td>{dueText(t, location.timezone)}</td>
                <td>
                  {describeAssignee(
                    t.assigned_person_id && names.ok
                      ? (names.data[t.assigned_person_id] ?? 'Someone')
                      : null,
                    t.assigned_job_title_id && titles.ok
                      ? (titles.data.find((j) => j.id === t.assigned_job_title_id)?.name ??
                          'A job title')
                      : null,
                    t.status,
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {res.ok ? (
        <Pager
          path="/app/admin/tasks"
          page={res.data.page}
          total={res.data.total}
          pageSize={res.data.pageSize}
          params={pagerParams}
        />
      ) : null}
    </main>
  );
}
