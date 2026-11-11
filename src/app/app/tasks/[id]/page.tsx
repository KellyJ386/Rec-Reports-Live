import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { guidParam } from '@/experiences/admin/page-params';
import { ErrorMessage } from '@/experiences/admin/ui';
import { getLocationMap, getTaskLevels, requireStaffArea } from '@/experiences/employee/access';
import { assignTaskAction, cancelTaskAction } from '@/experiences/employee/actions/tasks';
import { Paragraphs, StaffNav, TaskButtons, dueText } from '@/experiences/employee/ui';
import { formatInZone } from '@/lib/time';
import { firstParam } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import { displayName, getPersonNames, listJobTitles, listPeople } from '@/domains/identity';
import {
  availableTaskActions,
  describeAssignee,
  getTask,
  listTaskHistory,
  priorityLabel,
  statusLabel,
  taskEventLabel,
} from '@/domains/workflows';

export const metadata = { title: 'Task | Rec Reports' };

export default async function TaskPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, access } = await requireStaffArea();
  const id = guidParam((await params).id);
  const sp = await searchParams;
  const search = (firstParam(sp.q) ?? '').trim().slice(0, 100);

  const found = await getTask(orgId, id);
  if (!found.ok) {
    return (
      <main>
        <h1>Task</h1>
        <StaffNav access={access} />
        <ErrorMessage message={found.message} />
      </main>
    );
  }
  // The database shows a task only to people who may see it. Nothing there means nothing here.
  if (!found.data) notFound();
  const task = found.data;

  const [locations, levels, history, jobTitles] = await Promise.all([
    getLocationMap(orgId),
    getTaskLevels(orgId, [task.location_id]),
    listTaskHistory(orgId, task.id),
    listJobTitles(orgId, { includeArchived: true }),
  ]);
  const location = locations.get(task.location_id);
  const timezone = location?.timezone ?? 'UTC';
  const level = levels.get(task.location_id) ?? 'none';
  const actions = availableTaskActions(task.status, level);

  const events = history.ok ? history.data : [];
  const people = await getPersonNames(
    orgId,
    [
      task.assigned_person_id,
      task.created_by_person_id,
      ...events.flatMap((e) => [e.actor_person_id, e.assigned_person_id]),
    ].filter((v): v is string => v !== null),
  );
  const personName = (pid: string | null) =>
    pid && people.ok ? (people.data[pid] ?? 'Someone') : null;
  const titleName = (tid: string | null) =>
    tid && jobTitles.ok ? (jobTitles.data.find((j) => j.id === tid)?.name ?? 'A job title') : null;

  // Managers can search for a person to give the task to.
  const words = searchWords(search);
  const matches =
    actions.assign && words.length > 0
      ? await listPeople(orgId, { page: 1, words, status: 'active' })
      : null;

  return (
    <main>
      <h1>{task.title}</h1>
      <StaffNav access={access} />

      <dl>
        <dt>Status</dt>
        <dd>{statusLabel(task.status)}</dd>
        <dt>Priority</dt>
        <dd>{priorityLabel(task.priority)}</dd>
        <dt>Where</dt>
        <dd>{location?.name ?? 'A location'}</dd>
        <dt>Due</dt>
        <dd>{dueText(task, timezone)}</dd>
        <dt>For</dt>
        <dd>
          {describeAssignee(
            personName(task.assigned_person_id),
            titleName(task.assigned_job_title_id),
            task.status,
          )}
        </dd>
        <dt>Made by</dt>
        <dd>
          {task.created_by_person_id
            ? (personName(task.created_by_person_id) ?? 'Someone')
            : 'The system'}
        </dd>
        <dt>Made</dt>
        <dd>{formatInZone(task.created_at, timezone)}</dd>
        {task.completed_at ? (
          <>
            <dt>Finished</dt>
            <dd>{formatInZone(task.completed_at, timezone)}</dd>
          </>
        ) : null}
        {task.cancelled_at ? (
          <>
            <dt>Cancelled</dt>
            <dd>{formatInZone(task.cancelled_at, timezone)}</dd>
          </>
        ) : null}
      </dl>

      <h2>What to do</h2>
      {task.instructions ? <Paragraphs text={task.instructions} /> : <p>No instructions.</p>}

      <h2>Update this task</h2>
      {!actions.start && !actions.complete && !actions.reopen && !actions.comment ? (
        <p>You can look at this task but not change it.</p>
      ) : (
        <TaskButtons taskId={task.id} actions={actions} withComment />
      )}

      {actions.assign ? (
        <>
          <h2>Give this task to someone</h2>
          <form method="get" action={`/app/tasks/${task.id}`}>
            <p>
              <label>
                Find a person by name <input name="q" defaultValue={search} maxLength={100} />
              </label>{' '}
              <button type="submit">Search</button>
            </p>
          </form>
          {matches && !matches.ok ? <ErrorMessage message={matches.message} /> : null}
          {matches && matches.ok && matches.data.rows.length === 0 ? <p>Nobody matches.</p> : null}
          <ActionForm action={assignTaskAction} submitLabel="Save">
            <input type="hidden" name="task_id" value={task.id} />
            <p>
              <label>
                Give it to{' '}
                <select name="to" defaultValue="nobody">
                  <option value="nobody">Nobody (anyone can pick it up)</option>
                  <option value="person">One person (chosen below)</option>
                  <option value="title">People with a job title (chosen below)</option>
                </select>
              </label>
            </p>
            <p>
              <label>
                Person{' '}
                <select name="person_id" defaultValue="">
                  <option value="">Choose a person</option>
                  {matches && matches.ok
                    ? matches.data.rows.map((p) => (
                        <option key={p.id} value={p.id}>
                          {displayName(p)}
                        </option>
                      ))
                    : null}
                </select>
              </label>
            </p>
            <p>
              <label>
                Job title{' '}
                <select name="job_title_id" defaultValue="">
                  <option value="">Choose a job title</option>
                  {jobTitles.ok
                    ? jobTitles.data
                        .filter((j) => j.archived_at === null)
                        .map((j) => (
                          <option key={j.id} value={j.id}>
                            {j.name}
                          </option>
                        ))
                    : null}
                </select>
              </label>
            </p>
          </ActionForm>
        </>
      ) : null}

      {actions.cancel ? (
        <details>
          <summary>Cancel this task</summary>
          <ActionForm action={cancelTaskAction} submitLabel="Cancel task">
            <input type="hidden" name="task_id" value={task.id} />
            <p>
              <label>
                Why (optional) <input name="reason" maxLength={2000} />
              </label>
            </p>
            <p>
              <label>
                <input type="checkbox" name="confirm" value="yes" required /> Yes, cancel this task
                for everyone
              </label>
            </p>
          </ActionForm>
        </details>
      ) : null}

      <h2>History</h2>
      {!history.ok ? <ErrorMessage message={history.message} /> : null}
      {history.ok && events.length === 0 ? <p>Nothing has happened yet.</p> : null}
      <ol>
        {events.map((e) => (
          <li key={e.id}>
            <p>
              {formatInZone(e.created_at, timezone)}: {taskEventLabel(e.kind)} by{' '}
              {e.actor_person_id ? (personName(e.actor_person_id) ?? 'Someone') : 'the system'}
              {e.kind === 'assigned' || e.kind === 'created'
                ? `. For: ${describeAssignee(personName(e.assigned_person_id), titleName(e.assigned_job_title_id), 'open')}`
                : ''}
              {e.from_status && e.to_status && e.from_status !== e.to_status
                ? `. ${statusLabel(e.from_status)} to ${statusLabel(e.to_status)}`
                : ''}
              .
            </p>
            {e.body ? <Paragraphs text={e.body} /> : null}
          </li>
        ))}
      </ol>

      <p>
        <Link href="/app/my-work">Back to my work</Link>
      </p>
    </main>
  );
}
