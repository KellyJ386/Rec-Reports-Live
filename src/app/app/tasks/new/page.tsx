import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { getLocationsWithPermission } from '@/experiences/admin/access';
import { ErrorMessage } from '@/experiences/admin/ui';
import { getTaskLevels, requireStaffArea } from '@/experiences/employee/access';
import { createTaskAction } from '@/experiences/employee/actions/tasks';
import { StaffNav } from '@/experiences/employee/ui';
import { firstParam } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import { displayName, listJobTitles, listPeople } from '@/domains/identity';
import { listSpaces } from '@/domains/resources';
import { TASK_PRIORITIES, priorityLabel } from '@/domains/workflows';

export const metadata = { title: 'New task | Rec Reports' };

export default async function NewTaskPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, access } = await requireStaffArea();
  if (!access.tasksEdit) notFound();
  const sp = await searchParams;

  const locations = await getLocationsWithPermission(orgId, 'tasks', 'edit');
  if (!locations.ok) {
    return (
      <main>
        <h1>New task</h1>
        <StaffNav access={access} />
        <ErrorMessage message={locations.message} />
      </main>
    );
  }
  const options = locations.data;
  const requested = firstParam(sp.location);
  const chosen =
    options.find((l) => l.id === requested) ?? (options.length === 1 ? options[0] : undefined);

  if (!chosen) {
    return (
      <main>
        <h1>New task</h1>
        <StaffNav access={access} />
        {options.length === 0 ? (
          <p>You cannot make tasks at any location.</p>
        ) : (
          <form method="get" action="/app/tasks/new">
            <p>
              <label>
                Where is the task?{' '}
                <select name="location" required defaultValue="">
                  <option value="" disabled>
                    Choose a location
                  </option>
                  {options.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name}
                    </option>
                  ))}
                </select>
              </label>{' '}
              <button type="submit">Continue</button>
            </p>
          </form>
        )}
      </main>
    );
  }

  const search = (firstParam(sp.q) ?? '').trim().slice(0, 100);
  const levels = await getTaskLevels(orgId, [chosen.id]);
  const canAssign = levels.get(chosen.id) === 'admin';
  const words = searchWords(search);
  const [spaces, titles, matches] = await Promise.all([
    listSpaces(orgId, chosen.id),
    canAssign ? listJobTitles(orgId) : Promise.resolve(null),
    canAssign && words.length > 0
      ? listPeople(orgId, { page: 1, words, status: 'active' })
      : Promise.resolve(null),
  ]);

  return (
    <main>
      <h1>New task</h1>
      <StaffNav access={access} />
      <p>
        Location: {chosen.name}.{' '}
        {options.length > 1 ? <Link href="/app/tasks/new">Choose another location</Link> : null}
      </p>

      {canAssign ? (
        <form method="get" action="/app/tasks/new">
          <input type="hidden" name="location" value={chosen.id} />
          <p>
            <label>
              To give the task to a person, find them first{' '}
              <input name="q" defaultValue={search} maxLength={100} />
            </label>{' '}
            <button type="submit">Search</button>
          </p>
          {matches && matches.ok && matches.data.rows.length === 0 ? <p>Nobody matches.</p> : null}
        </form>
      ) : null}

      <ActionForm action={createTaskAction} submitLabel="Make task">
        <input type="hidden" name="location_id" value={chosen.id} />
        <p>
          <label>
            Title <input name="title" required maxLength={200} />
          </label>
        </p>
        <p>
          <label>
            What to do (optional) <textarea name="instructions" rows={4} maxLength={4000} />
          </label>
        </p>
        <p>
          <label>
            Priority{' '}
            <select name="priority" defaultValue="normal">
              {TASK_PRIORITIES.map((p) => (
                <option key={p} value={p}>
                  {priorityLabel(p)}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Due (optional), in the time zone of {chosen.name}: {chosen.timezone}{' '}
            <input type="datetime-local" name="due" />
          </label>
        </p>
        <p>
          <label>
            Space (optional){' '}
            <select name="space_id" defaultValue="">
              <option value="">No particular space</option>
              {spaces.ok
                ? spaces.data
                    .filter((s) => s.archived_at === null)
                    .map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.name}
                      </option>
                    ))
                : null}
            </select>
          </label>
        </p>
        <p>
          <label>
            Who does it{' '}
            <select name="to" defaultValue="me">
              <option value="me">Me</option>
              <option value="nobody">Nobody yet (anyone can pick it up)</option>
              {canAssign ? <option value="person">One person (chosen below)</option> : null}
              {canAssign ? (
                <option value="title">People with a job title (chosen below)</option>
              ) : null}
            </select>
          </label>
        </p>
        {canAssign ? (
          <>
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
                  {titles && titles.ok
                    ? titles.data.map((j) => (
                        <option key={j.id} value={j.id}>
                          {j.name}
                        </option>
                      ))
                    : null}
                </select>
              </label>
            </p>
          </>
        ) : null}
      </ActionForm>
    </main>
  );
}
