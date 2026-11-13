import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';

export default async function AdminIndexPage() {
  const { orgName, access } = await requireAdminArea();
  const nothing = !Object.values(access).some(Boolean);
  return (
    <main>
      <h1>Admin</h1>
      <p>Working in: {orgName}</p>
      {nothing ? <p>You do not have any admin screens. Ask an admin if you need one.</p> : null}
      <ul>
        {access.canLocations ? (
          <li>
            <Link href="/app/admin/locations">Locations</Link>: add and edit locations, their
            spaces, hours and closures
          </li>
        ) : null}
        {access.canSpaces ? (
          <li>
            <Link href="/app/admin/spaces">Spaces and closures</Link>: the locations where you
            manage spaces, hours and closures
          </li>
        ) : null}
        {access.canSpaceKinds ? (
          <li>
            <Link href="/app/admin/space-kinds">Space kinds</Link>: the kinds of space you can pick
            (pool, gym, court)
          </li>
        ) : null}
        {access.canPeople ? (
          <li>
            <Link href="/app/admin/people">People</Link>: staff list, roles, job titles and access
          </li>
        ) : null}
        {access.canPeople ? (
          <li>
            <Link href="/app/admin/roles">Roles</Link>: what each role can do
          </li>
        ) : null}
        {access.isOrgAdmin ? (
          <li>
            <Link href="/app/admin/job-titles">Job titles</Link>: the titles used to route tasks and
            messages
          </li>
        ) : null}
        {access.canTasks ? (
          <li>
            <Link href="/app/admin/tasks">Tasks</Link>: every task at a location, with filters; give
            tasks to people or cancel them
          </li>
        ) : null}
        {access.canTasks ? (
          <li>
            <Link href="/app/admin/task-templates">Task templates</Link>: tasks that workflow rules
            can make
          </li>
        ) : null}
        {access.canTasks ? (
          <li>
            <Link href="/app/admin/workflow-rules">Workflow rules</Link>: make tasks by themselves
            when something happens
          </li>
        ) : null}
        {access.canNotices ? (
          <li>
            <Link href="/app/admin/notices">Notices</Link>: write notices, choose who gets them, see
            who has confirmed
          </li>
        ) : null}
        {access.canSchedule ? (
          <li>
            <Link href="/app/admin/schedule">Schedule</Link>: build a week, assign shifts and
            publish
          </li>
        ) : null}
        {access.canScheduleRequests ? (
          <li>
            <Link href="/app/admin/schedule/requests">Schedule requests</Link>: swaps, drops, open
            shift claims and time off waiting for you
          </li>
        ) : null}
        {access.canScheduleAdmin ? (
          <li>
            <Link href="/app/admin/positions">Positions</Link>: the jobs people are scheduled for
          </li>
        ) : null}
        {access.canScheduleAdmin ? (
          <li>
            <Link href="/app/admin/qualifications">Qualifications</Link>: certificates and who holds
            them
          </li>
        ) : null}
        {access.canSchedule ? (
          <li>
            <Link href="/app/admin/shift-templates">Shift templates</Link>: a week or a day you can
            copy onto a schedule
          </li>
        ) : null}
        {access.canAudit ? (
          <li>
            <Link href="/app/admin/jobs">Failed jobs</Link>: notices, tasks and messages that did
            not go out, and a way to retry
          </li>
        ) : null}
        {access.canAudit ? (
          <li>
            <Link href="/app/admin/audit">Audit log</Link>: who changed what, and when
          </li>
        ) : null}
        {access.isOrgAdmin ? (
          <li>
            <Link href="/app/admin/settings">Organization settings</Link>: name, time zone, week
            start
          </li>
        ) : null}
      </ul>
    </main>
  );
}
