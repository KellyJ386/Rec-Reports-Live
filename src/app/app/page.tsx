import Link from 'next/link';
import { getActiveOrganization, getSessionContext } from '@/lib/auth/session';
import { redirectIfMfaPending } from '@/lib/auth/mfa-server';
import { getAdminAccess } from '@/experiences/admin/access';
import { getMyTitleScopes, getStaffAccess } from '@/experiences/employee/access';
import {
  countUnreadMessages,
  countUnreadNotifications,
  listLiveNotices,
  listMyAcknowledgments,
  needsAcknowledgment,
} from '@/domains/communications';
import { countMyOpenTasks } from '@/domains/workflows';
import { switchOrganization } from './actions';
import { SignOutForm } from './sign-out-form';

export default async function AppHomePage() {
  await redirectIfMfaPending();
  const ctx = await getSessionContext();
  const active = await getActiveOrganization();
  const orgName = (id: string) =>
    ctx.memberships.find((m) => m.organizationId === id)?.organizationName ?? id;

  // Staff links and counts for the organization being worked in. A count that cannot be read
  // is left out rather than shown as zero.
  const orgId = active?.organizationId ?? null;
  const personId = ctx.memberships.find((m) => m.organizationId === orgId)?.personId ?? null;
  const [staff, admin] = orgId
    ? await Promise.all([getStaffAccess(orgId), getAdminAccess(orgId)])
    : [null, null];
  const [openTasks, unreadMessages, unreadNotifications, toConfirm] =
    orgId && personId && staff
      ? await Promise.all([
          staff.tasks
            ? getMyTitleScopes(orgId, personId).then((t) => countMyOpenTasks(orgId, personId, t))
            : null,
          staff.comms ? countUnreadMessages(orgId, personId) : null,
          countUnreadNotifications(orgId, personId),
          staff.comms
            ? Promise.all([listLiveNotices(orgId), listMyAcknowledgments(orgId, personId)]).then(
                ([notices, acks]) => {
                  if (!notices.ok || !acks.ok) return null;
                  const acked = new Set(acks.data.keys());
                  return notices.data.filter((n) => needsAcknowledgment(n, acked)).length;
                },
              )
            : null,
        ])
      : [null, null, null, null];
  const hasAdmin = admin !== null && Object.values(admin).some(Boolean);

  return (
    <main>
      <h1>Rec Reports</h1>
      <p>
        Signed in as {ctx.email ?? 'unknown email'}
        {ctx.isPlatformAdmin ? ' (platform admin)' : ''}.
      </p>

      <h2>Organization</h2>
      {ctx.memberships.length === 0 ? (
        <p>You are not a member of any organization yet. Ask an admin to add you.</p>
      ) : (
        <>
          <p>Working in: {active ? active.organizationName : 'none chosen'}</p>
          {ctx.memberships.length > 1 ? (
            <form action={switchOrganization}>
              <label>
                Switch to{' '}
                <select name="organizationId" defaultValue={active?.organizationId ?? ''}>
                  {active ? null : (
                    <option value="" disabled>
                      Choose one
                    </option>
                  )}
                  {ctx.memberships.map((m) => (
                    <option key={m.organizationId} value={m.organizationId}>
                      {m.organizationName}
                    </option>
                  ))}
                </select>
              </label>{' '}
              <button type="submit">Switch</button>
            </form>
          ) : null}
        </>
      )}

      <h2>Your roles</h2>
      {ctx.roleAssignments.length === 0 ? (
        <p>No roles assigned.</p>
      ) : (
        <ul>
          {ctx.roleAssignments.map((a) => (
            <li key={`${a.organizationId}:${a.roleKey}:${a.locationId ?? 'org'}`}>
              {orgName(a.organizationId)}: {a.roleName} at {a.locationName ?? 'all locations'}
            </li>
          ))}
        </ul>
      )}

      {staff ? (
        <>
          <h2>My day</h2>
          <ul>
            {staff.tasks ? (
              <li>
                <Link href="/app/my-work">My work</Link>
                {openTasks && openTasks.ok
                  ? `: ${openTasks.data} open ${openTasks.data === 1 ? 'task' : 'tasks'}`
                  : ''}
              </li>
            ) : null}
            {staff.comms ? (
              <li>
                <Link href="/app/notices">Notices</Link>
                {typeof toConfirm === 'number' ? `: ${toConfirm} to confirm` : ''}
              </li>
            ) : null}
            {staff.comms ? (
              <li>
                <Link href="/app/messages">Messages</Link>
                {unreadMessages && unreadMessages.ok ? `: ${unreadMessages.data} unread` : ''}
              </li>
            ) : null}
            <li>
              <Link href="/app/notifications">Notifications</Link>
              {unreadNotifications && unreadNotifications.ok
                ? `: ${unreadNotifications.data} unread`
                : ''}
            </li>
          </ul>
        </>
      ) : null}

      {hasAdmin ? (
        <p>
          <Link href="/app/admin">Admin</Link>
        </p>
      ) : null}

      <p>
        <Link href="/app/security">Two-step sign-in</Link>
      </p>

      <SignOutForm />
    </main>
  );
}
