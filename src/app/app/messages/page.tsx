import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { StaffNav } from '@/experiences/employee/ui';
import { formatInZone } from '@/lib/time';
import { firstParam, parsePage } from '@/lib/paging';
import { excerpt, listInbox, listSent } from '@/domains/communications';
import { getPersonNames } from '@/domains/identity';
import { getOrganizationSettings } from '@/domains/organizations';

export const metadata = { title: 'Messages | Rec Reports' };

export default async function MessagesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.comms) notFound();
  const sp = await searchParams;
  const view = firstParam(sp.view) === 'sent' ? 'sent' : 'inbox';
  const page = parsePage(sp.page);

  const settings = await getOrganizationSettings(orgId);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';

  const nav = (
    <>
      <h1>Messages</h1>
      <StaffNav access={access} />
      <p>
        {view === 'inbox' ? 'Inbox' : <Link href="/app/messages">Inbox</Link>} |{' '}
        {view === 'sent' ? 'Sent' : <Link href="/app/messages?view=sent">Sent</Link>}
        {access.commsEdit ? (
          <>
            {' '}
            | <Link href="/app/messages/new">Write a message</Link>
          </>
        ) : null}
      </p>
      <p>Only you and the people on a message can read it. Managers and admins cannot.</p>
    </>
  );

  if (!personId) {
    return (
      <main>
        {nav}
        <p>You do not have a staff profile in this organization, so you have no messages here.</p>
      </main>
    );
  }

  if (view === 'inbox') {
    const res = await listInbox(orgId, personId, page);
    const rows = res.ok ? res.data.rows : [];
    const names = await getPersonNames(
      orgId,
      rows.map((r) => r.sender_person_id),
    );
    return (
      <main>
        {nav}
        {!res.ok ? <ErrorMessage message={res.message} /> : null}
        {res.ok && rows.length === 0 ? <p>Your inbox is empty.</p> : null}
        <ul>
          {rows.map((r) => (
            <li key={r.message_id}>
              <p>
                <Link href={`/app/messages/${r.message_id}`}>
                  {r.read_at ? '' : 'NEW: '}From{' '}
                  {names.ok ? (names.data[r.sender_person_id] ?? 'Someone') : 'Someone'}
                </Link>{' '}
                ({formatInZone(r.received_at, tz)})
              </p>
              <p>{excerpt(r.body)}</p>
            </li>
          ))}
        </ul>
        {res.ok ? (
          <Pager
            path="/app/messages"
            page={res.data.page}
            total={res.data.total}
            pageSize={res.data.pageSize}
          />
        ) : null}
      </main>
    );
  }

  const res = await listSent(orgId, personId, page);
  const rows = res.ok ? res.data.rows : [];
  const names = await getPersonNames(
    orgId,
    rows.flatMap((r) => r.recipients.map((x) => x.person_id)),
  );
  const nameOf = (id: string) => (names.ok ? (names.data[id] ?? 'Someone') : 'Someone');
  return (
    <main>
      {nav}
      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && rows.length === 0 ? <p>You have not sent any messages.</p> : null}
      <ul>
        {rows.map((r) => {
          const unread = r.recipients.filter((x) => x.read_at === null).length;
          return (
            <li key={r.message_id}>
              <p>
                <Link href={`/app/messages/${r.message_id}`}>
                  To {r.recipients.map((x) => nameOf(x.person_id)).join(', ') || 'nobody'}
                </Link>{' '}
                ({formatInZone(r.created_at, tz)})
              </p>
              <p>{excerpt(r.body)}</p>
              <p>
                {unread === 0
                  ? 'Everyone has read it.'
                  : `${unread} of ${r.recipients.length} have not read it yet.`}
              </p>
            </li>
          );
        })}
      </ul>
      {res.ok ? (
        <Pager
          path="/app/messages"
          page={res.data.page}
          total={res.data.total}
          pageSize={res.data.pageSize}
          params={{ view: 'sent' }}
        />
      ) : null}
    </main>
  );
}
