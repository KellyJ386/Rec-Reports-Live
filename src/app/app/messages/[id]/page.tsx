import Link from 'next/link';
import { notFound } from 'next/navigation';
import { guidParam } from '@/experiences/admin/page-params';
import { ErrorMessage } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { Paragraphs, StaffNav } from '@/experiences/employee/ui';
import { formatInZone } from '@/lib/time';
import { getMessage, markMessageRead } from '@/domains/communications';
import { getPersonNames } from '@/domains/identity';
import { getOrganizationSettings } from '@/domains/organizations';

export const metadata = { title: 'Message | Rec Reports' };

export default async function MessagePage({ params }: { params: Promise<{ id: string }> }) {
  const { orgId, personId, access } = await requireStaffArea();
  const id = guidParam((await params).id);
  const res = await getMessage(orgId, id);
  if (!res.ok) {
    return (
      <main>
        <h1>Message</h1>
        <StaffNav access={access} />
        <ErrorMessage message={res.message} />
      </main>
    );
  }
  // Only the sender and the recipients can read a message. Nothing there means nothing here.
  if (!res.data) notFound();
  const message = res.data;

  const mine = message.recipients.find((r) => r.person_id === personId);
  if (mine && mine.read_at === null) {
    // Opening a message marks it read. A failure here is not worth stopping the page for.
    await markMessageRead(message.id);
  }

  const [names, settings] = await Promise.all([
    getPersonNames(orgId, [
      message.sender_person_id,
      ...message.recipients.map((r) => r.person_id),
    ]),
    getOrganizationSettings(orgId),
  ]);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const nameOf = (pid: string) => (names.ok ? (names.data[pid] ?? 'Someone') : 'Someone');
  const iAmSender = message.sender_person_id === personId;

  return (
    <main>
      <h1>Message</h1>
      <StaffNav access={access} />
      <p>
        From {iAmSender ? 'you' : nameOf(message.sender_person_id)} on{' '}
        {formatInZone(message.created_at, tz)}.
      </p>
      <p>
        To:{' '}
        {message.recipients
          .map((r) => (r.person_id === personId ? 'you' : nameOf(r.person_id)))
          .join(', ')}
      </p>
      <Paragraphs text={message.body} />
      {iAmSender ? (
        <ul>
          {message.recipients.map((r) => (
            <li key={r.person_id}>
              {nameOf(r.person_id)}:{' '}
              {r.read_at ? `read ${formatInZone(r.read_at, tz)}` : 'not read yet'}
            </li>
          ))}
        </ul>
      ) : access.commsEdit ? (
        <p>
          <Link href={`/app/messages/new?to=${message.sender_person_id}`}>Reply</Link>
        </p>
      ) : null}
      <p>
        <Link href="/app/messages">Back to messages</Link>
      </p>
    </main>
  );
}
