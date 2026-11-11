import Link from 'next/link';
import { z } from 'zod';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { ErrorMessage } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { sendMessageAction } from '@/experiences/employee/actions/messages';
import { StaffNav } from '@/experiences/employee/ui';
import { buildHref, firstParam } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import {
  MAX_RECIPIENTS,
  addRecipient,
  parseRecipientIds,
  removeRecipient,
} from '@/domains/communications';
import { displayName, getPersonNames, listPeople } from '@/domains/identity';

export const metadata = { title: 'Write a message | Rec Reports' };

export default async function NewMessagePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.commsEdit) notFound();
  const sp = await searchParams;
  const search = (firstParam(sp.q) ?? '').trim().slice(0, 100);
  const replyParsed = z.guid().safeParse(firstParam(sp.replyTo));
  const replyTo = replyParsed.success ? replyParsed.data : undefined;
  const requested = parseRecipientIds(sp.to).filter((id) => id !== personId);

  // Only people the database lets this person read can be named here; the rest are dropped.
  const names = await getPersonNames(orgId, requested);
  const chosen = names.ok ? requested.filter((id) => names.data[id] !== undefined) : [];

  const words = searchWords(search);
  const found =
    words.length > 0 ? await listPeople(orgId, { page: 1, words, status: 'active' }) : null;
  const matches = found && found.ok ? found.data.rows.filter((p) => p.id !== personId) : [];

  const href = (ids: string[], q: string) =>
    buildHref('/app/messages/new', { to: ids.join(','), q: q || undefined, replyTo });

  return (
    <main>
      <h1>Write a message</h1>
      <StaffNav access={access} />
      <p>Pick who it is for first, then write it. Only you and those people can read it.</p>

      <h2>Who it is for</h2>
      {chosen.length === 0 ? <p>Nobody chosen yet.</p> : null}
      <ul>
        {chosen.map((id) => (
          <li key={id}>
            {names.ok ? names.data[id] : 'Someone'}{' '}
            <Link href={href(removeRecipient(chosen, id), search)}>Remove</Link>
          </li>
        ))}
      </ul>

      <form method="get" action="/app/messages/new">
        <input type="hidden" name="to" value={chosen.join(',')} />
        {replyTo ? <input type="hidden" name="replyTo" value={replyTo} /> : null}
        <p>
          <label>
            Find a person by name <input name="q" defaultValue={search} maxLength={100} />
          </label>{' '}
          <button type="submit">Search</button>
        </p>
      </form>
      {found && !found.ok ? <ErrorMessage message={found.message} /> : null}
      {found && found.ok && matches.length === 0 ? <p>Nobody matches.</p> : null}
      <ul>
        {matches.map((p) => (
          <li key={p.id}>
            {displayName(p)}{' '}
            {chosen.includes(p.id) ? (
              '(chosen)'
            ) : chosen.length >= MAX_RECIPIENTS ? (
              '(too many chosen)'
            ) : (
              <Link href={href(addRecipient(chosen, p.id), search)}>Add</Link>
            )}
          </li>
        ))}
      </ul>

      <h2>Your message</h2>
      <ActionForm action={sendMessageAction} submitLabel="Send">
        <input type="hidden" name="to" value={chosen.join(',')} />
        {replyTo ? <input type="hidden" name="reply_to" value={replyTo} /> : null}
        <p>
          <label>
            Message <textarea name="body" required rows={6} maxLength={4000} />
          </label>
        </p>
      </ActionForm>
      <p>
        <Link href="/app/messages">Back to messages</Link>
      </p>
    </main>
  );
}
