import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  archivePersonAction,
  disableLoginAction,
  enableLoginAction,
  restorePersonAction,
  sendInviteAction,
  updatePersonAction,
} from '@/experiences/admin/actions/people';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { PersonFields } from '@/experiences/admin/fields';
import { guidParam } from '@/experiences/admin/page-params';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { displayName, getAccountStatus, getPerson, inviteView } from '@/domains/identity';

const ACCOUNT_TEXT = {
  active: 'Has a login account.',
  disabled: 'Has a login account, but it is turned off.',
  none: 'No login account yet.',
} as const;

function LoginActions({
  personId,
  email,
  view,
  name,
}: {
  personId: string;
  email: string | null;
  view: ReturnType<typeof inviteView>;
  name: string;
}) {
  switch (view) {
    case 'can_invite':
      return (
        <ActionForm action={sendInviteAction} submitLabel="Send invite">
          <input type="hidden" name="id" value={personId} />
          <p>We will email {email} a link to choose a password.</p>
        </ActionForm>
      );
    case 'no_email':
      return <p>Add an email address under Details to send an invite.</p>;
    case 'can_resend':
      return (
        <>
          <ActionForm action={sendInviteAction} submitLabel="Resend invite">
            <input type="hidden" name="id" value={personId} />
            <p>Sends the link again. It only works until they have accepted.</p>
          </ActionForm>
          <ConfirmAction
            action={disableLoginAction}
            label="Disable login"
            question={`Yes, turn off ${name}'s login`}
            fields={{ id: personId }}
          />
        </>
      );
    case 'disabled':
      return (
        <ActionForm action={enableLoginAction} submitLabel="Enable login">
          <input type="hidden" name="id" value={personId} />
        </ActionForm>
      );
    default:
      return null;
  }
}

export default async function PersonPage({ params }: { params: Promise<{ personId: string }> }) {
  const personId = guidParam((await params).personId);
  const { orgId, access } = await requireAdminArea('canPeople');
  const [person, account] = await Promise.all([
    getPerson(orgId, personId),
    access.canPeopleAdmin ? getAccountStatus(orgId, personId) : Promise.resolve(null),
  ]);
  if (!person.ok) return <ErrorMessage message={person.message} />;
  if (!person.data) notFound();
  const p = person.data;

  return (
    <main>
      <h1>
        {displayName(p)}
        <ArchivedMark archivedAt={p.archived_at} />
      </h1>
      <p>
        <Link href="/app/admin/people">All people</Link>
        {' | '}
        <Link href={`/app/admin/people/${p.id}/access`}>Roles, job titles and access</Link>
      </p>

      {account ? (
        <>
          <h2>Login</h2>
          {account.ok ? (
            <p>{ACCOUNT_TEXT[account.data]}</p>
          ) : (
            <ErrorMessage message={account.message} />
          )}
          {account.ok ? (
            <LoginActions
              personId={p.id}
              email={p.email}
              view={inviteView({
                archived: p.archived_at !== null,
                email: p.email,
                account: account.data,
              })}
              name={displayName(p)}
            />
          ) : null}
        </>
      ) : null}

      <h2>Details</h2>
      {access.canPeopleAdmin ? (
        <ActionForm action={updatePersonAction} submitLabel="Save">
          <input type="hidden" name="id" value={p.id} />
          <PersonFields person={p} />
        </ActionForm>
      ) : (
        <dl>
          <dt>Email</dt>
          <dd>{p.email ?? 'none'}</dd>
          <dt>Phone</dt>
          <dd>{p.phone ?? 'none'}</dd>
          <dt>Employee number</dt>
          <dd>{p.employee_number ?? 'none'}</dd>
        </dl>
      )}

      {access.canPeopleAdmin ? (
        <>
          <h2>{p.archived_at ? 'Restore' : 'Archive'}</h2>
          {p.archived_at ? (
            <ActionForm action={restorePersonAction} submitLabel="Restore this person">
              <input type="hidden" name="id" value={p.id} />
            </ActionForm>
          ) : (
            <>
              <p>
                An archived person loses access to the organization. You can restore them later.
              </p>
              <ConfirmAction
                action={archivePersonAction}
                label="Archive this person"
                question={`Yes, archive ${displayName(p)}`}
                fields={{ id: p.id }}
              />
            </>
          )}
        </>
      ) : null}
    </main>
  );
}
