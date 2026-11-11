import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  archiveQualificationAction,
  removeHolderAction,
  saveQualificationAction,
  setHolderAction,
} from '@/experiences/admin/actions/schedule';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { ArchivedMark, ErrorMessage, Pager } from '@/experiences/admin/ui';
import { loadNames, nameOf } from '@/experiences/schedule/lookups';
import { firstParam, parsePage } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import { displayName, listPeople } from '@/domains/identity';
import { getOrganizationSettings } from '@/domains/organizations';
import {
  dateRangeText,
  listQualificationHolders,
  listQualifications,
  qualificationState,
  todayIn,
} from '@/domains/staffing';

export const metadata = { title: 'Qualifications | Rec Reports' };

const PATH = '/app/admin/qualifications';

export default async function QualificationsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canScheduleAdmin');
  const sp = await searchParams;
  const [quals, settings] = await Promise.all([
    listQualifications(orgId, true),
    getOrganizationSettings(orgId),
  ]);
  const today = todayIn(settings.ok && settings.data ? settings.data.default_timezone : 'UTC');
  if (!quals.ok) return <ErrorMessage message={quals.message} />;
  const selected = quals.data.find((q) => q.id === firstParam(sp.id));
  const page = parsePage(sp.page);
  const q = firstParam(sp.q) ?? '';

  const holders = selected ? await listQualificationHolders(orgId, selected.id, page) : null;
  const holderRows = holders && holders.ok ? holders.data.rows : [];
  const names = await loadNames(
    orgId,
    holderRows.map((h) => h.person_id),
  );
  const found =
    selected && q
      ? await listPeople(orgId, { page: 1, words: searchWords(q), status: 'active' })
      : null;

  return (
    <main>
      <h1>Qualifications</h1>
      <p>A qualification is something a person holds, such as a lifeguard certificate.</p>
      {quals.data.length === 0 ? <p>No qualifications yet.</p> : null}
      <ul>
        {quals.data.map((item) => (
          <li key={item.id}>
            <Link href={`${PATH}?id=${item.id}`}>{item.name}</Link>
            <ArchivedMark archivedAt={item.archived_at} />
          </li>
        ))}
      </ul>

      <h2>Add a qualification</h2>
      <ActionForm action={saveQualificationAction} submitLabel="Add qualification">
        <p>
          <label>
            Name <input name="name" required maxLength={100} />
          </label>
        </p>
      </ActionForm>

      {selected ? (
        <section>
          <h2>{selected.name}</h2>
          <ActionForm action={saveQualificationAction} submitLabel="Rename">
            <input type="hidden" name="qualification_id" value={selected.id} />
            <p>
              <label>
                Name <input name="name" defaultValue={selected.name} required maxLength={100} />
              </label>
            </p>
          </ActionForm>
          {selected.archived_at ? (
            <ActionForm action={archiveQualificationAction} submitLabel="Restore">
              <input type="hidden" name="qualification_id" value={selected.id} />
              <input type="hidden" name="archived" value="no" />
            </ActionForm>
          ) : (
            <ConfirmAction
              action={archiveQualificationAction}
              label="Archive"
              question={`Yes, archive ${selected.name}`}
              fields={{ qualification_id: selected.id }}
            />
          )}

          <h3>Who has it</h3>
          {holders && !holders.ok ? <ErrorMessage message={holders.message} /> : null}
          {holders && holders.ok && holderRows.length === 0 ? <p>Nobody yet.</p> : null}
          <ul>
            {holderRows.map((h) => {
              const state = qualificationState(h, today);
              return (
                <li key={h.id}>
                  <p>
                    {nameOf(names, h.person_id)}.{' '}
                    {h.expires_on
                      ? `Last valid day ${dateRangeText(h.expires_on, h.expires_on)}.`
                      : 'No expiry.'}{' '}
                    {state === 'expired' ? 'Expired.' : state === 'not_yet' ? 'Not valid yet.' : ''}
                  </p>
                  <ConfirmAction
                    action={removeHolderAction}
                    label="Remove"
                    question="Yes, remove this person"
                    fields={{ holder_id: h.id }}
                  />
                </li>
              );
            })}
          </ul>
          {holders && holders.ok ? (
            <Pager
              path={PATH}
              page={holders.data.page}
              total={holders.data.total}
              pageSize={holders.data.pageSize}
              params={{ id: selected.id, q }}
            />
          ) : null}

          <h3>Add a holder</h3>
          <form method="get">
            <input type="hidden" name="id" value={selected.id} />
            <label>
              Find a person <input name="q" defaultValue={q} maxLength={100} />
            </label>{' '}
            <button type="submit">Search</button>
          </form>
          {found && !found.ok ? <ErrorMessage message={found.message} /> : null}
          {found && found.ok && found.data.rows.length === 0 ? <p>Nobody matches.</p> : null}
          {found && found.ok && found.data.rows.length > 0 ? (
            <ActionForm action={setHolderAction} submitLabel="Save">
              <input type="hidden" name="qualification_id" value={selected.id} />
              <p>
                <label>
                  Person{' '}
                  <select name="person_id" required defaultValue="">
                    <option value="" disabled>
                      Choose a person
                    </option>
                    {found.data.rows.map((p) => (
                      <option key={p.id} value={p.id}>
                        {displayName(p)}
                      </option>
                    ))}
                  </select>
                </label>
              </p>
              <p>
                <label>
                  First valid day (optional) <input type="date" name="valid_from" />
                </label>
              </p>
              <p>
                <label>
                  Last valid day (optional) <input type="date" name="expires_on" />
                </label>
              </p>
            </ActionForm>
          ) : null}
        </section>
      ) : null}
    </main>
  );
}
