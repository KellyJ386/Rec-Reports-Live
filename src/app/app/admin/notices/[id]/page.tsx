import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { requireAdminArea } from '@/experiences/admin/access';
import {
  archiveNoticeAction,
  publishNoticeAction,
  updateNoticeDraftAction,
} from '@/experiences/admin/actions/notices';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { guidParam } from '@/experiences/admin/page-params';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { NoticeFields } from '@/experiences/admin/workflow-fields';
import { Paragraphs } from '@/experiences/employee/ui';
import { formatInZone, utcToZonedLocal } from '@/lib/time';
import { PAGE_SIZE, firstParam, parsePage } from '@/lib/paging';
import {
  describeAudience,
  getNotice,
  listAcknowledgments,
  listNoticeAudiences,
  noticeStatusLabel,
  pageOf,
  urgencyLabel,
} from '@/domains/communications';
import { getPersonNames, listJobTitles } from '@/domains/identity';
import { getOrganizationSettings, listAllLocations } from '@/domains/organizations';

export const metadata = { title: 'Notice | Rec Reports' };

export default async function AdminNoticePage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canNotices');
  const id = guidParam((await params).id);
  const sp = await searchParams;
  const res = await getNotice(orgId, id);
  if (!res.ok) {
    return (
      <main>
        <h1>Notice</h1>
        <ErrorMessage message={res.message} />
      </main>
    );
  }
  if (!res.data) notFound();
  const notice = res.data;

  const [settings, locations, titles, audiences, acks] = await Promise.all([
    getOrganizationSettings(orgId),
    listAllLocations(orgId, { includeArchived: true }),
    listJobTitles(orgId, { includeArchived: true }),
    listNoticeAudiences(orgId, notice.id),
    notice.status === 'draft' || !notice.requires_acknowledgment
      ? Promise.resolve(null)
      : listAcknowledgments(notice.id),
  ]);
  const orgTz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const homeLocation = notice.location_id
    ? locations.ok
      ? locations.data.find((l) => l.id === notice.location_id)
      : undefined
    : undefined;
  const tz = homeLocation?.timezone ?? orgTz;
  const locationNames = new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : []);
  const titleNames = new Map(titles.ok ? titles.data.map((t) => [t.id, t.name]) : []);

  // People who have not confirmed come first, then by the time they confirmed.
  const ackRows = [...(acks && acks.ok ? acks.data : [])].sort((a, b) => {
    if ((a.acknowledged_at === null) !== (b.acknowledged_at === null)) {
      return a.acknowledged_at === null ? -1 : 1;
    }
    return (a.acknowledged_at ?? '').localeCompare(b.acknowledged_at ?? '');
  });
  const confirmedCount = ackRows.filter((a) => a.acknowledged_at !== null).length;
  const shownAcks = pageOf(ackRows, parsePage(sp.page), PAGE_SIZE);
  const names = await getPersonNames(
    orgId,
    shownAcks.rows.map((a) => a.person_id),
  );

  return (
    <main>
      <h1>{notice.title}</h1>
      <p>
        <Link href="/app/admin/notices">Back to notices</Link>
      </p>
      {firstParam(sp.saved) === 'draft' ? (
        <p role="alert">
          Your notice was saved as a draft but it was not published. Check the details below and
          publish it again.
        </p>
      ) : null}
      <p>
        {noticeStatusLabel(notice.status)}. {urgencyLabel(notice.urgency)}.{' '}
        {notice.requires_acknowledgment
          ? 'People must confirm they have read it.'
          : 'No reply needed.'}
      </p>
      <p>
        From: {notice.location_id ? (homeLocation?.name ?? 'A location') : 'Whole organization'}.{' '}
        {notice.publish_at ? `Shown from ${formatInZone(notice.publish_at, tz)}. ` : ''}
        {notice.expires_at ? `Stops showing ${formatInZone(notice.expires_at, tz)}.` : ''}
      </p>

      <h2>Who it is for</h2>
      {!audiences.ok ? <ErrorMessage message={audiences.message} /> : null}
      {audiences.ok && audiences.data.length === 0 ? <p>Nobody is chosen yet.</p> : null}
      <ul>
        {audiences.ok
          ? describeAudience(audiences.data, locationNames, titleNames).map((line, i) => (
              <li key={i}>{line}</li>
            ))
          : null}
      </ul>

      {notice.status === 'draft' ? (
        <>
          <h2>Change the draft</h2>
          <p>
            To change who it is for, archive this draft and write a new notice. Times are in {tz}.
          </p>
          <ActionForm action={updateNoticeDraftAction} submitLabel="Save changes">
            <input type="hidden" name="id" value={notice.id} />
            <NoticeFields notice={notice} timezone={tz} />
            <p>
              <label>
                Show it from (optional), in {tz}{' '}
                <input
                  type="datetime-local"
                  name="publish_at"
                  defaultValue={utcToZonedLocal(notice.publish_at, tz)}
                />
              </label>
            </p>
          </ActionForm>

          <h2>Publish</h2>
          <ActionForm action={publishNoticeAction} submitLabel="Publish">
            <input type="hidden" name="id" value={notice.id} />
            <p>
              <label>
                <input type="radio" name="publish_mode" value="now" defaultChecked /> Publish now
              </label>
            </p>
            <p>
              <label>
                <input type="radio" name="publish_mode" value="later" /> Publish at this time, in{' '}
                {tz}: <input type="datetime-local" name="publish_at" />
              </label>
            </p>
          </ActionForm>
        </>
      ) : (
        <>
          <h2>Message</h2>
          <Paragraphs text={notice.body} />
        </>
      )}

      {notice.status !== 'draft' && notice.requires_acknowledgment ? (
        <>
          <h2>Who has confirmed</h2>
          {acks && !acks.ok ? <ErrorMessage message={acks.message} /> : null}
          {acks && acks.ok ? (
            <>
              <p>
                {confirmedCount} of {ackRows.length}{' '}
                {ackRows.length === 1 ? 'person has' : 'people have'} confirmed they read it. You
                only see people you are allowed to see.
              </p>
              {ackRows.length > 0 ? (
                <>
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Person</th>
                        <th scope="col">Confirmed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {shownAcks.rows.map((a) => (
                        <tr key={a.person_id}>
                          <td>{names.ok ? (names.data[a.person_id] ?? 'Someone') : 'Someone'}</td>
                          <td>
                            {a.acknowledged_at ? formatInZone(a.acknowledged_at, tz) : 'Not yet'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <Pager
                    path={`/app/admin/notices/${notice.id}`}
                    page={shownAcks.page}
                    total={shownAcks.total}
                    pageSize={shownAcks.pageSize}
                  />
                </>
              ) : null}
            </>
          ) : null}
        </>
      ) : null}

      {notice.status !== 'archived' ? (
        <>
          <h2>Archive</h2>
          <ConfirmAction
            action={archiveNoticeAction}
            label="Archive"
            question="Yes, archive this notice. People will no longer see it."
            fields={{ id: notice.id }}
          />
        </>
      ) : null}
    </main>
  );
}
