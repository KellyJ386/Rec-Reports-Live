import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { formatInZone } from '@/lib/time';
import { firstParam, parsePage } from '@/lib/paging';
import { listManagedNotices, noticeStatusLabel, urgencyFlag } from '@/domains/communications';
import { getOrganizationSettings, listAllLocations } from '@/domains/organizations';

export const metadata = { title: 'Notices | Rec Reports' };

const TABS = [
  { value: 'draft', label: 'Drafts' },
  { value: 'published', label: 'Published' },
  { value: 'archived', label: 'Archived' },
] as const;

export default async function AdminNoticesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canNotices');
  const sp = await searchParams;
  const status = TABS.find((t) => t.value === firstParam(sp.status))?.value ?? 'published';
  const [res, settings, locations] = await Promise.all([
    listManagedNotices(orgId, status, parsePage(sp.page)),
    getOrganizationSettings(orgId),
    listAllLocations(orgId, { includeArchived: true }),
  ]);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const locationName = new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : []);

  return (
    <main>
      <h1>Notices</h1>
      <p>
        <Link href="/app/admin/notices/new">Write a notice</Link>
      </p>
      <p>
        {TABS.map((t, i) => (
          <span key={t.value}>
            {i > 0 ? ' | ' : ''}
            {t.value === status ? (
              <strong>{t.label}</strong>
            ) : (
              <Link href={`/app/admin/notices?status=${t.value}`}>{t.label}</Link>
            )}
          </span>
        ))}
      </p>
      <p>Times are shown in {tz}, the organization&apos;s time zone.</p>
      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && res.data.rows.length === 0 ? <p>There are no notices here.</p> : null}
      {res.ok && res.data.rows.length > 0 ? (
        <>
          <table>
            <thead>
              <tr>
                <th scope="col">Notice</th>
                <th scope="col">Status</th>
                <th scope="col">From</th>
                <th scope="col">Shown on</th>
                <th scope="col">Needs a reply</th>
              </tr>
            </thead>
            <tbody>
              {res.data.rows.map((n) => (
                <tr key={n.id}>
                  <td>
                    <Link href={`/app/admin/notices/${n.id}`}>
                      {urgencyFlag(n.urgency)}
                      {n.title}
                    </Link>
                  </td>
                  <td>{noticeStatusLabel(n.status)}</td>
                  <td>
                    {n.location_id
                      ? (locationName.get(n.location_id) ?? 'A location')
                      : 'Whole organization'}
                  </td>
                  <td>{n.publish_at ? formatInZone(n.publish_at, tz) : 'Not set'}</td>
                  <td>{n.requires_acknowledgment ? 'Yes, people must confirm' : 'No'}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            path="/app/admin/notices"
            page={res.data.page}
            total={res.data.total}
            pageSize={res.data.pageSize}
            params={{ status }}
          />
        </>
      ) : null}
    </main>
  );
}
