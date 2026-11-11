import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { getLocationMap, requireStaffArea } from '@/experiences/employee/access';
import { StaffNav } from '@/experiences/employee/ui';
import { formatInZone } from '@/lib/time';
import { PAGE_SIZE, parsePage } from '@/lib/paging';
import {
  acknowledgedIds,
  listMyNotices,
  needsAcknowledgment,
  orderNoticesForReader,
  pageOf,
  urgencyFlag,
} from '@/domains/communications';
import { getOrganizationSettings } from '@/domains/organizations';

export const metadata = { title: 'Notices | Rec Reports' };

export default async function NoticesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, access } = await requireStaffArea();
  if (!access.comms) notFound();
  const page = parsePage((await searchParams).page);

  const [notices, settings, locations] = await Promise.all([
    listMyNotices(orgId),
    getOrganizationSettings(orgId),
    getLocationMap(orgId),
  ]);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';

  const acked = notices.ok ? acknowledgedIds(notices.data) : new Set<string>();
  const ordered = notices.ok ? orderNoticesForReader(notices.data, acked) : [];
  const shown = pageOf(ordered, page, PAGE_SIZE);

  return (
    <main>
      <h1>Notices</h1>
      <StaffNav access={access} />
      {!notices.ok ? <ErrorMessage message={notices.message} /> : null}
      {notices.ok && ordered.length === 0 ? <p>There are no notices for you right now.</p> : null}
      <p>Notices that need your answer come first. Times are in {tz}.</p>
      <ul>
        {shown.rows.map((n) => (
          <li key={n.id}>
            <p>
              <Link href={`/app/notices/${n.id}`}>
                {urgencyFlag(n.urgency)}
                {n.title}
              </Link>
            </p>
            <p>
              {n.publish_at ? `Posted ${formatInZone(n.publish_at, tz)}. ` : ''}
              {n.location_id ? `${locations.get(n.location_id)?.name ?? 'A location'}. ` : ''}
              {needsAcknowledgment(n, acked)
                ? 'You still need to confirm you have read this.'
                : n.requires_acknowledgment
                  ? 'You have confirmed you read this.'
                  : ''}
            </p>
          </li>
        ))}
      </ul>
      <Pager path="/app/notices" page={shown.page} total={shown.total} pageSize={shown.pageSize} />
    </main>
  );
}
