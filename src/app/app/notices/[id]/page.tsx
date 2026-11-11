import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { guidParam } from '@/experiences/admin/page-params';
import { ErrorMessage } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { acknowledgeNoticeAction } from '@/experiences/employee/actions/notices';
import { Paragraphs, StaffNav } from '@/experiences/employee/ui';
import { formatInZone } from '@/lib/time';
import {
  getMyAcknowledgment,
  getNotice,
  urgencyFlag,
  urgencyLabel,
} from '@/domains/communications';
import { getOrganizationSettings } from '@/domains/organizations';

export const metadata = { title: 'Notice | Rec Reports' };

export default async function NoticePage({ params }: { params: Promise<{ id: string }> }) {
  const { orgId, personId, access } = await requireStaffArea();
  const id = guidParam((await params).id);
  const res = await getNotice(orgId, id);
  if (!res.ok) {
    return (
      <main>
        <h1>Notice</h1>
        <StaffNav access={access} />
        <ErrorMessage message={res.message} />
      </main>
    );
  }
  // The database shows a notice only to its audience and its managers.
  if (!res.data) notFound();
  const notice = res.data;

  const [settings, ack] = await Promise.all([
    getOrganizationSettings(orgId),
    personId ? getMyAcknowledgment(orgId, notice.id, personId) : Promise.resolve(null),
  ]);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const acknowledgedAt = ack && ack.ok ? ack.data : null;
  const live = notice.status === 'published';

  return (
    <main>
      <h1>
        {urgencyFlag(notice.urgency)}
        {notice.title}
      </h1>
      <StaffNav access={access} />
      <p>
        {urgencyLabel(notice.urgency)} notice.
        {notice.publish_at ? ` Posted ${formatInZone(notice.publish_at, tz)}.` : ''}
        {notice.expires_at ? ` Shown until ${formatInZone(notice.expires_at, tz)}.` : ''}
      </p>
      {!live ? (
        <p>This notice is not live. You may be seeing it because you manage notices.</p>
      ) : null}
      <Paragraphs text={notice.body} />

      {notice.requires_acknowledgment && live ? (
        acknowledgedAt ? (
          <p>You confirmed you have read this on {formatInZone(acknowledgedAt, tz)}.</p>
        ) : (
          <ActionForm action={acknowledgeNoticeAction} submitLabel="I have read this">
            <input type="hidden" name="notice_id" value={notice.id} />
            <p>This notice needs you to confirm that you have read it.</p>
          </ActionForm>
        )
      ) : null}

      <p>
        <Link href="/app/notices">Back to notices</Link>
      </p>
    </main>
  );
}
