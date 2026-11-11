import Link from 'next/link';
import { ActionForm } from '@/experiences/admin/action-form';
import { getLocationsWithPermission, requireAdminArea } from '@/experiences/admin/access';
import { createNoticeAction } from '@/experiences/admin/actions/notices';
import { ErrorMessage } from '@/experiences/admin/ui';
import { AudienceFields, NoticeFields } from '@/experiences/admin/workflow-fields';
import { buildAudienceOptions } from '@/domains/communications';
import { listJobTitles } from '@/domains/identity';
import { getOrganizationSettings } from '@/domains/organizations';

export const metadata = { title: 'Write a notice | Rec Reports' };

export default async function NewNoticePage() {
  const { orgId } = await requireAdminArea('canNotices');
  const [places, titles, settings] = await Promise.all([
    getLocationsWithPermission(orgId, 'communications', 'admin'),
    listJobTitles(orgId),
    getOrganizationSettings(orgId),
  ]);
  if (!places.ok) {
    return (
      <main>
        <h1>Write a notice</h1>
        <ErrorMessage message={places.message} />
      </main>
    );
  }
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const options = buildAudienceOptions(places.orgWide, places.data);

  return (
    <main>
      <h1>Write a notice</h1>
      <p>
        <Link href="/app/admin/notices">Back to notices</Link>
      </p>
      <p>
        Times are read in the organization&apos;s time zone ({tz}). If you can only send for one
        location, they are read in that location&apos;s time zone.
      </p>
      <ActionForm action={createNoticeAction} submitLabel="Save">
        <NoticeFields timezone={tz} />
        <AudienceFields options={options} titles={titles.ok ? titles.data : []} />
        <fieldset>
          <legend>When to publish</legend>
          <p>
            <label>
              <input type="radio" name="publish_mode" value="draft" defaultChecked /> Save as a
              draft. Do not publish yet.
            </label>
          </p>
          <p>
            <label>
              <input type="radio" name="publish_mode" value="now" /> Publish now
            </label>
          </p>
          <p>
            <label>
              <input type="radio" name="publish_mode" value="later" /> Publish at this time:{' '}
              <input type="datetime-local" name="publish_at" />
            </label>
          </p>
        </fieldset>
      </ActionForm>
    </main>
  );
}
