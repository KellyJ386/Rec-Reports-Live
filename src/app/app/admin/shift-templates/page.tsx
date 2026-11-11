import Link from 'next/link';
import { getLocationsWithPermission, requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { saveTemplateAction } from '@/experiences/admin/actions/schedule';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { firstParam } from '@/lib/paging';
import { listTemplates } from '@/domains/staffing';

export const metadata = { title: 'Shift templates | Rec Reports' };

export default async function ShiftTemplatesPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canSchedule');
  const sp = await searchParams;
  const places = await getLocationsWithPermission(orgId, 'staff_schedule', 'edit');
  if (!places.ok) return <ErrorMessage message={places.message} />;
  const location = places.data.find((l) => l.id === firstParam(sp.location)) ?? places.data[0];
  if (!location) return <p>You cannot manage templates at any location.</p>;
  const templates = await listTemplates(orgId, location.id, true);

  return (
    <main>
      <h1>Shift templates</h1>
      <p>A template is a set of shifts you can add to a week in one step.</p>
      <form method="get">
        <label>
          Location{' '}
          <select name="location" defaultValue={location.id}>
            {places.data.map((l) => (
              <option key={l.id} value={l.id}>
                {l.name}
              </option>
            ))}
          </select>
        </label>{' '}
        <button type="submit">Show</button>
      </form>
      {!templates.ok ? <ErrorMessage message={templates.message} /> : null}
      {templates.ok && templates.data.length === 0 ? <p>No templates yet.</p> : null}
      <ul>
        {templates.ok
          ? templates.data.map((t) => (
              <li key={t.id}>
                <Link href={`/app/admin/shift-templates/${t.id}`}>{t.name}</Link>
                <ArchivedMark archivedAt={t.archived_at} />
                {` (${t.span_days === 1 ? 'one day' : 'one week'})`}
              </li>
            ))
          : null}
      </ul>
      <h2>Add a template</h2>
      <ActionForm action={saveTemplateAction} submitLabel="Add template">
        <input type="hidden" name="location_id" value={location.id} />
        <p>
          <label>
            Name <input name="name" required maxLength={100} />
          </label>
        </p>
        <p>
          <label>
            Covers{' '}
            <select name="span_days" defaultValue="7">
              <option value="7">One week</option>
              <option value="1">One day</option>
            </select>
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
