import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  addTemplateItemAction,
  archiveTemplateAction,
  removeTemplateItemAction,
  saveTemplateAction,
} from '@/experiences/admin/actions/schedule';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { loadNames, nameOf } from '@/experiences/schedule/lookups';
import { listLocationPeople } from '@/experiences/schedule/people';
import { displayName } from '@/domains/identity';
import { WEEK_START_OPTIONS, formatClock, toTimeInput } from '@/lib/time';
import { getOrganizationSettings } from '@/domains/organizations';
import { getTemplate, listPositions, listTemplateItems } from '@/domains/staffing';

export const metadata = { title: 'Shift template | Rec Reports' };

export default async function TemplatePage({ params }: { params: Promise<{ id: string }> }) {
  const { orgId } = await requireAdminArea('canSchedule');
  const { id } = await params;
  if (!/^[0-9a-f-]{36}$/i.test(id)) notFound();
  const template = await getTemplate(orgId, id);
  if (!template.ok) return <ErrorMessage message={template.message} />;
  if (!template.data) notFound();
  const t = template.data;
  const [items, positions, people] = await Promise.all([
    listTemplateItems(orgId, t.id),
    listPositions(orgId, { locationId: t.location_id }),
    listLocationPeople(orgId, t.location_id),
  ]);
  const rows = items.ok ? items.data : [];
  const names = await loadNames(
    orgId,
    rows.map((r) => r.assigned_person_id),
  );
  const posName = new Map(positions.ok ? positions.data.map((p) => [p.id, p.name]) : []);
  const weekly = t.span_days === 7;
  const settings = await getOrganizationSettings(orgId);
  const startsOn = settings.ok && settings.data ? settings.data.week_starts_on : 0;
  // Day 0 is the first day of the week (the organization's week start).
  const dayName = (offset: number) =>
    WEEK_START_OPTIONS[(startsOn + offset) % 7]?.label ?? `Day ${offset + 1}`;

  return (
    <main>
      <h1>
        {t.name}
        <ArchivedMark archivedAt={t.archived_at} />
      </h1>
      <p>
        <Link href="/app/admin/shift-templates">All templates</Link>. Times are the wall-clock time
        at the location.
      </p>
      <ActionForm action={saveTemplateAction} submitLabel="Rename">
        <input type="hidden" name="template_id" value={t.id} />
        <input type="hidden" name="location_id" value={t.location_id} />
        <p>
          <label>
            Name <input name="name" defaultValue={t.name} required maxLength={100} />
          </label>
        </p>
      </ActionForm>
      {t.archived_at ? (
        <ActionForm action={archiveTemplateAction} submitLabel="Restore">
          <input type="hidden" name="template_id" value={t.id} />
          <input type="hidden" name="location_id" value={t.location_id} />
          <input type="hidden" name="archived" value="no" />
        </ActionForm>
      ) : (
        <ConfirmAction
          action={archiveTemplateAction}
          label="Archive"
          question="Yes, archive this template"
          fields={{ template_id: t.id, location_id: t.location_id }}
        />
      )}

      <h2>Shifts</h2>
      {!items.ok ? <ErrorMessage message={items.message} /> : null}
      {items.ok && rows.length === 0 ? <p>No shifts in this template yet.</p> : null}
      <ul>
        {rows.map((r) => (
          <li key={r.id}>
            <p>
              {weekly ? `${dayName(r.day_offset)}, ` : ''}
              {formatClock(r.start_time)} for {r.duration_minutes} minutes.{' '}
              {posName.get(r.position_id) ?? 'Position'}.{' '}
              {r.assigned_person_id ? nameOf(names, r.assigned_person_id) : 'Open'}.
            </p>
            <ActionForm action={removeTemplateItemAction} submitLabel="Remove">
              <input type="hidden" name="item_id" value={r.id} />
              <input type="hidden" name="template_id" value={t.id} />
            </ActionForm>
          </li>
        ))}
      </ul>

      <h2>Add a shift</h2>
      <ActionForm action={addTemplateItemAction} submitLabel="Add shift">
        <input type="hidden" name="template_id" value={t.id} />
        <input type="hidden" name="location_id" value={t.location_id} />
        <p>
          <label>
            Position{' '}
            <select name="position_id" required defaultValue="">
              <option value="" disabled>
                Choose a position
              </option>
              {positions.ok
                ? positions.data.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))
                : null}
            </select>
          </label>
        </p>
        {weekly ? (
          <p>
            <label>
              Day{' '}
              <select name="day_offset" defaultValue="0">
                {WEEK_START_OPTIONS.map((_, i) => (
                  <option key={i} value={i}>
                    {dayName(i)}
                  </option>
                ))}
              </select>
            </label>
          </p>
        ) : (
          <input type="hidden" name="day_offset" value="0" />
        )}
        <p>
          <label>
            Starts at{' '}
            <input type="time" name="start_time" required defaultValue={toTimeInput('09:00')} />
          </label>
        </p>
        <p>
          <label>
            Length in minutes{' '}
            <input
              type="number"
              name="duration_minutes"
              min={15}
              max={1440}
              step={15}
              required
              defaultValue={480}
            />
          </label>
        </p>
        <p>
          <label>
            Person (optional){' '}
            <select name="assigned_person_id" defaultValue="">
              <option value="">Nobody (open shift)</option>
              {people.map((p) => (
                <option key={p.id} value={p.id}>
                  {displayName(p)}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Note (optional) <input name="notes" maxLength={1000} />
          </label>
        </p>
      </ActionForm>
    </main>
  );
}
