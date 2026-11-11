import Link from 'next/link';
import { notFound } from 'next/navigation';
import { requireModulePermission } from '@/lib/auth';
import { formatHoursRange, toTimeInput } from '@/lib/time';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  addHoursAction,
  archiveSpaceAction,
  removeHoursAction,
  restoreSpaceAction,
  updateSpaceAction,
} from '@/experiences/admin/actions/spaces';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { guidParam } from '@/experiences/admin/page-params';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { getLocation } from '@/domains/organizations';
import {
  getSpace,
  groupHoursByDay,
  listSpaceHours,
  listSpaceKinds,
  listSpaces,
  parentChoices,
} from '@/domains/resources';

export default async function SpacePage({
  params,
}: {
  params: Promise<{ locationId: string; spaceId: string }>;
}) {
  const p = await params;
  const locationId = guidParam(p.locationId);
  const spaceId = guidParam(p.spaceId);
  const { orgId } = await requireAdminArea('canSpaces');
  await requireModulePermission(orgId, locationId, 'locations_spaces', 'edit');

  const [location, space, kinds, spaces, hours] = await Promise.all([
    getLocation(orgId, locationId),
    getSpace(orgId, locationId, spaceId),
    listSpaceKinds(orgId, { includeArchived: true }),
    listSpaces(orgId, locationId),
    listSpaceHours(orgId, locationId, spaceId),
  ]);
  for (const r of [location, space, kinds, spaces, hours]) {
    if (!r.ok) return <ErrorMessage message={r.message} />;
  }
  if (!location.ok || !space.ok || !kinds.ok || !spaces.ok || !hours.ok) return null;
  if (!location.data || !space.data) notFound();

  const s = space.data;
  const base = `/app/admin/locations/${locationId}`;
  const hasChildren = spaces.data.some((x) => x.parent_space_id === s.id);
  const parents = parentChoices(spaces.data, s.id);
  const kindOptions = kinds.data.filter((k) => k.archived_at === null || k.id === s.space_kind_id);
  const days = groupHoursByDay(hours.data);

  return (
    <main>
      <h1>
        {s.name}
        <ArchivedMark archivedAt={s.archived_at} />
      </h1>
      <p>
        <Link href={`${base}/spaces`}>All spaces at {location.data.name}</Link>
      </p>

      <h2>Details</h2>
      <ActionForm action={updateSpaceAction} submitLabel="Save">
        <input type="hidden" name="location_id" value={locationId} />
        <input type="hidden" name="id" value={s.id} />
        <p>
          <label>
            Name <input name="name" defaultValue={s.name} required maxLength={200} />
          </label>
        </p>
        <p>
          <label>
            Kind{' '}
            <select name="space_kind_id" defaultValue={s.space_kind_id} required>
              {kindOptions.map((k) => (
                <option key={k.id} value={k.id}>
                  {k.name}
                  {k.archived_at ? ' (archived)' : ''}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            Part of (optional){' '}
            <select name="parent_space_id" defaultValue={s.parent_space_id ?? ''}>
              <option value="">Nothing: a top-level space</option>
              {hasChildren
                ? null
                : parents.map((x) => (
                    <option key={x.id} value={x.id}>
                      {x.name}
                    </option>
                  ))}
            </select>
          </label>
        </p>
        {hasChildren ? (
          <p>This space has sub-spaces, so it cannot be part of another space.</p>
        ) : null}
        <p>
          <label>
            Capacity (optional){' '}
            <input
              name="capacity"
              type="number"
              min={0}
              step={1}
              inputMode="numeric"
              defaultValue={s.capacity ?? ''}
            />
          </label>
        </p>
        <p>
          <label>
            Notes (optional){' '}
            <input name="description" maxLength={2000} defaultValue={s.description ?? ''} />
          </label>
        </p>
      </ActionForm>

      <h2>Weekly hours</h2>
      <p>
        Times are local time at {location.data.name} ({location.data.timezone}). Monday is the first
        day. A space with no hours listed has no set opening times.
      </p>
      <table>
        <thead>
          <tr>
            <th scope="col">Day</th>
            <th scope="col">Open</th>
            <th scope="col">Remove</th>
          </tr>
        </thead>
        <tbody>
          {days.map((d) =>
            d.rows.length === 0 ? (
              <tr key={d.day}>
                <th scope="row">{d.label}</th>
                <td>Closed (no hours set)</td>
                <td />
              </tr>
            ) : (
              d.rows.map((r, i) => (
                <tr key={r.id}>
                  <th scope="row">{i === 0 ? d.label : ''}</th>
                  <td>
                    {formatHoursRange(r.opens_at, r.closes_at)}
                    {r.effective_from || r.effective_to
                      ? ` (${r.effective_from ?? 'any time'} to ${r.effective_to ?? 'any time'})`
                      : ''}
                  </td>
                  <td>
                    <ConfirmAction
                      action={removeHoursAction}
                      label="Remove"
                      question={`Yes, remove ${d.label} ${toTimeInput(r.opens_at)}`}
                      fields={{ id: r.id, space_id: s.id, location_id: locationId }}
                    />
                  </td>
                </tr>
              ))
            ),
          )}
        </tbody>
      </table>

      <h3>Add hours</h3>
      <ActionForm action={addHoursAction} submitLabel="Add hours">
        <input type="hidden" name="location_id" value={locationId} />
        <input type="hidden" name="space_id" value={s.id} />
        <fieldset>
          <legend>Days</legend>
          {days.map((d) => (
            <label key={d.day}>
              <input type="checkbox" name="day" value={d.day} /> {d.label}{' '}
            </label>
          ))}
        </fieldset>
        <p>
          <label>
            Opens at <input type="time" name="opens_at" required />
          </label>
        </p>
        <p>
          <label>
            Closes at <input type="time" name="closes_at" />
          </label>{' '}
          <label>
            <input type="checkbox" name="closes_at_midnight" value="yes" /> Closes at midnight (end
            of day)
          </label>
        </p>
        <p>
          <label>
            Only from (optional) <input type="date" name="effective_from" />
          </label>{' '}
          <label>
            until (optional) <input type="date" name="effective_to" />
          </label>
        </p>
      </ActionForm>
      <p>
        For hours that run past midnight, add two rows: one ending at midnight, one starting at
        12:00 AM the next day.
      </p>

      <h2>{s.archived_at ? 'Restore' : 'Archive'}</h2>
      {s.archived_at ? (
        <ActionForm action={restoreSpaceAction} submitLabel="Restore this space">
          <input type="hidden" name="location_id" value={locationId} />
          <input type="hidden" name="id" value={s.id} />
        </ActionForm>
      ) : (
        <ConfirmAction
          action={archiveSpaceAction}
          label="Archive this space"
          question="Yes, archive this space"
          fields={{ id: s.id, location_id: locationId }}
        />
      )}
    </main>
  );
}
