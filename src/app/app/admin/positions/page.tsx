import { getLocationsWithPermission, requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import { archivePositionAction, savePositionAction } from '@/experiences/admin/actions/schedule';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { ArchivedMark, ErrorMessage } from '@/experiences/admin/ui';
import { listPositions, listQualifications } from '@/domains/staffing';

export const metadata = { title: 'Positions | Rec Reports' };

export default async function PositionsPage() {
  const { orgId } = await requireAdminArea('canScheduleAdmin');
  const [positions, quals, places] = await Promise.all([
    listPositions(orgId, { includeArchived: true }),
    listQualifications(orgId),
    getLocationsWithPermission(orgId, 'staff_schedule', 'admin'),
  ]);
  if (!positions.ok) return <ErrorMessage message={positions.message} />;
  const locationName = new Map(places.ok ? places.data.map((l) => [l.id, l.name]) : []);
  const orgWide = places.ok && places.orgWide;
  const qualName = new Map(quals.ok ? quals.data.map((q) => [q.id, q.name]) : []);

  return (
    <main>
      <h1>Positions</h1>
      <p>A position is a job on a shift, such as Lifeguard. It can need qualifications.</p>
      {positions.data.length === 0 ? <p>No positions yet.</p> : null}
      <ul>
        {positions.data.map((p) => (
          <li key={p.id}>
            <p>
              {p.name}
              <ArchivedMark archivedAt={p.archived_at} />.{' '}
              {p.location_id
                ? (locationName.get(p.location_id) ?? 'One location')
                : 'All locations'}
              .{' '}
              {p.position_qualifications.length > 0
                ? `Needs: ${p.position_qualifications.map((q) => qualName.get(q.qualification_id) ?? 'A qualification').join(', ')}.`
                : 'Needs no qualification.'}
            </p>
            {p.archived_at ? (
              <ActionForm action={archivePositionAction} submitLabel="Restore">
                <input type="hidden" name="position_id" value={p.id} />
                <input type="hidden" name="archived" value="no" />
              </ActionForm>
            ) : (
              <>
                <details>
                  <summary>Edit</summary>
                  <ActionForm action={savePositionAction} submitLabel="Save">
                    <input type="hidden" name="position_id" value={p.id} />
                    <input type="hidden" name="location_id" value={p.location_id ?? ''} />
                    <p>
                      <label>
                        Name <input name="name" defaultValue={p.name} required maxLength={100} />
                      </label>
                    </p>
                    <QualificationBoxes
                      all={quals.ok ? quals.data : []}
                      selected={p.position_qualifications.map((q) => q.qualification_id)}
                    />
                  </ActionForm>
                </details>
                <ConfirmAction
                  action={archivePositionAction}
                  label="Archive"
                  question={`Yes, archive ${p.name}`}
                  fields={{ position_id: p.id }}
                />
              </>
            )}
          </li>
        ))}
      </ul>

      <h2>Add a position</h2>
      <ActionForm action={savePositionAction} submitLabel="Add position">
        <p>
          <label>
            Name <input name="name" required maxLength={100} />
          </label>
        </p>
        <p>
          <label>
            Where{' '}
            <select
              name="location_id"
              defaultValue={orgWide ? '' : places.ok ? places.data[0]?.id : ''}
            >
              {orgWide ? <option value="">All locations</option> : null}
              {places.ok
                ? places.data.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name}
                    </option>
                  ))
                : null}
            </select>
          </label>
        </p>
        <QualificationBoxes all={quals.ok ? quals.data : []} selected={[]} />
      </ActionForm>
    </main>
  );
}

function QualificationBoxes({
  all,
  selected,
}: {
  all: { id: string; name: string }[];
  selected: string[];
}) {
  if (all.length === 0) return <p>No qualifications to require yet.</p>;
  return (
    <fieldset>
      <legend>Needs these qualifications</legend>
      {all.map((q) => (
        <p key={q.id}>
          <label>
            <input
              type="checkbox"
              name="qualification_ids"
              value={q.id}
              defaultChecked={selected.includes(q.id)}
            />{' '}
            {q.name}
          </label>
        </p>
      ))}
    </fieldset>
  );
}
