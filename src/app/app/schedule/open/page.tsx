import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { cancelClaimAction, requestClaimAction } from '@/experiences/employee/actions/schedule';
import { StaffNav } from '@/experiences/employee/ui';
import { loadScheduleLookups, placeOf, zoneOf } from '@/experiences/schedule/lookups';
import { ScheduleNav } from '@/experiences/schedule/ui';
import { parsePage } from '@/lib/paging';
import {
  claimStatusLabel,
  formatShiftRange,
  getShiftsByIds,
  listClaimableShifts,
  listMyClaims,
} from '@/domains/staffing';

export const metadata = { title: 'Open shifts | Rec Reports' };

export default async function OpenShiftsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.schedule) notFound();
  const page = parsePage((await searchParams).page);
  const [lookups, claimable, claims] = await Promise.all([
    loadScheduleLookups(orgId),
    listClaimableShifts(orgId),
    personId ? listMyClaims(orgId, personId, page) : Promise.resolve(null),
  ]);
  const claimShifts =
    claims && claims.ok
      ? await getShiftsByIds(
          orgId,
          claims.data.rows.map((c) => c.shift_id),
        )
      : null;
  const shiftById = new Map(
    claimShifts && claimShifts.ok ? claimShifts.data.map((s) => [s.id, s]) : [],
  );

  return (
    <main>
      <h1>Open shifts</h1>
      <StaffNav access={access} />
      <ScheduleNav />
      <p>These shifts have nobody on them and you can work them now.</p>
      {!claimable.ok ? <ErrorMessage message={claimable.message} /> : null}
      {claimable.ok && claimable.data.length === 0 ? (
        <p>No open shifts for you right now.</p>
      ) : null}
      <ul>
        {(claimable.ok ? claimable.data : []).map((s) => (
          <li key={s.shift_id}>
            <p>
              {formatShiftRange(s.starts_at, s.ends_at, zoneOf(lookups, s.location_id))}
              <br />
              {lookups.positions.get(s.position_id) ?? 'Shift'} at {placeOf(lookups, s.location_id)}
            </p>
            <ActionForm action={requestClaimAction} submitLabel="Ask for this shift">
              <input type="hidden" name="shift_id" value={s.shift_id} />
            </ActionForm>
          </li>
        ))}
      </ul>

      <h2>My requests</h2>
      {claims && !claims.ok ? <ErrorMessage message={claims.message} /> : null}
      {claims && claims.ok && claims.data.rows.length === 0 ? (
        <p>You have not asked for any.</p>
      ) : null}
      <ul>
        {(claims && claims.ok ? claims.data.rows : []).map((c) => {
          const s = shiftById.get(c.shift_id);
          return (
            <li key={c.id}>
              <p>
                {s
                  ? `${formatShiftRange(s.starts_at, s.ends_at, zoneOf(lookups, s.location_id))}, ${lookups.positions.get(s.position_id) ?? 'Shift'}`
                  : 'A shift'}
                : {claimStatusLabel(c.status)}
              </p>
              {c.status === 'requested' ? (
                <ActionForm action={cancelClaimAction} submitLabel="Cancel request">
                  <input type="hidden" name="claim_id" value={c.id} />
                </ActionForm>
              ) : null}
            </li>
          );
        })}
      </ul>
      {claims && claims.ok ? (
        <Pager
          path="/app/schedule/open"
          page={claims.data.page}
          total={claims.data.total}
          pageSize={claims.data.pageSize}
        />
      ) : null}
    </main>
  );
}
