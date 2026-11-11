import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  decideClaimAction,
  decideSwapAction,
  decideTimeOffAction,
} from '@/experiences/admin/actions/schedule';
import { OverrideForm } from '@/experiences/admin/override-form';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import {
  loadNames,
  loadScheduleLookups,
  nameOf,
  placeOf,
  zoneOf,
} from '@/experiences/schedule/lookups';
import { parsePage } from '@/lib/paging';
import {
  dateRangeText,
  formatShiftRange,
  getShiftsByIds,
  listClaimsAwaitingDecision,
  listPendingTimeOff,
  listSwapsAwaitingDecision,
  type ShiftRow,
} from '@/domains/staffing';

export const metadata = { title: 'Schedule requests | Rec Reports' };

const PATH = '/app/admin/schedule/requests';

export default async function RequestsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canScheduleRequests');
  const sp = await searchParams;
  const page = parsePage(sp.page);
  const [lookups, swaps, claims, timeOff] = await Promise.all([
    loadScheduleLookups(orgId),
    listSwapsAwaitingDecision(orgId, page),
    listClaimsAwaitingDecision(orgId, page),
    listPendingTimeOff(orgId, page),
  ]);
  const swapRows = swaps.ok ? swaps.data.rows : [];
  const claimRows = claims.ok ? claims.data.rows : [];
  const timeOffRows = timeOff.ok ? timeOff.data.rows : [];

  const shiftRes = await getShiftsByIds(orgId, [
    ...swapRows.map((s) => s.shift_id),
    ...claimRows.map((c) => c.shift_id),
  ]);
  const shiftById = new Map<string, ShiftRow>(
    (shiftRes.ok ? shiftRes.data : []).map((s) => [s.id, s]),
  );
  const names = await loadNames(orgId, [
    ...swapRows.flatMap((s) => [s.from_person_id, s.to_person_id]),
    ...claimRows.map((c) => c.person_id),
    ...timeOffRows.map((t) => t.person_id),
  ]);

  function describe(shift: ShiftRow | undefined): string {
    if (!shift) return 'A shift you cannot see';
    return `${formatShiftRange(shift.starts_at, shift.ends_at, zoneOf(lookups, shift.location_id))}, ${
      lookups.positions.get(shift.position_id) ?? 'Shift'
    } at ${placeOf(lookups, shift.location_id)}`;
  }

  return (
    <main>
      <h1>Schedule requests</h1>
      <p>
        <Link href="/app/admin/schedule">Back to the schedule</Link>
      </p>

      <h2>Swaps and drops</h2>
      {!swaps.ok ? <ErrorMessage message={swaps.message} /> : null}
      {swaps.ok && swapRows.length === 0 ? <p>Nothing is waiting.</p> : null}
      <ul>
        {swapRows.map((s) => (
          <li key={s.id}>
            <p>
              {s.kind === 'drop'
                ? `${nameOf(names, s.from_person_id)} asks to drop`
                : `${nameOf(names, s.from_person_id)} and ${nameOf(names, s.to_person_id)} want to swap`}
              : {describe(shiftById.get(s.shift_id))}
            </p>
            <OverrideForm
              action={decideSwapAction}
              submitLabel="Approve"
              overrideLabel="Approve anyway"
            >
              <input type="hidden" name="swap_id" value={s.id} />
              <input type="hidden" name="location_id" value={s.location_id} />
              <input type="hidden" name="shift_id" value={s.shift_id} />
              <input type="hidden" name="person_id" value={s.to_person_id ?? s.from_person_id} />
              <input
                type="hidden"
                name="party_ids"
                value={[s.from_person_id, s.to_person_id].filter(Boolean).join(',')}
              />
              <input type="hidden" name="decision" value="approve" />
            </OverrideForm>
            <ActionForm action={decideSwapAction} submitLabel="Do not approve">
              <input type="hidden" name="swap_id" value={s.id} />
              <input type="hidden" name="location_id" value={s.location_id} />
              <input type="hidden" name="decision" value="deny" />
            </ActionForm>
          </li>
        ))}
      </ul>
      {swaps.ok ? (
        <Pager
          path={PATH}
          page={swaps.data.page}
          total={swaps.data.total}
          pageSize={swaps.data.pageSize}
        />
      ) : null}

      <h2>Open shift requests</h2>
      {!claims.ok ? <ErrorMessage message={claims.message} /> : null}
      {claims.ok && claimRows.length === 0 ? <p>Nothing is waiting.</p> : null}
      <ul>
        {claimRows.map((c) => (
          <li key={c.id}>
            <p>
              {nameOf(names, c.person_id)} wants: {describe(shiftById.get(c.shift_id))}
            </p>
            <OverrideForm
              action={decideClaimAction}
              submitLabel="Approve"
              overrideLabel="Approve anyway"
            >
              <input type="hidden" name="claim_id" value={c.id} />
              <input type="hidden" name="location_id" value={c.location_id} />
              <input type="hidden" name="shift_id" value={c.shift_id} />
              <input type="hidden" name="person_id" value={c.person_id} />
              <input type="hidden" name="party_ids" value={c.person_id} />
              <input type="hidden" name="decision" value="approve" />
            </OverrideForm>
            <ActionForm action={decideClaimAction} submitLabel="Do not approve">
              <input type="hidden" name="claim_id" value={c.id} />
              <input type="hidden" name="location_id" value={c.location_id} />
              <input type="hidden" name="decision" value="deny" />
            </ActionForm>
          </li>
        ))}
      </ul>
      {claims.ok ? (
        <Pager
          path={PATH}
          page={claims.data.page}
          total={claims.data.total}
          pageSize={claims.data.pageSize}
        />
      ) : null}

      <h2>Time off</h2>
      {!timeOff.ok ? <ErrorMessage message={timeOff.message} /> : null}
      {timeOff.ok && timeOffRows.length === 0 ? <p>Nothing is waiting.</p> : null}
      <ul>
        {timeOffRows.map((t) => (
          <li key={t.id}>
            <p>
              {nameOf(names, t.person_id)}: {dateRangeText(t.starts_on, t.ends_on)}
              {t.reason ? `. Reason: ${t.reason}` : ''}
            </p>
            <ActionForm action={decideTimeOffAction} submitLabel="Approve">
              <input type="hidden" name="time_off_id" value={t.id} />
              <input type="hidden" name="decision" value="approve" />
            </ActionForm>
            <ActionForm action={decideTimeOffAction} submitLabel="Do not approve">
              <input type="hidden" name="time_off_id" value={t.id} />
              <input type="hidden" name="decision" value="deny" />
            </ActionForm>
          </li>
        ))}
      </ul>
      {timeOff.ok ? (
        <Pager
          path={PATH}
          page={timeOff.data.page}
          total={timeOff.data.total}
          pageSize={timeOff.data.pageSize}
        />
      ) : null}
    </main>
  );
}
