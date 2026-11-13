import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { cancelSwapAction, respondSwapAction } from '@/experiences/employee/actions/schedule';
import { StaffNav } from '@/experiences/employee/ui';
import { loadNames, loadScheduleLookups, nameOf, zoneOf } from '@/experiences/schedule/lookups';
import { ScheduleNav } from '@/experiences/schedule/ui';
import { parsePage } from '@/lib/paging';
import {
  dropStatusLabel,
  formatShiftRange,
  getShiftsByIds,
  listMySwaps,
  swapStatusLabel,
  type ShiftRow,
} from '@/domains/staffing';

export const metadata = { title: 'Swaps and drops | Rec Reports' };

export default async function SwapsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.schedule) notFound();
  const page = parsePage((await searchParams).page);
  const lookups = await loadScheduleLookups(orgId);
  const swaps = personId ? await listMySwaps(orgId, personId, page) : null;
  const rows = swaps && swaps.ok ? swaps.data.rows : [];
  const shifts = await getShiftsByIds(
    orgId,
    rows.flatMap((r) => [r.shift_id, r.counter_shift_id].filter((x): x is string => !!x)),
  );
  const shiftById = new Map<string, ShiftRow>(shifts.ok ? shifts.data.map((s) => [s.id, s]) : []);
  const names = await loadNames(
    orgId,
    rows.flatMap((r) => [r.from_person_id, r.to_person_id]),
  );

  const describe = (s: ShiftRow | undefined) =>
    s
      ? `${formatShiftRange(s.starts_at, s.ends_at, zoneOf(lookups, s.location_id))}, ${lookups.positions.get(s.position_id) ?? 'Shift'}`
      : 'A shift';

  const offersToMe = rows.filter((r) => r.kind === 'swap' && r.to_person_id === personId);
  const mine = rows.filter((r) => r.from_person_id === personId);

  return (
    <main>
      <h1>Swaps and drops</h1>
      <StaffNav access={access} />
      <ScheduleNav />
      <p>To offer a swap or ask to drop a shift, open the shift on My schedule.</p>
      {swaps && !swaps.ok ? <ErrorMessage message={swaps.message} /> : null}

      <h2>Offered to me</h2>
      {offersToMe.length === 0 ? <p>Nobody has offered you a swap.</p> : null}
      <ul>
        {offersToMe.map((r) => (
          <li key={r.id}>
            <p>
              {nameOf(names, r.from_person_id)} offers {describe(shiftById.get(r.shift_id))}
              {r.counter_shift_id ? ` for your ${describe(shiftById.get(r.counter_shift_id))}` : ''}
              . {swapStatusLabel(r.status)}.
            </p>
            {r.status === 'requested' ? (
              <>
                <ActionForm action={respondSwapAction} submitLabel="Accept">
                  <input type="hidden" name="swap_id" value={r.id} />
                  <input type="hidden" name="answer" value="accept" />
                </ActionForm>
                <ActionForm action={respondSwapAction} submitLabel="Decline">
                  <input type="hidden" name="swap_id" value={r.id} />
                  <input type="hidden" name="answer" value="decline" />
                </ActionForm>
              </>
            ) : null}
            {r.status === 'requested' || r.status === 'accepted' ? (
              <ActionForm action={cancelSwapAction} submitLabel="Cancel">
                <input type="hidden" name="swap_id" value={r.id} />
              </ActionForm>
            ) : null}
          </li>
        ))}
      </ul>

      <h2>My offers and drops</h2>
      {mine.length === 0 ? <p>You have not offered or dropped anything.</p> : null}
      <ul>
        {mine.map((r) => (
          <li key={r.id}>
            <p>
              {r.kind === 'drop' ? 'Drop' : `Swap with ${nameOf(names, r.to_person_id)}`}:{' '}
              {describe(shiftById.get(r.shift_id))}.{' '}
              {r.kind === 'drop' ? dropStatusLabel(r.status) : swapStatusLabel(r.status)}.
            </p>
            {r.status === 'requested' || r.status === 'accepted' ? (
              <ActionForm action={cancelSwapAction} submitLabel="Cancel">
                <input type="hidden" name="swap_id" value={r.id} />
              </ActionForm>
            ) : null}
          </li>
        ))}
      </ul>
      {swaps && swaps.ok ? (
        <Pager
          path="/app/schedule/swaps"
          page={swaps.data.page}
          total={swaps.data.total}
          pageSize={swaps.data.pageSize}
        />
      ) : null}
    </main>
  );
}
