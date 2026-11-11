import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { requestDropAction, requestSwapAction } from '@/experiences/employee/actions/schedule';
import { StaffNav } from '@/experiences/employee/ui';
import { getMyScheduleLocations } from '@/experiences/schedule/locations';
import {
  loadNames,
  loadScheduleLookups,
  nameOf,
  placeOf,
  zoneOf,
} from '@/experiences/schedule/lookups';
import { ScheduleNav } from '@/experiences/schedule/ui';
import { addDays } from '@/lib/time';
import { firstParam, parsePage } from '@/lib/paging';
import { displayName, listPeople, type Person } from '@/domains/identity';
import {
  formatShiftRange,
  getSchedule,
  groupShiftsByDay,
  listMyUpcomingShifts,
  listScheduleShifts,
  notStarted,
  todayIn,
  weekStartOf,
} from '@/domains/staffing';

export const metadata = { title: 'Schedule | Rec Reports' };

export default async function SchedulePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.schedule) notFound();
  const sp = await searchParams;
  const page = parsePage(sp.page);

  const [lookups, places] = await Promise.all([
    loadScheduleLookups(orgId),
    getMyScheduleLocations(orgId),
  ]);
  const location = places.find((l) => l.id === firstParam(sp.location)) ?? places[0];
  const zone = location?.timezone ?? 'UTC';
  const weekParam = firstParam(sp.week);
  const week =
    weekStartOf(
      weekParam && /^\d{4}-\d{2}-\d{2}$/.test(weekParam) ? weekParam : todayIn(zone),
      lookups.weekStartsOn,
    ) ?? todayIn(zone);

  const [mine, schedule] = await Promise.all([
    personId ? listMyUpcomingShifts(orgId, personId, page) : Promise.resolve(null),
    location ? getSchedule(orgId, location.id, week) : Promise.resolve(null),
  ]);
  const weekShifts =
    schedule && schedule.ok && schedule.data
      ? await listScheduleShifts(orgId, schedule.data.id)
      : null;
  const visibleWeek =
    weekShifts && weekShifts.ok ? weekShifts.data.filter((s) => s.status === 'scheduled') : [];
  const myRows = mine && mine.ok ? mine.data.rows : [];
  const names = await loadNames(orgId, [...visibleWeek.map((s) => s.assigned_person_id)]);

  // Coworkers to offer a swap to: the people the database lets this person see at that location.
  const peers =
    personId && myRows.length > 0
      ? await Promise.all(
          [...new Set(myRows.map((s) => s.location_id))].map(async (id) => {
            const res = await listPeople(orgId, {
              page: 1,
              words: [],
              locationId: id,
              status: 'active',
            });
            return [id, res.ok ? res.data.rows.filter((p) => p.id !== personId) : []] as const;
          }),
        ).then((e) => new Map(e))
      : new Map<string, Person[]>();

  return (
    <main>
      <h1>Schedule</h1>
      <StaffNav access={access} />
      <ScheduleNav />

      <h2>My next shifts</h2>
      {mine && !mine.ok ? <ErrorMessage message={mine.message} /> : null}
      {mine && mine.ok && myRows.length === 0 ? <p>You have no upcoming shifts.</p> : null}
      <ul>
        {myRows.map((s) => (
          <li key={s.id}>
            <p>
              {formatShiftRange(s.starts_at, s.ends_at, zoneOf(lookups, s.location_id))}
              <br />
              {lookups.positions.get(s.position_id) ?? 'Shift'} at {placeOf(lookups, s.location_id)}
            </p>
            {notStarted(s.starts_at) ? (
              <details>
                <summary>Swap or drop this shift</summary>
                <ActionForm action={requestSwapAction} submitLabel="Offer swap">
                  <input type="hidden" name="shift_id" value={s.id} />
                  <p>
                    <label>
                      Offer it to{' '}
                      <select name="to_person_id" required defaultValue="">
                        <option value="" disabled>
                          Choose a person
                        </option>
                        {(peers.get(s.location_id) ?? []).map((p) => (
                          <option key={p.id} value={p.id}>
                            {displayName(p)}
                          </option>
                        ))}
                      </select>
                    </label>
                  </p>
                  <p>
                    <label>
                      Note (optional) <input name="note" maxLength={500} />
                    </label>
                  </p>
                </ActionForm>
                <ActionForm action={requestDropAction} submitLabel="Ask to drop it">
                  <input type="hidden" name="shift_id" value={s.id} />
                  <p>A manager decides. Until then the shift is still yours.</p>
                  <p>
                    <label>
                      Note (optional) <input name="note" maxLength={500} />
                    </label>
                  </p>
                </ActionForm>
              </details>
            ) : null}
          </li>
        ))}
      </ul>
      {mine && mine.ok ? (
        <Pager
          path="/app/schedule"
          page={mine.data.page}
          total={mine.data.total}
          pageSize={mine.data.pageSize}
          params={{ location: location?.id, week }}
        />
      ) : null}

      <h2>The week at my location</h2>
      {places.length > 1 ? (
        <form method="get">
          <label>
            Location{' '}
            <select name="location" defaultValue={location?.id}>
              {places.map((l) => (
                <option key={l.id} value={l.id}>
                  {l.name}
                </option>
              ))}
            </select>
          </label>{' '}
          <input type="hidden" name="week" value={week} />
          <button type="submit">Show</button>
        </form>
      ) : null}
      {!location ? <p>You have no location yet.</p> : null}
      {location ? (
        <>
          <p>
            Week of {week}. Times are in {zone}.{' '}
            <Link href={`/app/schedule?location=${location.id}&week=${addDays(week, -7)}`}>
              Earlier week
            </Link>
            {' | '}
            <Link href={`/app/schedule?location=${location.id}&week=${addDays(week, 7)}`}>
              Later week
            </Link>
          </p>
          {schedule && !schedule.ok ? <ErrorMessage message={schedule.message} /> : null}
          {weekShifts && !weekShifts.ok ? <ErrorMessage message={weekShifts.message} /> : null}
          {!weekShifts ? <p>No schedule is published for this week yet.</p> : null}
          {weekShifts && weekShifts.ok
            ? groupShiftsByDay(visibleWeek, zone, week).map((day) => (
                <section key={day.date}>
                  <h3>{day.label}</h3>
                  {day.shifts.length === 0 ? <p>No shifts.</p> : null}
                  <ul>
                    {day.shifts.map((s) => (
                      <li key={s.id}>
                        {formatShiftRange(s.starts_at, s.ends_at, zone)}:{' '}
                        {lookups.positions.get(s.position_id) ?? 'Shift'},{' '}
                        {s.assigned_person_id === personId
                          ? 'you'
                          : nameOf(names, s.assigned_person_id)}
                        {s.assigned_person_id === null ? (
                          <>
                            {' '}
                            (<Link href="/app/schedule/open">ask for it</Link>)
                          </>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </section>
              ))
            : null}
        </>
      ) : null}
    </main>
  );
}
