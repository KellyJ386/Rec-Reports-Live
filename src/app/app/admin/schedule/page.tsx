import Link from 'next/link';
import { getLocationsWithPermission, requireAdminArea } from '@/experiences/admin/access';
import { ActionForm } from '@/experiences/admin/action-form';
import {
  addShiftAction,
  applyTemplateAction,
  assignShiftAction,
  cancelShiftAction,
  createScheduleAction,
  publishScheduleAction,
  updateShiftAction,
} from '@/experiences/admin/actions/schedule';
import { ConfirmAction } from '@/experiences/admin/confirm-action';
import { ErrorMessage } from '@/experiences/admin/ui';
import { loadNames, loadScheduleLookups, nameOf } from '@/experiences/schedule/lookups';
import { listLocationPeople } from '@/experiences/schedule/people';
import { addDays, utcToZonedLocal } from '@/lib/time';
import { displayName } from '@/domains/identity';
import { buildHref, firstParam } from '@/lib/paging';
import {
  ASSIGN_RULES,
  RULE_TEXT,
  canOfferOverride,
  formatShiftRange,
  getSchedule,
  groupShiftsByDay,
  listPositions,
  listScheduleShifts,
  listTemplates,
  todayIn,
  weekStartOf,
  type AssignRule,
} from '@/domains/staffing';

export const metadata = { title: 'Schedule | Rec Reports' };

const PATH = '/app/admin/schedule';

export default async function AdminSchedulePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, access } = await requireAdminArea('canSchedule');
  const sp = await searchParams;
  const [places, lookups] = await Promise.all([
    getLocationsWithPermission(orgId, 'staff_schedule', 'edit'),
    loadScheduleLookups(orgId),
  ]);
  if (!places.ok) return <ErrorMessage message={places.message} />;
  const location = places.data.find((l) => l.id === firstParam(sp.location)) ?? places.data[0];
  if (!location) {
    return (
      <main>
        <h1>Schedule</h1>
        <p>You cannot build a schedule at any location.</p>
      </main>
    );
  }
  const zone = location.timezone;
  const weekParam = firstParam(sp.week);
  const week =
    weekStartOf(
      weekParam && /^\d{4}-\d{2}-\d{2}$/.test(weekParam) ? weekParam : todayIn(zone),
      lookups.weekStartsOn,
    ) ?? todayIn(zone);

  const [scheduleRes, positions, templates, people] = await Promise.all([
    getSchedule(orgId, location.id, week),
    listPositions(orgId, { locationId: location.id }),
    listTemplates(orgId, location.id),
    listLocationPeople(orgId, location.id),
  ]);
  const schedule = scheduleRes.ok ? scheduleRes.data : null;
  const shiftsRes = schedule ? await listScheduleShifts(orgId, schedule.id) : null;
  const shifts = shiftsRes && shiftsRes.ok ? shiftsRes.data : [];
  const names = await loadNames(
    orgId,
    shifts.map((s) => s.assigned_person_id),
  );

  // The override offer: the page was reloaded after a refusal that a schedule admin may override.
  const failedShift = firstParam(sp.shift);
  const failedPerson = firstParam(sp.person);
  const ruleParam = firstParam(sp.rule);
  const rule = (ASSIGN_RULES as readonly string[]).includes(ruleParam ?? '')
    ? (ruleParam as AssignRule)
    : null;
  const offer =
    failedShift && failedPerson && canOfferOverride(rule, access.canScheduleAdmin) && rule
      ? { shift: failedShift, person: failedPerson, rule }
      : null;

  const here = { location: location.id, week };
  const draft = schedule?.status === 'draft';

  return (
    <main>
      <h1>Schedule</h1>
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
        <label>
          Week of <input type="date" name="week" defaultValue={week} />
        </label>{' '}
        <button type="submit">Show</button>
      </form>
      <p>
        Week of {week}. Times are in {zone}.{' '}
        <Link href={buildHref(PATH, { location: location.id, week: addDays(week, -7) ?? week })}>
          Earlier week
        </Link>
        {' | '}
        <Link href={buildHref(PATH, { location: location.id, week: addDays(week, 7) ?? week })}>
          Later week
        </Link>
      </p>
      {!scheduleRes.ok ? <ErrorMessage message={scheduleRes.message} /> : null}
      {shiftsRes && !shiftsRes.ok ? <ErrorMessage message={shiftsRes.message} /> : null}

      {offer ? (
        <section aria-label="Assign anyway">
          <h2>Assign anyway?</h2>
          <p role="alert">
            {RULE_TEXT[offer.rule]} You can still assign them, because you manage this schedule.
            This is recorded.
          </p>
          <ActionForm action={assignShiftAction} submitLabel="Assign anyway">
            <input type="hidden" name="location_id" value={location.id} />
            <input type="hidden" name="week" value={week} />
            <input type="hidden" name="shift_id" value={offer.shift} />
            <input type="hidden" name="person_id" value={offer.person} />
            <input type="hidden" name="override" value="yes" />
          </ActionForm>
          <p>
            <Link href={buildHref(PATH, here)}>Cancel</Link>
          </p>
        </section>
      ) : null}

      {!schedule ? (
        <section>
          <h2>No schedule for this week</h2>
          <ActionForm action={createScheduleAction} submitLabel="Start this week">
            <input type="hidden" name="location_id" value={location.id} />
            <input type="hidden" name="week_start" value={week} />
            <p>It starts as a draft. Nobody sees it until you publish.</p>
          </ActionForm>
        </section>
      ) : (
        <>
          <p>Status: {draft ? 'Draft (not visible to staff)' : 'Published'}.</p>
          {draft ? (
            <ConfirmAction
              action={publishScheduleAction}
              label="Publish"
              question="Yes, publish this week and tell the people on it"
              fields={{ location_id: location.id, schedule_id: schedule.id }}
            />
          ) : null}

          {groupShiftsByDay(shifts, zone, week).map((day) => (
            <section key={day.date}>
              <h3>{day.label}</h3>
              {day.shifts.length === 0 ? <p>No shifts.</p> : null}
              <ul>
                {day.shifts.map((s) => (
                  <li key={s.id}>
                    <p>
                      {formatShiftRange(s.starts_at, s.ends_at, zone)}:{' '}
                      {lookups.positions.get(s.position_id) ?? 'Shift'}.{' '}
                      {s.status === 'cancelled'
                        ? 'Cancelled.'
                        : s.assigned_person_id
                          ? `Assigned to ${nameOf(names, s.assigned_person_id)}.`
                          : 'Open.'}
                      {s.override_kinds && s.override_kinds.length > 0
                        ? ' Assigned with an override.'
                        : ''}
                    </p>
                    {s.status !== 'cancelled' ? (
                      <details>
                        <summary>Change this shift</summary>
                        <ActionForm action={assignShiftAction} submitLabel="Assign">
                          <input type="hidden" name="location_id" value={location.id} />
                          <input type="hidden" name="week" value={week} />
                          <input type="hidden" name="shift_id" value={s.id} />
                          <p>
                            <label>
                              Person{' '}
                              <select name="person_id" defaultValue={s.assigned_person_id ?? ''}>
                                <option value="">Nobody (open shift)</option>
                                {people.map((p) => (
                                  <option key={p.id} value={p.id}>
                                    {displayName(p)}
                                  </option>
                                ))}
                              </select>
                            </label>
                          </p>
                        </ActionForm>
                        <ActionForm action={updateShiftAction} submitLabel="Save times">
                          <input type="hidden" name="location_id" value={location.id} />
                          <input type="hidden" name="shift_id" value={s.id} />
                          <p>
                            <label>
                              Position{' '}
                              <select name="position_id" defaultValue={s.position_id}>
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
                          <p>
                            <label>
                              Starts ({zone}){' '}
                              <input
                                type="datetime-local"
                                name="starts_at"
                                required
                                defaultValue={utcToZonedLocal(s.starts_at, zone)}
                              />
                            </label>
                          </p>
                          <p>
                            <label>
                              Ends ({zone}){' '}
                              <input
                                type="datetime-local"
                                name="ends_at"
                                required
                                defaultValue={utcToZonedLocal(s.ends_at, zone)}
                              />
                            </label>
                          </p>
                          <p>
                            <label>
                              Note (leave blank to keep it) <input name="notes" maxLength={1000} />
                            </label>
                          </p>
                        </ActionForm>
                        <ConfirmAction
                          action={cancelShiftAction}
                          label="Cancel shift"
                          question="Yes, cancel this shift"
                          fields={{ location_id: location.id, shift_id: s.id }}
                        />
                      </details>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
          ))}

          <h2>Add a shift</h2>
          <p>The shift starts open. Assign someone after you add it.</p>
          <ActionForm action={addShiftAction} submitLabel="Add shift">
            <input type="hidden" name="location_id" value={location.id} />
            <input type="hidden" name="schedule_id" value={schedule.id} />
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
            <p>
              <label>
                Starts ({zone}) <input type="datetime-local" name="starts_at" required />
              </label>
            </p>
            <p>
              <label>
                Ends ({zone}) <input type="datetime-local" name="ends_at" required />
              </label>
            </p>
            <p>
              <label>
                Note (optional) <input name="notes" maxLength={1000} />
              </label>
            </p>
          </ActionForm>

          <h2>Use a template</h2>
          {templates.ok && templates.data.length > 0 ? (
            <ActionForm action={applyTemplateAction} submitLabel="Add the template's shifts">
              <input type="hidden" name="location_id" value={location.id} />
              <input type="hidden" name="schedule_id" value={schedule.id} />
              <p>
                <label>
                  Template{' '}
                  <select name="template_id" required defaultValue="">
                    <option value="" disabled>
                      Choose a template
                    </option>
                    {templates.data.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.name}
                      </option>
                    ))}
                  </select>
                </label>
              </p>
            </ActionForm>
          ) : (
            <p>
              No templates yet. <Link href="/app/admin/shift-templates">Make one</Link>.
            </p>
          )}
        </>
      )}
    </main>
  );
}
