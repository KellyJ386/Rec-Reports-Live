import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { ErrorMessage } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import {
  addAvailabilityAction,
  removeAvailabilityAction,
} from '@/experiences/employee/actions/schedule';
import { StaffNav } from '@/experiences/employee/ui';
import { ScheduleNav } from '@/experiences/schedule/ui';
import { ISO_WEEKDAYS, formatClock } from '@/lib/time';
import { AVAILABILITY_KINDS, availabilityKindLabel, listMyAvailability } from '@/domains/staffing';

export const metadata = { title: 'Availability | Rec Reports' };

export default async function AvailabilityPage() {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.schedule) notFound();
  const rows = personId ? await listMyAvailability(orgId, personId) : null;
  const dayName = (n: number) => ISO_WEEKDAYS.find((d) => d.value === n)?.label ?? String(n);

  return (
    <main>
      <h1>Availability</h1>
      <StaffNav access={access} />
      <ScheduleNav />
      <p>
        Tell your managers when you can and cannot work. It is a note for them: it does not block a
        shift.
      </p>
      <h2>Add a time</h2>
      <ActionForm action={addAvailabilityAction} submitLabel="Save">
        <p>
          <label>
            Day{' '}
            <select name="day_of_week" required defaultValue="1">
              {ISO_WEEKDAYS.map((d) => (
                <option key={d.value} value={d.value}>
                  {d.label}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            From <input type="time" name="start_time" required defaultValue="09:00" />
          </label>{' '}
          <label>
            To <input type="time" name="end_time" required defaultValue="17:00" />
          </label>
        </p>
        <p>
          <label>
            I{' '}
            <select name="kind" defaultValue="available">
              {AVAILABILITY_KINDS.map((k) => (
                <option key={k} value={k}>
                  {availabilityKindLabel(k)}
                </option>
              ))}
            </select>
          </label>
        </p>
        <p>
          <label>
            From date (optional) <input type="date" name="effective_from" />
          </label>{' '}
          <label>
            Until date (optional) <input type="date" name="effective_to" />
          </label>
        </p>
      </ActionForm>

      <h2>My times</h2>
      {rows && !rows.ok ? <ErrorMessage message={rows.message} /> : null}
      {rows && rows.ok && rows.data.length === 0 ? <p>You have not added any.</p> : null}
      <ul>
        {(rows && rows.ok ? rows.data : []).map((a) => (
          <li key={a.id}>
            <p>
              {dayName(a.day_of_week)} {formatClock(a.start_time)} to {formatClock(a.end_time)}:{' '}
              {availabilityKindLabel(a.kind)}
              {a.effective_from ? `, from ${a.effective_from}` : ''}
              {a.effective_to ? `, until ${a.effective_to}` : ''}
            </p>
            <ActionForm action={removeAvailabilityAction} submitLabel="Remove">
              <input type="hidden" name="availability_id" value={a.id} />
            </ActionForm>
          </li>
        ))}
      </ul>
    </main>
  );
}
