import { notFound } from 'next/navigation';
import { ActionForm } from '@/experiences/admin/action-form';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { requireStaffArea } from '@/experiences/employee/access';
import { cancelTimeOffAction, requestTimeOffAction } from '@/experiences/employee/actions/schedule';
import { StaffNav } from '@/experiences/employee/ui';
import { ScheduleNav } from '@/experiences/schedule/ui';
import { parsePage } from '@/lib/paging';
import { dateRangeText, listMyTimeOff, timeOffStatusLabel } from '@/domains/staffing';

export const metadata = { title: 'Time off | Rec Reports' };

export default async function TimeOffPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, personId, access } = await requireStaffArea();
  if (!access.schedule) notFound();
  const page = parsePage((await searchParams).page);
  const rows = personId ? await listMyTimeOff(orgId, personId, page) : null;
  const today = new Date().toISOString().slice(0, 10);

  return (
    <main>
      <h1>Time off</h1>
      <StaffNav access={access} />
      <ScheduleNav />
      <h2>Ask for time off</h2>
      <ActionForm action={requestTimeOffAction} submitLabel="Ask for time off">
        <p>
          <label>
            First day <input type="date" name="starts_on" required />
          </label>
        </p>
        <p>
          <label>
            Last day <input type="date" name="ends_on" />
          </label>{' '}
          (leave blank for one day)
        </p>
        <p>
          <label>
            Reason (optional) <input name="reason" maxLength={500} />
          </label>
        </p>
      </ActionForm>

      <h2>My requests</h2>
      {rows && !rows.ok ? <ErrorMessage message={rows.message} /> : null}
      {rows && rows.ok && rows.data.rows.length === 0 ? (
        <p>You have not asked for time off.</p>
      ) : null}
      <ul>
        {(rows && rows.ok ? rows.data.rows : []).map((t) => (
          <li key={t.id}>
            <p>
              {dateRangeText(t.starts_on, t.ends_on)}: {timeOffStatusLabel(t.status)}
            </p>
            {t.status === 'pending' || (t.status === 'approved' && t.ends_on >= today) ? (
              <ActionForm action={cancelTimeOffAction} submitLabel="Cancel">
                <input type="hidden" name="time_off_id" value={t.id} />
              </ActionForm>
            ) : null}
          </li>
        ))}
      </ul>
      {rows && rows.ok ? (
        <Pager
          path="/app/schedule/time-off"
          page={rows.data.page}
          total={rows.data.total}
          pageSize={rows.data.pageSize}
        />
      ) : null}
    </main>
  );
}
