import { ActionForm } from '@/experiences/admin/action-form';
import { retryJobAction } from '@/experiences/admin/actions/jobs';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import {
  getLocationsWithPermission,
  hasPermission,
  requireAdminArea,
} from '@/experiences/admin/access';
import { formatInZone } from '@/lib/time';
import { parsePage } from '@/lib/paging';
import { getOrganizationSettings, listAllLocations } from '@/domains/organizations';
import { jobStateLabel, listFailedJobs } from '@/domains/workflows';

export const metadata = { title: 'Failed jobs | Rec Reports' };

// Plain names for the event types, for people who are not developers.
function jobLabel(type: string): string {
  return type.replace(/[._]/g, ' ');
}

export default async function FailedJobsPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canAudit');
  const page = parsePage((await searchParams).page);
  const [res, settings, locations, adminPlaces, orgAdmin] = await Promise.all([
    listFailedJobs(orgId, page),
    getOrganizationSettings(orgId),
    listAllLocations(orgId, { includeArchived: true }),
    getLocationsWithPermission(orgId, 'audit_log', 'admin'),
    hasPermission(orgId, null, 'audit_log', 'admin'),
  ]);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const locationName = new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : []);
  // Who may retry which job (the database checks again): organization scope, or the job's location.
  const canRetryAt = new Set(adminPlaces.ok ? adminPlaces.data.map((l) => l.id) : []);
  const canRetry = (locationId: string | null) =>
    orgAdmin || (locationId !== null && canRetryAt.has(locationId));

  return (
    <main>
      <h1>Failed jobs</h1>
      <p>
        Background jobs that did not work: the notices, tasks and messages that were meant to go
        out. A job marked &quot;Failing&quot; will try again by itself. A job that &quot;stopped
        trying&quot; needs you to retry it. Times are shown in {tz}.
      </p>
      {!res.ok ? <ErrorMessage message={res.message} /> : null}
      {res.ok && res.data.rows.length === 0 ? <p>Nothing has failed.</p> : null}
      {res.ok && res.data.rows.length > 0 ? (
        <>
          <table>
            <thead>
              <tr>
                <th scope="col">Job</th>
                <th scope="col">Where</th>
                <th scope="col">Started</th>
                <th scope="col">Tries</th>
                <th scope="col">What went wrong</th>
                <th scope="col">State</th>
                <th scope="col">Retry</th>
              </tr>
            </thead>
            <tbody>
              {res.data.rows.map((j) => (
                <tr key={j.id}>
                  <td>{jobLabel(j.type)}</td>
                  <td>
                    {j.location_id
                      ? (locationName.get(j.location_id) ?? 'A location')
                      : 'Whole organization'}
                  </td>
                  <td>{formatInZone(j.created_at, tz)}</td>
                  <td>{j.attempts}</td>
                  <td>{j.errorClass}</td>
                  <td>
                    {jobStateLabel(j.status)}
                    {j.status === 'pending'
                      ? ` Next try: ${formatInZone(j.next_attempt_at, tz)}.`
                      : ''}
                    {j.retried_at ? ` Retried ${formatInZone(j.retried_at, tz)}.` : ''}
                  </td>
                  <td>
                    {j.status === 'dead' && canRetry(j.location_id) ? (
                      <ActionForm action={retryJobAction} submitLabel="Retry">
                        <input type="hidden" name="job_id" value={j.id} />
                      </ActionForm>
                    ) : j.status === 'pending' ? (
                      'It will try again by itself'
                    ) : (
                      'Not available to you'
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            path="/app/admin/jobs"
            page={res.data.page}
            total={res.data.total}
            pageSize={res.data.pageSize}
          />
        </>
      ) : null}
    </main>
  );
}
