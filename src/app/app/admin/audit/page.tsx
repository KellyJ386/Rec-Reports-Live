import { requireAdminArea } from '@/experiences/admin/access';
import { ErrorMessage, Pager } from '@/experiences/admin/ui';
import { formatInZone } from '@/lib/time';
import { getPersonNames } from '@/domains/identity';
import { getOrganizationSettings, listAllLocations } from '@/domains/organizations';
import {
  AUDIT_ACTIONS,
  AUDIT_TABLES,
  actionLabel,
  listAuditLog,
  parseAuditQuery,
  tableLabel,
} from '@/domains/audit';

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId } = await requireAdminArea('canAudit');
  const [settings, locations] = await Promise.all([
    getOrganizationSettings(orgId),
    listAllLocations(orgId, { includeArchived: true }),
  ]);
  const tz = settings.ok && settings.data ? settings.data.default_timezone : 'UTC';
  const query = parseAuditQuery(await searchParams, orgId, tz);
  const locationName = new Map(locations.ok ? locations.data.map((l) => [l.id, l.name]) : []);

  const entries = query.filter ? await listAuditLog(query.filter, query.page) : null;
  const names =
    entries && entries.ok
      ? await getPersonNames(
          orgId,
          entries.data.rows.flatMap((e) => (e.actor_person_id ? [e.actor_person_id] : [])),
        )
      : null;
  const personName = (id: string | null) =>
    id === null ? 'The system' : ((names && names.ok ? names.data[id] : undefined) ?? 'Someone');

  const v = query.values;
  const pagerParams = {
    table: v.table || undefined,
    action: v.action || undefined,
    location: v.location || undefined,
    from: v.from || undefined,
    to: v.to || undefined,
  };

  return (
    <main>
      <h1>Audit log</h1>
      <p>
        Who changed what, newest first. Times are shown in {tz}, the organization&apos;s default
        time zone. You only see the entries your access allows.
      </p>

      <form method="get" action="/app/admin/audit">
        <p>
          <label>
            What changed{' '}
            <select name="table" defaultValue={v.table}>
              <option value="">Anything</option>
              {AUDIT_TABLES.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.label}
                </option>
              ))}
            </select>
          </label>{' '}
          <label>
            Kind of change{' '}
            <select name="action" defaultValue={v.action}>
              <option value="">Any</option>
              {AUDIT_ACTIONS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </select>
          </label>{' '}
          <label>
            Location{' '}
            <select name="location" defaultValue={v.location}>
              <option value="">All</option>
              {locations.ok
                ? locations.data.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name}
                    </option>
                  ))
                : null}
            </select>
          </label>
        </p>
        <p>
          <label>
            From <input type="date" name="from" defaultValue={v.from} />
          </label>{' '}
          <label>
            To (including this day) <input type="date" name="to" defaultValue={v.to} />
          </label>{' '}
          <button type="submit">Show</button>
        </p>
      </form>

      {query.problem ? <ErrorMessage message={query.problem} /> : null}
      {entries && !entries.ok ? <ErrorMessage message={entries.message} /> : null}
      {entries && entries.ok ? (
        entries.data.rows.length === 0 ? (
          <p>Nothing matches.</p>
        ) : (
          <>
            <table>
              <thead>
                <tr>
                  <th scope="col">When</th>
                  <th scope="col">Who</th>
                  <th scope="col">Change</th>
                  <th scope="col">Where</th>
                  <th scope="col">Fields changed</th>
                </tr>
              </thead>
              <tbody>
                {entries.data.rows.map((e) => (
                  <tr key={e.id}>
                    <td>{formatInZone(e.occurred_at, tz)}</td>
                    <td>{personName(e.actor_person_id)}</td>
                    <td>
                      {actionLabel(e.action)} {tableLabel(e.table_name).toLowerCase()}
                    </td>
                    <td>
                      {e.location_id
                        ? (locationName.get(e.location_id) ?? 'A location')
                        : 'Whole organization'}
                    </td>
                    <td>{e.changed_columns?.join(', ') ?? ''}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pager
              path="/app/admin/audit"
              page={entries.data.page}
              total={entries.data.total}
              pageSize={entries.data.pageSize}
              params={pagerParams}
            />
          </>
        )
      ) : null}
    </main>
  );
}
