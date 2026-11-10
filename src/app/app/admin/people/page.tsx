import Link from 'next/link';
import { requireAdminArea } from '@/experiences/admin/access';
import { ArchivedMark, ErrorMessage, Pager } from '@/experiences/admin/ui';
import { firstParam, parsePage } from '@/lib/paging';
import { searchWords } from '@/lib/text';
import { listPeople, displayName } from '@/domains/identity';
import { listAllLocations } from '@/domains/organizations';
import { z } from 'zod';

const STATUSES = ['active', 'archived', 'all'] as const;

export default async function PeoplePage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const { orgId, access } = await requireAdminArea('canPeople');
  const sp = await searchParams;
  const page = parsePage(sp.page);
  const q = (firstParam(sp.q) ?? '').slice(0, 100);
  const locationParam = z.guid().safeParse(firstParam(sp.location));
  const locationId = locationParam.success ? locationParam.data : undefined;
  const statusParam = firstParam(sp.status);
  const status = STATUSES.find((s) => s === statusParam) ?? 'active';

  const [people, locations] = await Promise.all([
    listPeople(orgId, { page, words: searchWords(q), locationId, status }),
    listAllLocations(orgId, { includeArchived: true }),
  ]);

  return (
    <main>
      <h1>People</h1>
      {access.canPeopleAdmin ? (
        <p>
          <Link href="/app/admin/people/new">Add a person</Link>
        </p>
      ) : null}

      <form method="get" action="/app/admin/people">
        <p>
          <label>
            Search by name, email or employee number (up to 3 words, 2 letters or more){' '}
            <input type="search" name="q" defaultValue={q} maxLength={100} />
          </label>
        </p>
        <p>
          <label>
            Location{' '}
            <select name="location" defaultValue={locationId ?? ''}>
              <option value="">All locations</option>
              {locations.ok
                ? locations.data.map((l) => (
                    <option key={l.id} value={l.id}>
                      {l.name}
                      {l.archived_at ? ' (archived)' : ''}
                    </option>
                  ))
                : null}
            </select>
          </label>{' '}
          <label>
            Show{' '}
            <select name="status" defaultValue={status}>
              <option value="active">Active people</option>
              <option value="archived">Archived people</option>
              <option value="all">Everyone</option>
            </select>
          </label>{' '}
          <button type="submit">Search</button>
        </p>
      </form>

      {!people.ok ? (
        <ErrorMessage message={people.message} />
      ) : people.data.rows.length === 0 ? (
        <p>No one matches.</p>
      ) : (
        <>
          <table>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Email</th>
                <th scope="col">Employee number</th>
              </tr>
            </thead>
            <tbody>
              {people.data.rows.map((p) => (
                <tr key={p.id}>
                  <td>
                    <Link href={`/app/admin/people/${p.id}`}>{displayName(p)}</Link>
                    <ArchivedMark archivedAt={p.archived_at} />
                  </td>
                  <td>{p.email ?? ''}</td>
                  <td>{p.employee_number ?? ''}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pager
            path="/app/admin/people"
            page={people.data.page}
            total={people.data.total}
            pageSize={people.data.pageSize}
            params={{
              q: q || undefined,
              location: locationId,
              status: status === 'active' ? undefined : status,
            }}
          />
        </>
      )}
    </main>
  );
}
