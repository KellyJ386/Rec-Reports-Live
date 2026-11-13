import 'server-only';
import { listPeople, type Person } from '@/domains/identity';

const MAX_PAGES = 8;

/** Active people with a role at a location, for pick lists. Up to 200; the database limits who is visible. */
export async function listLocationPeople(orgId: string, locationId: string): Promise<Person[]> {
  const out: Person[] = [];
  for (let page = 1; page <= MAX_PAGES; page++) {
    const res = await listPeople(orgId, { page, words: [], locationId, status: 'active' });
    if (!res.ok) break;
    out.push(...res.data.rows);
    if (out.length >= res.data.total) break;
  }
  return out;
}
