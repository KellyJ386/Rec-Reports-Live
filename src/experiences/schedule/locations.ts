import 'server-only';
import { getSessionContext } from '@/lib/auth';
import { listAllLocations, type Location } from '@/domains/organizations';

/**
 * The locations to offer on the staff schedule: where the person has a role, or every active
 * location when their roles cover the whole organization. The database still decides which
 * schedules and shifts they may see.
 */
export async function getMyScheduleLocations(orgId: string): Promise<Location[]> {
  const ctx = await getSessionContext();
  const mine = new Set(
    ctx.roleAssignments
      .filter((a) => a.organizationId === orgId && a.locationId !== null)
      .map((a) => a.locationId as string),
  );
  const all = await listAllLocations(orgId);
  if (!all.ok) return [];
  return mine.size === 0 ? all.data : all.data.filter((l) => mine.has(l.id));
}
