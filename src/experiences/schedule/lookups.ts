import 'server-only';
// Names and time zones the schedule screens need, loaded through the domains' service
// functions (never by querying their tables). A time is only ever formatted with the zone of
// the location it belongs to.
import { getLocationMap, type LocationInfo } from '@/experiences/employee/access';
import { getPersonNames } from '@/domains/identity';
import { getOrganizationSettings } from '@/domains/organizations';
import { listPositions } from '@/domains/staffing';

export type ScheduleLookups = {
  weekStartsOn: number;
  locations: Map<string, LocationInfo>;
  positions: Map<string, string>;
};

export async function loadScheduleLookups(orgId: string): Promise<ScheduleLookups> {
  const [settings, locations, positions] = await Promise.all([
    getOrganizationSettings(orgId),
    getLocationMap(orgId),
    listPositions(orgId, { includeArchived: true }),
  ]);
  return {
    weekStartsOn: settings.ok && settings.data ? settings.data.week_starts_on : 0,
    locations,
    positions: new Map(positions.ok ? positions.data.map((p) => [p.id, p.name]) : []),
  };
}

export function zoneOf(lookups: ScheduleLookups, locationId: string): string {
  return lookups.locations.get(locationId)?.timezone ?? 'UTC';
}

export function placeOf(lookups: ScheduleLookups, locationId: string): string {
  return lookups.locations.get(locationId)?.name ?? 'A location';
}

export async function loadNames(
  orgId: string,
  ids: readonly (string | null | undefined)[],
): Promise<Record<string, string>> {
  const res = await getPersonNames(
    orgId,
    ids.filter((i): i is string => typeof i === 'string'),
  );
  return res.ok ? res.data : {};
}

export function nameOf(names: Record<string, string>, id: string | null | undefined): string {
  return id ? (names[id] ?? 'Someone') : 'Open';
}
