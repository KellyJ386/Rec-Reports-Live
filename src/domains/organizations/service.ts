// Organizations domain services: organizations, settings, locations.
// Reads and writes go through the caller's session client, so RLS decides what is allowed.
// Each function returns a Result with a plain-language message on failure.
import { createClient } from '@/lib/supabase/server';
import type { Tables } from '@/lib/supabase/database.types';
import { failure, ok, requireChanged, type Result } from '@/lib/db-errors';
import { fetchAllRows, fetchClampedPage, type Paged } from '@/lib/paging';
import type {
  LocationCreate,
  LocationUpdate,
  OrganizationSettingsUpdate,
  OrganizationUpdate,
} from './schemas';

export type Location = Pick<
  Tables<'locations'>,
  'id' | 'name' | 'code' | 'timezone' | 'address' | 'phone' | 'archived_at'
>;
export type OrganizationSummary = Pick<Tables<'organizations'>, 'id' | 'name'>;
export type OrganizationSettings = Pick<
  Tables<'organization_settings'>,
  'default_timezone' | 'week_starts_on'
>;

const LOCATION_COLUMNS = 'id, name, code, timezone, address, phone, archived_at';
const LOCATION_CONFLICT = 'A location with that name or code already exists.';

/** One page of locations, archived ones last. */
export async function listLocations(orgId: string, page: number): Promise<Result<Paged<Location>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('locations')
      .select(LOCATION_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId)
      .order('archived_at', { ascending: true, nullsFirst: true })
      .order('name')
      .order('id')
      .range(from, to),
  );
}

/** Every location, for pickers and name lookups. Read in chunks, never truncated. */
export async function listAllLocations(
  orgId: string,
  options: { includeArchived?: boolean } = {},
): Promise<Result<Location[]>> {
  const supabase = await createClient();
  return fetchAllRows<Location>((from, to) => {
    const q = supabase.from('locations').select(LOCATION_COLUMNS).eq('organization_id', orgId);
    return (options.includeArchived ? q : q.is('archived_at', null))
      .order('name')
      .order('id')
      .range(from, to);
  });
}

export async function getLocation(orgId: string, id: string): Promise<Result<Location | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('locations')
    .select(LOCATION_COLUMNS)
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

export async function createLocation(input: LocationCreate): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.from('locations').insert(input).select('id').single();
  if (error) return failure(error, { unique: LOCATION_CONFLICT });
  return ok({ id: data.id });
}

export async function updateLocation(
  orgId: string,
  id: string,
  patch: LocationUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('locations')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { unique: LOCATION_CONFLICT });
  return requireChanged(data);
}

export function setLocationArchived(
  orgId: string,
  id: string,
  archived: boolean,
): Promise<Result<number>> {
  return updateLocation(orgId, id, { archived_at: archived ? new Date().toISOString() : null });
}

export async function getOrganization(orgId: string): Promise<Result<OrganizationSummary | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('organizations')
    .select('id, name')
    .eq('id', orgId)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

export async function getOrganizationSettings(
  orgId: string,
): Promise<Result<OrganizationSettings | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('organization_settings')
    .select('default_timezone, week_starts_on')
    .eq('organization_id', orgId)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

export async function updateOrganization(
  orgId: string,
  patch: OrganizationUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('organizations')
    .update(patch)
    .eq('id', orgId)
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}

export async function updateOrganizationSettings(
  orgId: string,
  patch: OrganizationSettingsUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { settings, ...rest } = patch;
  const { data, error } = await supabase
    .from('organization_settings')
    .update({
      ...rest,
      ...(settings === undefined
        ? {}
        : { settings: settings as Tables<'organization_settings'>['settings'] }),
    })
    .eq('organization_id', orgId)
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}

/** The two staffing switches kept in organization_settings.settings.staffing (both default to off). */
export type StaffingSwitches = { auto_approve_swaps: boolean; first_come_open_shifts: boolean };

export async function getStaffingSwitches(orgId: string): Promise<Result<StaffingSwitches>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('organization_settings')
    .select('settings')
    .eq('organization_id', orgId)
    .maybeSingle();
  if (error) return failure(error);
  const raw = (data?.settings ?? {}) as Record<string, unknown>;
  const staffing = (raw.staffing ?? {}) as Record<string, unknown>;
  return ok({
    auto_approve_swaps: staffing.auto_approve_swaps === true,
    first_come_open_shifts: staffing.first_come_open_shifts === true,
  });
}

/** Changes only the two staffing switches, in one database call (other settings are untouched). */
export async function updateStaffingSwitches(
  orgId: string,
  switches: StaffingSwitches,
): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('set_staffing_switches', {
    p_organization_id: orgId,
    p_auto_approve_swaps: switches.auto_approve_swaps,
    p_first_come_open_shifts: switches.first_come_open_shifts,
  });
  return error ? failure(error) : ok(null);
}
