// Resources domain services: space kinds, spaces, weekly hours, closures.
// Reads and writes go through the caller's session client, so RLS decides what is allowed.
import { createClient } from '@/lib/supabase/server';
import type { Tables } from '@/lib/supabase/database.types';
import { fail, failure, ok, requireChanged, type Result } from '@/lib/db-errors';
import { fetchAllRows, fetchClampedPage, type Paged } from '@/lib/paging';
import { checkParent, overlapsExisting } from './logic';
import type {
  SpaceClosureCreate,
  SpaceCreate,
  SpaceHourCreate,
  SpaceKindCreate,
  SpaceKindUpdate,
  SpaceUpdate,
} from './schemas';

export type SpaceKind = Pick<
  Tables<'space_kinds'>,
  'id' | 'key' | 'name' | 'sort_order' | 'archived_at'
>;
export type Space = Pick<
  Tables<'spaces'>,
  | 'id'
  | 'location_id'
  | 'space_kind_id'
  | 'parent_space_id'
  | 'name'
  | 'description'
  | 'capacity'
  | 'sort_order'
  | 'archived_at'
>;
export type SpaceHour = Pick<
  Tables<'space_hours'>,
  'id' | 'space_id' | 'day_of_week' | 'opens_at' | 'closes_at' | 'effective_from' | 'effective_to'
>;
export type SpaceClosure = Pick<
  Tables<'space_closures'>,
  'id' | 'space_id' | 'starts_at' | 'ends_at' | 'reason'
>;

const KIND_COLUMNS = 'id, key, name, sort_order, archived_at';
const SPACE_COLUMNS =
  'id, location_id, space_kind_id, parent_space_id, name, description, capacity, sort_order, archived_at';
const HOUR_COLUMNS = 'id, space_id, day_of_week, opens_at, closes_at, effective_from, effective_to';
const SPACE_CONFLICT = 'A space with that name already exists here.';
const KIND_CONFLICT = 'A kind with that name already exists.';

// ---- space kinds ----

export async function listSpaceKinds(
  orgId: string,
  options: { includeArchived?: boolean } = {},
): Promise<Result<SpaceKind[]>> {
  const supabase = await createClient();
  return fetchAllRows<SpaceKind>((from, to) => {
    const q = supabase.from('space_kinds').select(KIND_COLUMNS).eq('organization_id', orgId);
    return (options.includeArchived ? q : q.is('archived_at', null))
      .order('sort_order')
      .order('name')
      .order('id')
      .range(from, to);
  });
}

export async function createSpaceKind(input: SpaceKindCreate): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.from('space_kinds').insert(input).select('id').single();
  if (error) return failure(error, { unique: KIND_CONFLICT });
  return ok({ id: data.id });
}

export async function updateSpaceKind(
  orgId: string,
  id: string,
  patch: SpaceKindUpdate,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('space_kinds')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { unique: KIND_CONFLICT });
  return requireChanged(data);
}

export function setSpaceKindArchived(orgId: string, id: string, archived: boolean) {
  return updateSpaceKind(orgId, id, { archived_at: archived ? new Date().toISOString() : null });
}

// ---- spaces ----

/** Every space at a location, archived included, in chunks so nothing is truncated. */
export async function listSpaces(orgId: string, locationId: string): Promise<Result<Space[]>> {
  const supabase = await createClient();
  return fetchAllRows<Space>((from, to) =>
    supabase
      .from('spaces')
      .select(SPACE_COLUMNS)
      .eq('organization_id', orgId)
      .eq('location_id', locationId)
      .order('sort_order')
      .order('name')
      .order('id')
      .range(from, to),
  );
}

export async function getSpace(
  orgId: string,
  locationId: string,
  id: string,
): Promise<Result<Space | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('spaces')
    .select(SPACE_COLUMNS)
    .eq('organization_id', orgId)
    .eq('location_id', locationId)
    .eq('id', id)
    .maybeSingle();
  if (error) return failure(error);
  return ok(data);
}

async function parentProblem(
  orgId: string,
  locationId: string,
  parentId: string,
  selfId?: string,
): Promise<string | null> {
  const parent = await getSpace(orgId, locationId, parentId);
  if (!parent.ok) return parent.message;
  const check = checkParent(parent.data, selfId, parentId);
  return check.ok ? null : check.message;
}

export async function createSpace(input: SpaceCreate): Promise<Result<{ id: string }>> {
  if (input.parent_space_id) {
    const problem = await parentProblem(
      input.organization_id,
      input.location_id,
      input.parent_space_id,
    );
    if (problem) return fail(problem);
  }
  const supabase = await createClient();
  const { data, error } = await supabase.from('spaces').insert(input).select('id').single();
  if (error) return failure(error, { unique: SPACE_CONFLICT });
  return ok({ id: data.id });
}

export async function updateSpace(
  orgId: string,
  locationId: string,
  id: string,
  patch: SpaceUpdate,
): Promise<Result<number>> {
  if (patch.parent_space_id) {
    const problem = await parentProblem(orgId, locationId, patch.parent_space_id, id);
    if (problem) return fail(problem);
  }
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('spaces')
    .update(patch)
    .eq('organization_id', orgId)
    .eq('location_id', locationId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error, { unique: SPACE_CONFLICT });
  return requireChanged(data);
}

export function setSpaceArchived(orgId: string, locationId: string, id: string, archived: boolean) {
  return updateSpace(orgId, locationId, id, {
    archived_at: archived ? new Date().toISOString() : null,
  });
}

// ---- weekly hours ----

export async function listSpaceHours(
  orgId: string,
  locationId: string,
  spaceId: string,
): Promise<Result<SpaceHour[]>> {
  const supabase = await createClient();
  return fetchAllRows<SpaceHour>((from, to) =>
    supabase
      .from('space_hours')
      .select(HOUR_COLUMNS)
      .eq('organization_id', orgId)
      .eq('location_id', locationId)
      .eq('space_id', spaceId)
      .order('day_of_week')
      .order('opens_at')
      .order('id')
      .range(from, to),
  );
}

/** Adds one open interval. Refuses an interval that overlaps one already on that weekday. */
export async function addSpaceHours(input: SpaceHourCreate): Promise<Result<{ id: string }>> {
  const existing = await listSpaceHours(input.organization_id, input.location_id, input.space_id);
  if (!existing.ok) return existing;
  const sameSeason = existing.data.filter(
    (r) =>
      (r.effective_from ?? '') === (input.effective_from ?? '') &&
      (r.effective_to ?? '') === (input.effective_to ?? ''),
  );
  if (overlapsExisting(sameSeason, input)) {
    return fail('Those hours overlap hours already set for that day.');
  }
  const supabase = await createClient();
  const { data, error } = await supabase.from('space_hours').insert(input).select('id').single();
  if (error) return failure(error);
  return ok({ id: data.id });
}

export async function removeSpaceHours(
  orgId: string,
  locationId: string,
  id: string,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('space_hours')
    .delete()
    .eq('organization_id', orgId)
    .eq('location_id', locationId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}

// ---- closures ----

/** One page of closures at a location, newest first. */
export async function listClosures(
  orgId: string,
  locationId: string,
  page: number,
): Promise<Result<Paged<SpaceClosure>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('space_closures')
      .select('id, space_id, starts_at, ends_at, reason', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('location_id', locationId)
      .order('starts_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
}

export async function addClosure(input: SpaceClosureCreate): Promise<Result<{ id: string }>> {
  const supabase = await createClient();
  const { data, error } = await supabase.from('space_closures').insert(input).select('id').single();
  if (error) return failure(error);
  return ok({ id: data.id });
}

export async function removeClosure(
  orgId: string,
  locationId: string,
  id: string,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('space_closures')
    .delete()
    .eq('organization_id', orgId)
    .eq('location_id', locationId)
    .eq('id', id)
    .select('id');
  if (error) return failure(error);
  return requireChanged(data);
}
