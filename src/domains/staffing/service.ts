// Staffing domain services: positions, qualifications, schedules, shifts, templates,
// availability, time off, swaps, drops and open-shift claims. Reads go through the caller's
// session client, so RLS decides what is visible, and are paged (PostgREST stops at 1000 rows).
// Every change is a database RPC (no table write exists for tenants). Free text (notes,
// reasons) is never logged.
import { createClient } from '@/lib/supabase/server';
import type { Tables } from '@/lib/supabase/database.types';
import {
  failure,
  ok,
  type DbErrorLike,
  type Result,
  mapDbError,
  GENERIC_ERROR,
} from '@/lib/db-errors';
import { fetchAllRows, fetchClampedPage, type Paged } from '@/lib/paging';
import { assignRuleOf, type AssignRule } from './logic';
import type {
  AvailabilityInput,
  Decision,
  DropRequest,
  PersonQualificationInput,
  PositionSave,
  QualificationSave,
  ScheduleCreate,
  ShiftAssign,
  ShiftCreate,
  ShiftUpdate,
  SwapRequest,
  TemplateApply,
  TemplateItemInput,
  TemplateSave,
  TimeOffRequestInput,
} from './schemas';

// ---- row types ----

const POSITION_COLUMNS =
  'id, organization_id, location_id, name, archived_at, position_qualifications(qualification_id)';
export type PositionRow = Pick<
  Tables<'positions'>,
  'id' | 'organization_id' | 'location_id' | 'name' | 'archived_at'
> & { position_qualifications: { qualification_id: string }[] };

export type QualificationRow = Pick<Tables<'qualifications'>, 'id' | 'name' | 'archived_at'>;
export type PersonQualificationRow = Pick<
  Tables<'person_qualifications'>,
  'id' | 'person_id' | 'qualification_id' | 'valid_from' | 'expires_on'
>;
export type ScheduleRow = Pick<
  Tables<'schedules'>,
  'id' | 'location_id' | 'week_start' | 'status' | 'published_at'
>;
const SHIFT_COLUMNS =
  'id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id, status, notes';
export type ShiftRow = Pick<
  Tables<'shifts'>,
  | 'id'
  | 'location_id'
  | 'schedule_id'
  | 'position_id'
  | 'starts_at'
  | 'ends_at'
  | 'assigned_person_id'
  | 'status'
  | 'notes'
>;
export type TemplateRow = Pick<
  Tables<'shift_templates'>,
  'id' | 'location_id' | 'name' | 'span_days' | 'archived_at'
>;
export type TemplateItemRow = Pick<
  Tables<'shift_template_items'>,
  | 'id'
  | 'template_id'
  | 'position_id'
  | 'day_offset'
  | 'start_time'
  | 'duration_minutes'
  | 'assigned_person_id'
  | 'notes'
>;
export type AvailabilityRow = Pick<
  Tables<'availability'>,
  'id' | 'day_of_week' | 'start_time' | 'end_time' | 'kind' | 'effective_from' | 'effective_to'
>;
export type TimeOffRow = Pick<
  Tables<'time_off_requests'>,
  'id' | 'person_id' | 'starts_on' | 'ends_on' | 'reason' | 'status' | 'decided_at'
>;
export type SwapRow = Pick<
  Tables<'shift_swaps'>,
  | 'id'
  | 'location_id'
  | 'kind'
  | 'shift_id'
  | 'counter_shift_id'
  | 'from_person_id'
  | 'to_person_id'
  | 'status'
  | 'note'
  | 'created_at'
>;
export type ClaimRow = Pick<
  Tables<'shift_claims'>,
  'id' | 'location_id' | 'shift_id' | 'person_id' | 'status' | 'created_at'
>;
export type ClaimableShift = {
  shift_id: string;
  location_id: string;
  schedule_id: string;
  position_id: string;
  starts_at: string;
  ends_at: string;
};
/** One row per template item. shift_id is null when no shift was made (time_change, position_unavailable). */
export type TemplateApplyRow = {
  shift_id: string | null;
  assigned_person_id: string | null;
  refused: string | null;
  item_id: string;
};

/** An override recorded on a shift (read only through shift_overrides, never from the table). */
export type ShiftOverride = {
  shift_id: string;
  override_kinds: string[];
  override_by_person_id: string;
  override_at: string;
};

export type SwapCandidate = { person_id: string; display_name: string };

/** A refusal while putting a person on a shift, with the rule that refused it (for the override flow). */
export type AssignResult<T = null> =
  { ok: true; data: T } | { ok: false; message: string; rule: AssignRule | null };

function assignFailure(error: DbErrorLike | null | undefined): {
  ok: false;
  message: string;
  rule: AssignRule | null;
} {
  const text = mapDbError(error);
  if (text === GENERIC_ERROR) console.error('database error', error?.code ?? '');
  return { ok: false, message: text, rule: error ? assignRuleOf(error) : null };
}

function done<T>(error: DbErrorLike | null, data: T): Result<T> {
  return error ? failure(error) : ok(data);
}

// ---- positions and qualifications ----

/** Positions of a location: its own and the organization-wide ones. */
export async function listPositions(
  orgId: string,
  opts: { locationId?: string | null; includeArchived?: boolean } = {},
): Promise<Result<PositionRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<PositionRow>((from, to) => {
    let q = supabase.from('positions').select(POSITION_COLUMNS).eq('organization_id', orgId);
    if (opts.locationId) q = q.or(`location_id.eq.${opts.locationId},location_id.is.null`);
    if (!opts.includeArchived) q = q.is('archived_at', null);
    return q.order('name').order('id').range(from, to);
  });
}

export async function listQualifications(
  orgId: string,
  includeArchived = false,
): Promise<Result<QualificationRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<QualificationRow>((from, to) => {
    let q = supabase
      .from('qualifications')
      .select('id, name, archived_at')
      .eq('organization_id', orgId);
    if (!includeArchived) q = q.is('archived_at', null);
    return q.order('name').order('id').range(from, to);
  });
}

export async function listQualificationHolders(
  orgId: string,
  qualificationId: string,
  page: number,
): Promise<Result<Paged<PersonQualificationRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('person_qualifications')
      .select('id, person_id, qualification_id, valid_from, expires_on', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('qualification_id', qualificationId)
      .order('expires_on', { ascending: true, nullsFirst: false })
      .order('id')
      .range(from, to),
  );
}

export async function savePosition(input: PositionSave): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('save_position', {
    p_organization_id: input.organization_id,
    p_location_id: input.location_id,
    p_name: input.name,
    p_qualification_ids: input.qualification_ids ?? null,
    p_position_id: input.position_id ?? null,
  });
  return done(error, data as string);
}

export async function archivePosition(id: string, archived: boolean): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('archive_position', {
    p_position_id: id,
    p_archived: archived,
  });
  return done(error, null);
}

export async function saveQualification(input: QualificationSave): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('save_qualification', {
    p_organization_id: input.organization_id,
    p_name: input.name,
    p_qualification_id: input.qualification_id ?? null,
  });
  return done(error, data as string);
}

export async function archiveQualification(id: string, archived: boolean): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('archive_qualification', {
    p_qualification_id: id,
    p_archived: archived,
  });
  return done(error, null);
}

export async function setPersonQualification(
  input: PersonQualificationInput,
): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('set_person_qualification', {
    p_organization_id: input.organization_id,
    p_person_id: input.person_id,
    p_qualification_id: input.qualification_id,
    p_valid_from: input.valid_from,
    p_expires_on: input.expires_on,
  });
  return done(error, data as string);
}

export async function removePersonQualification(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('remove_person_qualification', {
    p_person_qualification_id: id,
  });
  return done(error, null);
}

// ---- schedules and shifts ----

export async function listSchedules(
  orgId: string,
  locationId: string,
  page: number,
): Promise<Result<Paged<ScheduleRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('schedules')
      .select('id, location_id, week_start, status, published_at', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('location_id', locationId)
      .order('week_start', { ascending: false })
      .order('id')
      .range(from, to),
  );
}

/** The schedule of one location for the week that starts on `weekStart` (null: none, or not visible). */
export async function getSchedule(
  orgId: string,
  locationId: string,
  weekStart: string,
): Promise<Result<ScheduleRow | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('schedules')
    .select('id, location_id, week_start, status, published_at')
    .eq('organization_id', orgId)
    .eq('location_id', locationId)
    .eq('week_start', weekStart)
    .maybeSingle();
  return done(error, data);
}

export async function createSchedule(input: ScheduleCreate): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('create_schedule', {
    p_organization_id: input.organization_id,
    p_location_id: input.location_id,
    p_week_start: input.week_start,
  });
  return done(error, data as string);
}

export async function publishSchedule(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('publish_schedule', { p_schedule_id: id });
  return done(error, null);
}

/** Every shift of a schedule (cancelled ones included), in time order. */
export async function listScheduleShifts(
  orgId: string,
  scheduleId: string,
): Promise<Result<ShiftRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<ShiftRow>((from, to) =>
    supabase
      .from('shifts')
      .select(SHIFT_COLUMNS)
      .eq('organization_id', orgId)
      .eq('schedule_id', scheduleId)
      .order('starts_at')
      .order('id')
      .range(from, to),
  );
}

export async function getShift(orgId: string, id: string): Promise<Result<ShiftRow | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('shifts')
    .select(SHIFT_COLUMNS)
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  return done(error, data);
}

/** Shifts by id (for the screens that list swaps and claims). RLS shows only the ones the caller may see. */
export async function getShiftsByIds(
  orgId: string,
  ids: readonly string[],
): Promise<Result<ShiftRow[]>> {
  const unique = [...new Set(ids)].slice(0, 200);
  if (unique.length === 0) return ok([]);
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('shifts')
    .select(SHIFT_COLUMNS)
    .eq('organization_id', orgId)
    .in('id', unique);
  return done(error, data ?? []);
}

/** The caller's own scheduled shifts that have not ended, soonest first. */
export async function listMyUpcomingShifts(
  orgId: string,
  personId: string,
  page: number,
): Promise<Result<Paged<ShiftRow>>> {
  const supabase = await createClient();
  const nowIso = new Date().toISOString();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('shifts')
      .select(SHIFT_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('assigned_person_id', personId)
      .eq('status', 'scheduled')
      .gt('ends_at', nowIso)
      .order('starts_at')
      .order('id')
      .range(from, to),
  );
}

/** The start of the caller's next shift, or null. Used for the home page line. */
export async function getMyNextShift(
  orgId: string,
  personId: string,
): Promise<Result<ShiftRow | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('shifts')
    .select(SHIFT_COLUMNS)
    .eq('organization_id', orgId)
    .eq('assigned_person_id', personId)
    .eq('status', 'scheduled')
    .gt('ends_at', new Date().toISOString())
    .order('starts_at')
    .limit(1)
    .maybeSingle();
  return done(error, data);
}

/**
 * Overrides recorded on a schedule's shifts. Needs staff_schedule >= edit; for anyone else the
 * database answers 42501 and this returns an empty list (show nothing).
 */
export async function listShiftOverrides(scheduleId: string): Promise<Result<ShiftOverride[]>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('shift_overrides', { p_schedule_id: scheduleId });
  if (error) return error.code === '42501' ? ok([]) : failure(error);
  return ok(data ?? []);
}

/** People the caller may offer this shift to (name only; nothing about their time off or skills). */
export async function listSwapCandidates(shiftId: string): Promise<Result<SwapCandidate[]>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('swap_candidates', { p_shift_id: shiftId });
  return done(error, data ?? []);
}

/** Upcoming shifts whose person does not meet a qualification the position now needs. */
export async function positionShiftsMissingQualification(
  positionId: string,
): Promise<Result<number>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('position_shifts_missing_qualification', {
    p_position_id: positionId,
  });
  return done(error, typeof data === 'number' ? data : 0);
}

export async function createShift(input: ShiftCreate): Promise<AssignResult<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('create_shift', {
    p_schedule_id: input.schedule_id,
    p_position_id: input.position_id,
    p_starts_at: input.starts_at,
    p_ends_at: input.ends_at,
    p_assigned_person_id: input.assigned_person_id ?? null,
    p_notes: input.notes ?? null,
    p_override: input.override ?? false,
  });
  return error ? assignFailure(error) : { ok: true, data: data as string };
}

export async function updateShift(input: ShiftUpdate): Promise<AssignResult> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('update_shift', {
    p_shift_id: input.shift_id,
    p_position_id: input.position_id ?? null,
    p_starts_at: input.starts_at ?? null,
    p_ends_at: input.ends_at ?? null,
    p_notes: input.notes ?? null,
    p_override: input.override ?? false,
  });
  return error ? assignFailure(error) : { ok: true, data: null };
}

/** A null person opens the shift. */
export async function assignShift(input: ShiftAssign): Promise<AssignResult> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('assign_shift', {
    p_shift_id: input.shift_id,
    p_person_id: input.person_id,
    p_override: input.override ?? false,
  });
  return error ? assignFailure(error) : { ok: true, data: null };
}

export async function cancelShift(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('cancel_shift', { p_shift_id: id });
  return done(error, null);
}

// ---- templates ----

export async function listTemplates(
  orgId: string,
  locationId: string,
  includeArchived = false,
): Promise<Result<TemplateRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<TemplateRow>((from, to) => {
    let q = supabase
      .from('shift_templates')
      .select('id, location_id, name, span_days, archived_at')
      .eq('organization_id', orgId)
      .eq('location_id', locationId);
    if (!includeArchived) q = q.is('archived_at', null);
    return q.order('name').order('id').range(from, to);
  });
}

export async function getTemplate(orgId: string, id: string): Promise<Result<TemplateRow | null>> {
  const supabase = await createClient();
  const { data, error } = await supabase
    .from('shift_templates')
    .select('id, location_id, name, span_days, archived_at')
    .eq('organization_id', orgId)
    .eq('id', id)
    .maybeSingle();
  return done(error, data);
}

export async function listTemplateItems(
  orgId: string,
  templateId: string,
): Promise<Result<TemplateItemRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<TemplateItemRow>((from, to) =>
    supabase
      .from('shift_template_items')
      .select(
        'id, template_id, position_id, day_offset, start_time, duration_minutes, assigned_person_id, notes',
      )
      .eq('organization_id', orgId)
      .eq('template_id', templateId)
      .order('day_offset')
      .order('start_time')
      .order('id')
      .range(from, to),
  );
}

export async function saveTemplate(input: TemplateSave): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('save_shift_template', {
    p_organization_id: input.organization_id,
    p_location_id: input.location_id,
    p_name: input.name,
    p_span_days: input.span_days ?? null,
    p_template_id: input.template_id ?? null,
  });
  return done(error, data as string);
}

export async function archiveTemplate(id: string, archived: boolean): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('archive_shift_template', {
    p_template_id: id,
    p_archived: archived,
  });
  return done(error, null);
}

export async function addTemplateItem(input: TemplateItemInput): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('add_shift_template_item', {
    p_template_id: input.template_id,
    p_position_id: input.position_id,
    p_day_offset: input.day_offset,
    p_start_time: input.start_time,
    p_duration_minutes: input.duration_minutes,
    p_assigned_person_id: input.assigned_person_id ?? null,
    p_notes: input.notes ?? null,
  });
  return done(error, data as string);
}

export async function removeTemplateItem(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('remove_shift_template_item', { p_item_id: id });
  return done(error, null);
}

/** Stamps a template onto a draft schedule. Each row says whether the item got its person or became an open shift, and why. */
export async function applyTemplate(input: TemplateApply): Promise<Result<TemplateApplyRow[]>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('apply_shift_template', {
    p_schedule_id: input.schedule_id,
    p_template_id: input.template_id,
    p_first_day: input.first_day ?? 0,
  });
  return done(error, data ?? []);
}

// ---- availability and time off ----

export async function listMyAvailability(
  orgId: string,
  personId: string,
): Promise<Result<AvailabilityRow[]>> {
  const supabase = await createClient();
  return fetchAllRows<AvailabilityRow>((from, to) =>
    supabase
      .from('availability')
      .select('id, day_of_week, start_time, end_time, kind, effective_from, effective_to')
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('day_of_week')
      .order('start_time')
      .order('id')
      .range(from, to),
  );
}

export async function addAvailability(input: AvailabilityInput): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('add_availability', {
    p_organization_id: input.organization_id,
    p_day_of_week: input.day_of_week,
    p_start_time: input.start_time,
    p_end_time: input.end_time,
    p_kind: input.kind,
    p_effective_from: input.effective_from ?? null,
    p_effective_to: input.effective_to ?? null,
  });
  return done(error, data as string);
}

export async function removeAvailability(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('remove_availability', { p_availability_id: id });
  return done(error, null);
}

export async function listMyTimeOff(
  orgId: string,
  personId: string,
  page: number,
): Promise<Result<Paged<TimeOffRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('time_off_requests')
      .select('id, person_id, starts_on, ends_on, reason, status, decided_at', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('starts_on', { ascending: false })
      .order('id')
      .range(from, to),
  );
}

/** Time off waiting for a decision, for people in the caller's scope (RLS limits the rows). */
export async function listPendingTimeOff(
  orgId: string,
  page: number,
): Promise<Result<Paged<TimeOffRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('time_off_requests')
      .select('id, person_id, starts_on, ends_on, reason, status, decided_at', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('status', 'pending')
      .order('starts_on')
      .order('id')
      .range(from, to),
  );
}

export async function requestTimeOff(input: TimeOffRequestInput): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('request_time_off', {
    p_organization_id: input.organization_id,
    p_starts_on: input.starts_on,
    p_ends_on: input.ends_on,
    p_reason: input.reason ?? null,
  });
  return done(error, data as string);
}

export async function cancelTimeOff(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('cancel_time_off', { p_time_off_id: id });
  return done(error, null);
}

export async function decideTimeOff(id: string, approve: boolean): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('decide_time_off', {
    p_time_off_id: id,
    p_approve: approve,
  });
  return done(error, null);
}

// ---- swaps, drops, claims ----

const SWAP_COLUMNS =
  'id, location_id, kind, shift_id, counter_shift_id, from_person_id, to_person_id, status, note, created_at';

/** Swaps and drops the person is part of (as offerer or receiver), newest first. */
export async function listMySwaps(
  orgId: string,
  personId: string,
  page: number,
): Promise<Result<Paged<SwapRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('shift_swaps')
      .select(SWAP_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId)
      .or(`from_person_id.eq.${personId},to_person_id.eq.${personId}`)
      .order('created_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
}

/** Swaps and drops waiting on a manager at the locations the caller may decide for (RLS limits the rows). */
export async function listSwapsAwaitingDecision(
  orgId: string,
  page: number,
): Promise<Result<Paged<SwapRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('shift_swaps')
      .select(SWAP_COLUMNS, { count: 'exact' })
      .eq('organization_id', orgId)
      .or('and(kind.eq.drop,status.eq.requested),and(kind.eq.swap,status.eq.accepted)')
      .order('created_at')
      .order('id')
      .range(from, to),
  );
}

export async function listMyClaims(
  orgId: string,
  personId: string,
  page: number,
): Promise<Result<Paged<ClaimRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('shift_claims')
      .select('id, location_id, shift_id, person_id, status, created_at', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('person_id', personId)
      .order('created_at', { ascending: false })
      .order('id')
      .range(from, to),
  );
}

export async function listClaimsAwaitingDecision(
  orgId: string,
  page: number,
): Promise<Result<Paged<ClaimRow>>> {
  const supabase = await createClient();
  return fetchClampedPage(page, (from, to) =>
    supabase
      .from('shift_claims')
      .select('id, location_id, shift_id, person_id, status, created_at', { count: 'exact' })
      .eq('organization_id', orgId)
      .eq('status', 'requested')
      .order('created_at')
      .order('id')
      .range(from, to),
  );
}

/** Open shifts the caller can claim right now (the database checks every rule for them). */
export async function listClaimableShifts(orgId: string): Promise<Result<ClaimableShift[]>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('my_claimable_shifts', {
    p_organization_id: orgId,
    p_limit: 200,
  });
  return done(error, data ?? []);
}

export async function requestSwap(input: SwapRequest): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('request_shift_swap', {
    p_shift_id: input.shift_id,
    p_to_person_id: input.to_person_id,
    p_counter_shift_id: input.counter_shift_id ?? null,
    p_note: input.note ?? null,
  });
  return done(error, data as string);
}

export async function requestDrop(input: DropRequest): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('request_shift_drop', {
    p_shift_id: input.shift_id,
    p_note: input.note ?? null,
  });
  return done(error, data as string);
}

/** 'accepted' (waits for a manager), 'approved' (automatic) or 'denied'. */
export async function respondToSwap(
  id: string,
  accept: boolean,
): Promise<Result<'accepted' | 'approved' | 'denied'>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('respond_shift_swap', {
    p_swap_id: id,
    p_accept: accept,
  });
  if (error) return failure(error);
  return data === 'accepted' || data === 'approved' || data === 'denied' ? ok(data) : failure(null);
}

export async function cancelSwap(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('cancel_shift_swap', { p_swap_id: id });
  return done(error, null);
}

export async function decideSwap(input: Decision): Promise<AssignResult> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('decide_shift_swap', {
    p_swap_id: input.id,
    p_approve: input.approve,
    p_override: input.override ?? false,
  });
  return error ? assignFailure(error) : { ok: true, data: null };
}

export async function requestClaim(shiftId: string): Promise<Result<string>> {
  const supabase = await createClient();
  const { data, error } = await supabase.rpc('request_shift_claim', { p_shift_id: shiftId });
  return done(error, data as string);
}

export async function cancelClaim(id: string): Promise<Result<null>> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('cancel_shift_claim', { p_claim_id: id });
  return done(error, null);
}

export async function decideClaim(input: Decision): Promise<AssignResult> {
  const supabase = await createClient();
  const { error } = await supabase.rpc('decide_shift_claim', {
    p_claim_id: input.id,
    p_approve: input.approve,
    p_override: input.override ?? false,
  });
  return error ? assignFailure(error) : { ok: true, data: null };
}
