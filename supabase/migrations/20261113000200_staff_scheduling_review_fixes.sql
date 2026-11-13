-- Phase 3 security review fixes (staff scheduling). 20261113000100 is committed;
-- everything here replaces or adds to it. See docs/SECURITY.md "Staff scheduling"
-- and its "Review fixes (20261113000200)" part for the behaviour each item gives.
--
--   M1  a schedule admin cannot override the rules for themselves
--   M2  shifts.override_* and uncovered_emitted_for are not readable by tenants
--       (column grants); schedulers read overrides through shift_overrides();
--       override columns are redacted in shifts audit rows
--   M4  fan-out: apply_shift_template charges shift_edit per created shift; at most
--       2,000 scheduled shifts per schedule; publish emits no shift.opened (the
--       schedule.published payload carries open_shift_count); shift.opened is
--       throttled to 20 per location per clock hour
--   M5  own-shift reads and the three cancel RPCs need real membership (MFA rules)
--   L1  the person is checked against the organization before any person lock
--   L2  archive_qualification vs save_position serialize on the qualification row
--   L3  auto-approval only for swaps without a counter shift
--   L4  staff paths: a conflict with a draft shift gives a generic refusal
--   L5  position_shifts_missing_qualification(): how many future shifts now miss one
--   L6  update_shift (new time / position) closes open swaps and claims of the shift
--   L7  set_staffing_switches(): atomic change of settings.staffing only
--   DST apply_shift_template reports skipped items in its result
--   G1  swap_candidates(); G2 update_shift p_notes '' clears (documented);
--   G3  day_offset 0 = schedule week_start + p_first_day (documented)

-- ===========================================================================
-- Small helpers
-- ===========================================================================

-- Most scheduled shifts one schedule may hold (M4).
create function private.max_shifts_per_schedule()
returns integer
language sql
immutable
set search_path = ''
as $$ select 2000 $$;

-- At most this many shift.opened events per location per clock hour (M4).
create function private.max_shift_opened_per_hour()
returns integer
language sql
immutable
set search_path = ''
as $$ select 20 $$;

-- The not_member rule alone (no locks, nothing but reads): is p_person unable to
-- work at the location? With p_check_visibility, a signed-in non-platform-admin
-- caller must also be able to see the person. Used before any person lock (L1)
-- and by shift_assignment_problems.
create function private.assignee_not_member(
  p_organization_id uuid, p_location_id uuid, p_person_id uuid, p_check_visibility boolean)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if p_person_id is null then
    return false;
  end if;
  if not exists (select 1 from public.people p
                 where p.id = p_person_id and p.organization_id = p_organization_id and p.archived_at is null) then
    return true;
  end if;
  return not private.person_is_active_member(p_organization_id, p_person_id)
      or coalesce(private.person_effective_level(p_organization_id, p_person_id, p_location_id, 'staff_schedule')
                  >= 'view', false) is not true
      or (coalesce(p_check_visibility, true) and (select auth.uid()) is not null and not public.is_platform_admin()
          and p_person_id not in (select private.visible_person_ids()));
end;
$$;

-- Raise the not_member refusal before locking a manager-supplied person (L1).
create function private.precheck_assignee(
  p_organization_id uuid, p_location_id uuid, p_person_id uuid)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if private.assignee_not_member(p_organization_id, p_location_id, p_person_id, true) then
    raise exception 'that person cannot work at this location' using errcode = 'check_violation', detail = 'not_member';
  end if;
end;
$$;

-- Take the per-schedule shift-count lock and refuse when p_adding more scheduled
-- shifts would pass the cap. Returns the current count (M4).
create function private.lock_schedule_shift_count(p_schedule_id uuid, p_adding integer)
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n integer;
begin
  perform pg_advisory_xact_lock(hashtextextended('staffing:schedule:' || p_schedule_id::text, 0));
  select count(*) into v_n from public.shifts s where s.schedule_id = p_schedule_id and s.status = 'scheduled';
  if v_n + coalesce(p_adding, 0) > private.max_shifts_per_schedule() then
    raise exception 'a schedule holds at most 2000 shifts' using errcode = 'check_violation', detail = 'too_many_shifts';
  end if;
  return v_n;
end;
$$;

-- Emit shift.opened unless the location already had its share this clock hour.
-- Returns whether it was emitted. The open shift itself is unaffected; the
-- uncovered sweep still covers it (M4).
create function private.emit_shift_opened(p_s public.shifts, p_via text)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if not public.consume_rate_limit('staffing.shift_opened',
                                   p_s.organization_id::text || ':' || p_s.location_id::text,
                                   private.max_shift_opened_per_hour(), 3600) then
    return false;
  end if;
  perform private.emit_shift_event('shift.opened', p_s, jsonb_build_object('via', p_via));
  return true;
end;
$$;

revoke all on function
  private.max_shifts_per_schedule(),
  private.max_shift_opened_per_hour(),
  private.assignee_not_member(uuid, uuid, uuid, boolean),
  private.precheck_assignee(uuid, uuid, uuid),
  private.lock_schedule_shift_count(uuid, integer),
  private.emit_shift_opened(public.shifts, text)
from public, anon, authenticated;

-- ===========================================================================
-- M5: own shifts only through real membership (MFA rules of my_assignments)
-- ===========================================================================
create or replace function private.can_see_shift(
  p_organization_id uuid, p_location_id uuid, p_schedule_id uuid, p_assigned_person_id uuid, p_status text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'edit')
    or (exists (select 1 from public.schedules sc
                where sc.id = p_schedule_id and sc.organization_id = p_organization_id and sc.status = 'published')
        and ((p_status <> 'cancelled'
              and public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'view'))
             or (p_assigned_person_id is not null
                 and p_assigned_person_id in (select private.my_person_ids())))),
    false)
$$;

-- ===========================================================================
-- M2: override columns are not tenant-readable
-- ===========================================================================
revoke select on table public.shifts from authenticated;
grant select (id, organization_id, location_id, schedule_id, position_id, starts_at, ends_at, assigned_person_id,
              status, notes, created_by_person_id, cancelled_at, created_at, updated_at)
  on table public.shifts to authenticated;
-- service_role keeps its table-level SELECT (Phase 2 pattern).

do $$
begin
  perform private.enable_audit('public.shifts', 'id',
    array['notes', 'override_kinds', 'override_by_person_id', 'override_at']);
end;
$$;

-- Overrides recorded on a schedule's shifts, for staff_schedule >= edit at its
-- location (42501 otherwise). Only shifts that carry an override.
create function public.shift_overrides(p_schedule_id uuid)
returns table (shift_id uuid, override_kinds text[], override_by_person_id uuid, override_at timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_sc public.schedules%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_sc from public.schedules sc where sc.id = p_schedule_id;
  if not found or public.has_permission(v_sc.organization_id, v_sc.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  return query
  select s.id, s.override_kinds, s.override_by_person_id, s.override_at
  from public.shifts s
  where s.schedule_id = v_sc.id and s.organization_id = v_sc.organization_id and s.override_kinds is not null
  order by s.starts_at, s.id;
end;
$$;

-- ===========================================================================
-- Assignment rules: L1 (shared not_member), M1 (no self-override), L4 (generic
-- refusal on staff paths when the conflict is a draft shift)
-- ===========================================================================
create or replace function private.shift_assignment_problems(
  p_organization_id uuid, p_location_id uuid, p_position_id uuid,
  p_starts_at timestamptz, p_ends_at timestamptz, p_person_id uuid,
  p_ignore uuid[] default '{}', p_check_visibility boolean default true)
returns text[]
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_tz text;
  v_day date;
  v_out text[] := '{}';
begin
  if p_person_id is null then
    return v_out;
  end if;
  if private.assignee_not_member(p_organization_id, p_location_id, p_person_id, p_check_visibility) then
    return array['not_member'];
  end if;
  if exists (select 1 from public.shifts s
             where s.organization_id = p_organization_id and s.assigned_person_id = p_person_id
               and s.status = 'scheduled' and not (s.id = any (coalesce(p_ignore, '{}')))
               and tstzrange(s.starts_at, s.ends_at, '[)') && tstzrange(p_starts_at, p_ends_at, '[)')) then
    v_out := v_out || 'overlap'::text;
  end if;
  select l.timezone into v_tz from public.locations l where l.id = p_location_id and l.organization_id = p_organization_id;
  if exists (select 1 from public.time_off_requests t
             where t.organization_id = p_organization_id and t.person_id = p_person_id and t.status = 'approved'
               and tstzrange(t.starts_on::timestamp at time zone v_tz, (t.ends_on + 1)::timestamp at time zone v_tz, '[)')
                   && tstzrange(p_starts_at, p_ends_at, '[)')) then
    v_out := v_out || 'time_off'::text;
  end if;
  v_day := (p_starts_at at time zone v_tz)::date;
  if exists (select 1 from public.position_qualifications pq
             where pq.position_id = p_position_id and pq.organization_id = p_organization_id
               and not exists (select 1 from public.person_qualifications x
                               where x.organization_id = p_organization_id and x.person_id = p_person_id
                                 and x.qualification_id = pq.qualification_id
                                 and (x.valid_from is null or x.valid_from <= v_day)
                                 and (x.expires_on is null or x.expires_on >= v_day))) then
    v_out := v_out || 'qualification'::text;
  end if;
  return v_out;
end;
$$;

-- p_check_visibility = false marks a staff path (the person acts for themselves).
create or replace function private.require_assignable(
  p_organization_id uuid, p_location_id uuid, p_position_id uuid,
  p_starts_at timestamptz, p_ends_at timestamptz, p_person_id uuid,
  p_ignore uuid[], p_override boolean, p_check_visibility boolean default true)
returns text[]
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_p text[];
  v_first text;
  v_signed_in boolean := (select auth.uid()) is not null;
begin
  if coalesce(p_override, false) and v_signed_in
     and public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'admin') is not true then
    raise exception 'only a schedule admin can override' using errcode = 'insufficient_privilege';
  end if;
  v_p := private.shift_assignment_problems(p_organization_id, p_location_id, p_position_id, p_starts_at, p_ends_at,
                                           p_person_id, p_ignore, p_check_visibility);
  if 'not_member' = any (v_p) then
    v_first := 'not_member';
  elsif 'overlap' = any (v_p) then
    v_first := 'overlap';
  elsif cardinality(v_p) > 0 and not coalesce(p_override, false) then
    v_first := v_p[1];
  end if;
  -- M1: an override that is actually needed is never for the caller themselves.
  if v_first is null and coalesce(p_override, false) and cardinality(v_p) > 0 and v_signed_in
     and p_person_id is not distinct from public.current_person_id(p_organization_id) then
    raise exception 'you cannot override the rules for yourself' using errcode = 'insufficient_privilege';
  end if;
  -- L4: on a staff path, an overlap with no published shift of the person behind
  -- it (a draft shift) is not named.
  if v_first = 'overlap' and not coalesce(p_check_visibility, true) and v_signed_in
     and p_person_id is not distinct from public.current_person_id(p_organization_id)
     and not exists (
       select 1 from public.shifts s
       join public.schedules sc on sc.id = s.schedule_id and sc.organization_id = s.organization_id
       where s.organization_id = p_organization_id and s.assigned_person_id = p_person_id
         and s.status = 'scheduled' and sc.status = 'published'
         and not (s.id = any (coalesce(p_ignore, '{}')))
         and tstzrange(s.starts_at, s.ends_at, '[)') && tstzrange(p_starts_at, p_ends_at, '[)')) then
    raise exception 'you cannot take this shift' using errcode = 'check_violation', detail = 'unavailable';
  end if;
  if v_first is not null then
    raise exception '%', case v_first
        when 'not_member' then 'that person cannot work at this location'
        when 'overlap' then 'that person already has a shift at that time'
        when 'time_off' then 'that person has approved time off then'
        else 'that person is missing a required qualification' end
      using errcode = 'check_violation', detail = v_first;
  end if;
  return v_p;
end;
$$;

-- M4: shift.opened through the throttle.
create or replace function private.after_assignee_change(p_old public.shifts, p_new public.shifts, p_via text)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if p_old.assigned_person_id is not distinct from p_new.assigned_person_id then
    return;
  end if;
  perform private.close_shift_exchanges(p_new.id, p_new.organization_id, p_new.assigned_person_id is not null);
  if not exists (select 1 from public.schedules sc where sc.id = p_new.schedule_id and sc.status = 'published') then
    return;
  end if;
  if p_new.assigned_person_id is not null then
    perform private.emit_shift_event('shift.assigned', p_new,
      jsonb_build_object('previous_person_id', p_old.assigned_person_id, 'via', p_via,
                         'override', p_new.override_kinds is not null));
  end if;
  if p_old.assigned_person_id is not null then
    perform private.emit_shift_event('shift.unassigned', p_new,
      jsonb_build_object('person_id', p_old.assigned_person_id, 'new_person_id', p_new.assigned_person_id, 'via', p_via));
  end if;
  if p_new.assigned_person_id is null then
    perform private.emit_shift_opened(p_new, p_via);
  end if;
end;
$$;

-- ===========================================================================
-- L2 + L5: positions and qualifications
-- ===========================================================================

-- Same signature as 20261113000100 (returns the position id). The qualifications
-- named are share-locked (archive_qualification locks the row for update), so a
-- concurrent archive either comes first and this call says 'unknown
-- qualification', or waits and then sees the requirement. For L5 call
-- public.position_shifts_missing_qualification(id) afterwards.
create or replace function public.save_position(
  p_organization_id uuid, p_location_id uuid, p_name text,
  p_qualification_ids uuid[] default null, p_position_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_p public.positions%rowtype;
  v_q uuid[];
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_position_id is not null then
    select * into v_p from public.positions p where p.id = p_position_id;
    if not found or v_p.organization_id is distinct from p_organization_id
       or public.has_permission(v_p.organization_id, v_p.location_id, 'staff_schedule', 'admin') is not true then
      raise exception 'not allowed' using errcode = 'insufficient_privilege';
    end if;
    if v_p.location_id is distinct from p_location_id then
      raise exception 'the location of a position cannot change' using errcode = 'invalid_parameter_value';
    end if;
  elsif p_organization_id is null
        or public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  if p_name is null or char_length(btrim(p_name)) not between 1 and 100 then
    raise exception 'a name needs 1 to 100 characters' using errcode = 'invalid_parameter_value';
  end if;
  if p_qualification_ids is not null then
    select coalesce(array_agg(distinct q), '{}') into v_q from unnest(p_qualification_ids) q where q is not null;
    if cardinality(v_q) > 20 then
      raise exception 'at most 20 qualifications' using errcode = 'invalid_parameter_value';
    end if;
    perform 1 from public.qualifications x
    where x.id = any (v_q) and x.organization_id = p_organization_id
    order by x.id
    for share;
    if exists (select 1 from unnest(v_q) q
               where not exists (select 1 from public.qualifications x
                                 where x.id = q and x.organization_id = p_organization_id and x.archived_at is null)) then
      raise exception 'unknown qualification' using errcode = 'invalid_parameter_value';
    end if;
  end if;
  begin
    if p_position_id is null then
      insert into public.positions (organization_id, location_id, name)
      values (p_organization_id, p_location_id, btrim(p_name))
      returning * into v_p;
    else
      select * into v_p from public.positions p where p.id = p_position_id for update;
      if v_p.name is distinct from btrim(p_name) then
        update public.positions p set name = btrim(p_name) where p.id = v_p.id returning * into v_p;
      end if;
    end if;
  exception when unique_violation then
    raise exception 'a position with that name already exists' using errcode = 'invalid_parameter_value';
  end;
  if p_qualification_ids is not null then
    delete from public.position_qualifications pq
    where pq.position_id = v_p.id and pq.organization_id = v_p.organization_id and not (pq.qualification_id = any (v_q));
    insert into public.position_qualifications (organization_id, position_id, qualification_id)
    select v_p.organization_id, v_p.id, q from unnest(v_q) q
    on conflict (position_id, qualification_id) do nothing;
  end if;
  return v_p.id;
end;
$$;

-- L5: future scheduled shifts of a position whose assignee does not hold every
-- qualification it requires on the shift's local date, without a recorded
-- qualification override. Nothing is refused or unassigned: the app shows the
-- number after save_position so a scheduler can reassign. Needs staff_schedule
-- >= edit in the position's scope (its location, or organization scope for an
-- organization-wide position); 42501 otherwise.
create function public.position_shifts_missing_qualification(p_position_id uuid)
returns integer
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_p public.positions%rowtype;
  v_n integer;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_p from public.positions p where p.id = p_position_id;
  if not found or public.has_permission(v_p.organization_id, v_p.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select count(*) into v_n
  from public.shifts s
  join public.locations l on l.id = s.location_id and l.organization_id = s.organization_id
  where s.organization_id = v_p.organization_id and s.position_id = v_p.id
    and s.status = 'scheduled' and s.assigned_person_id is not null and s.starts_at > now()
    and not ('qualification' = any (coalesce(s.override_kinds, '{}')))
    and exists (select 1 from public.position_qualifications pq
                where pq.position_id = v_p.id and pq.organization_id = v_p.organization_id
                  and not exists (select 1 from public.person_qualifications x
                                  where x.organization_id = s.organization_id and x.person_id = s.assigned_person_id
                                    and x.qualification_id = pq.qualification_id
                                    and (x.valid_from is null or x.valid_from <= (s.starts_at at time zone l.timezone)::date)
                                    and (x.expires_on is null or x.expires_on >= (s.starts_at at time zone l.timezone)::date)));
  return v_n;
end;
$$;

-- L2: lock the qualification row before checking who requires it.
create or replace function public.archive_qualification(p_qualification_id uuid, p_archived boolean default true)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_q public.qualifications%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_q from public.qualifications q where q.id = p_qualification_id;
  if not found or private.has_permission_anywhere(v_q.organization_id, 'staff_schedule', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  select * into v_q from public.qualifications q where q.id = p_qualification_id for update;
  if coalesce(p_archived, true) and exists (
       select 1 from public.position_qualifications pq
       join public.positions p on p.id = pq.position_id and p.organization_id = pq.organization_id
       where pq.qualification_id = v_q.id and pq.organization_id = v_q.organization_id and p.archived_at is null) then
    raise exception 'a position still requires this qualification' using errcode = 'invalid_parameter_value';
  end if;
  begin
    update public.qualifications q
    set archived_at = case when coalesce(p_archived, true) then coalesce(q.archived_at, now()) end
    where q.id = v_q.id;
  exception when unique_violation then
    raise exception 'a qualification with that name already exists' using errcode = 'invalid_parameter_value';
  end;
end;
$$;

-- ===========================================================================
-- Schedules and shifts
-- ===========================================================================

-- M4: publish emits schedule.published only; the payload gains open_shift_count.
create or replace function public.publish_schedule(p_schedule_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_sc public.schedules%rowtype;
  v_n integer;
  v_open integer;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_sc from public.schedules sc where sc.id = p_schedule_id;
  if not found or public.has_permission(v_sc.organization_id, v_sc.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select * into v_sc from public.schedules sc where sc.id = p_schedule_id for update;
  if v_sc.status <> 'draft' then
    raise exception 'this schedule is already published' using errcode = 'invalid_parameter_value';
  end if;
  perform private.enforce_write_limit('schedule_publish');
  update public.schedules sc
  set status = 'published', published_at = now(), published_by_person_id = public.current_person_id(sc.organization_id)
  where sc.id = v_sc.id
  returning * into v_sc;
  select count(*), count(*) filter (where s.assigned_person_id is null) into v_n, v_open
  from public.shifts s where s.schedule_id = v_sc.id and s.status = 'scheduled';
  perform private.emit_event(
    v_sc.organization_id, v_sc.location_id, 'schedule.published', 'schedules', v_sc.id,
    jsonb_build_object('schedule_id', v_sc.id, 'location_id', v_sc.location_id, 'week_start', v_sc.week_start,
                       'shift_count', v_n, 'open_shift_count', v_open, 'actor_person_id', v_sc.published_by_person_id));
end;
$$;

-- L1 (person checked before its lock), M4 (cap, throttled shift.opened).
create or replace function public.create_shift(
  p_schedule_id uuid, p_position_id uuid, p_starts_at timestamptz, p_ends_at timestamptz,
  p_assigned_person_id uuid default null, p_notes text default null, p_override boolean default false)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_sc public.schedules%rowtype;
  v_ov text[] := '{}';
  v_s public.shifts%rowtype;
  v_blank public.shifts%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_sc from public.schedules sc where sc.id = p_schedule_id;
  if not found or public.has_permission(v_sc.organization_id, v_sc.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_edit');
  perform private.validate_shift_times(v_sc, p_starts_at, p_ends_at);
  perform private.validate_shift_position(v_sc, p_position_id);
  if char_length(p_notes) > 1000 then
    raise exception 'notes are too long' using errcode = 'invalid_parameter_value';
  end if;
  select * into v_sc from public.schedules sc where sc.id = p_schedule_id for share;
  perform private.lock_schedule_shift_count(v_sc.id, 1);
  if p_assigned_person_id is not null then
    perform private.precheck_assignee(v_sc.organization_id, v_sc.location_id, p_assigned_person_id);
    perform private.lock_staffing_people(array[p_assigned_person_id]);
    v_ov := private.require_assignable(v_sc.organization_id, v_sc.location_id, p_position_id, p_starts_at, p_ends_at,
                                       p_assigned_person_id, '{}', p_override);
  end if;
  insert into public.shifts (organization_id, location_id, schedule_id, position_id, starts_at, ends_at, notes,
                             created_by_person_id)
  values (v_sc.organization_id, v_sc.location_id, v_sc.id, p_position_id, p_starts_at, p_ends_at,
          nullif(btrim(p_notes), ''), public.current_person_id(v_sc.organization_id))
  returning * into v_s;
  if p_assigned_person_id is not null then
    v_blank := v_s;
    v_s := private.write_shift_assignee(v_s.id, p_assigned_person_id, v_ov);
    perform private.after_assignee_change(v_blank, v_s, 'manager');
  elsif v_sc.status = 'published' then
    perform private.emit_shift_opened(v_s, 'manager');
  end if;
  return v_s.id;
end;
$$;

-- L6: a new time or position closes open swaps / drops / claims of the shift.
-- G2: p_notes null keeps the notes; '' (or only spaces) clears them.
create or replace function public.update_shift(
  p_shift_id uuid, p_position_id uuid default null, p_starts_at timestamptz default null,
  p_ends_at timestamptz default null, p_notes text default null, p_override boolean default false)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_s public.shifts%rowtype := private.lock_shift_for_scheduler(p_shift_id, 'edit');
  v_sc public.schedules%rowtype;
  v_new_pos uuid;
  v_new_start timestamptz;
  v_new_end timestamptz;
  v_ov text[];
  v_after public.shifts%rowtype;
  v_moved boolean;
begin
  perform private.enforce_write_limit('shift_edit');
  if v_s.status <> 'scheduled' then
    raise exception 'a cancelled shift cannot be changed' using errcode = 'invalid_parameter_value';
  end if;
  select * into v_sc from public.schedules sc where sc.id = v_s.schedule_id;
  v_new_pos := coalesce(p_position_id, v_s.position_id);
  v_new_start := coalesce(p_starts_at, v_s.starts_at);
  v_new_end := coalesce(p_ends_at, v_s.ends_at);
  perform private.validate_shift_times(v_sc, v_new_start, v_new_end);
  if v_new_pos is distinct from v_s.position_id then
    perform private.validate_shift_position(v_sc, v_new_pos);
  end if;
  if char_length(p_notes) > 1000 then
    raise exception 'notes are too long' using errcode = 'invalid_parameter_value';
  end if;
  v_moved := v_new_pos <> v_s.position_id or v_new_start <> v_s.starts_at or v_new_end <> v_s.ends_at;
  v_ov := v_s.override_kinds;
  if v_s.assigned_person_id is not null and v_moved then
    perform private.lock_staffing_people(array[v_s.assigned_person_id]);
    v_ov := private.require_assignable(v_s.organization_id, v_s.location_id, v_new_pos, v_new_start, v_new_end,
                                       v_s.assigned_person_id, array[v_s.id], p_override);
  end if;
  begin
    update public.shifts s
    set position_id = v_new_pos, starts_at = v_new_start, ends_at = v_new_end,
        notes = case when p_notes is null then s.notes else nullif(btrim(p_notes), '') end,
        override_kinds = case when cardinality(coalesce(v_ov, '{}')) > 0 then v_ov end,
        override_at = case when cardinality(coalesce(v_ov, '{}')) = 0 then null
                           when v_ov is not distinct from s.override_kinds then s.override_at else now() end,
        override_by_person_id = case when cardinality(coalesce(v_ov, '{}')) = 0 then null
                                     when v_ov is not distinct from s.override_kinds then s.override_by_person_id
                                     else public.current_person_id(s.organization_id) end,
        uncovered_emitted_for = case when v_new_start <> s.starts_at then null else s.uncovered_emitted_for end
    where s.id = v_s.id
    returning * into v_after;
  exception when exclusion_violation then
    raise exception 'that person already has a shift at that time' using errcode = 'check_violation', detail = 'overlap';
  end;
  if v_moved then
    perform private.close_shift_exchanges(v_s.id, v_s.organization_id, true);
  end if;
  if v_sc.status = 'published' and v_after.assigned_person_id is not null and v_moved then
    perform private.emit_shift_event('shift.changed', v_after,
      jsonb_build_object('previous_starts_at', v_s.starts_at, 'previous_ends_at', v_s.ends_at,
                         'previous_position_id', v_s.position_id));
  end if;
end;
$$;

-- L1: the person is checked against the organization before its lock.
create or replace function public.assign_shift(p_shift_id uuid, p_person_id uuid, p_override boolean default false)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_s public.shifts%rowtype := private.lock_shift_for_scheduler(p_shift_id, 'edit');
  v_ov text[] := '{}';
  v_after public.shifts%rowtype;
begin
  perform private.enforce_write_limit('shift_edit');
  if v_s.status <> 'scheduled' then
    raise exception 'a cancelled shift cannot be assigned' using errcode = 'invalid_parameter_value';
  end if;
  if v_s.assigned_person_id is not distinct from p_person_id then
    raise exception 'nothing to change' using errcode = 'invalid_parameter_value';
  end if;
  if p_person_id is not null then
    perform private.precheck_assignee(v_s.organization_id, v_s.location_id, p_person_id);
    perform private.lock_staffing_people(array[p_person_id]);
    v_ov := private.require_assignable(v_s.organization_id, v_s.location_id, v_s.position_id, v_s.starts_at, v_s.ends_at,
                                       p_person_id, array[v_s.id], p_override);
  end if;
  v_after := private.write_shift_assignee(v_s.id, p_person_id, v_ov);
  perform private.after_assignee_change(v_s, v_after, 'manager');
end;
$$;

-- Signature change: the result gains item_id, and items that make no shift get a
-- row too (shift_id null).
drop function public.apply_shift_template(uuid, uuid, integer);

-- Stamp a template into a DRAFT schedule of the same location (G3): item
-- day_offset d lands on local date week_start + p_first_day + d, where week_start
-- is the schedule's week_start (the organization's first day of the week). A week
-- template (7 days) takes p_first_day 0 only (the default); a day template takes
-- 0-6. Wall times are in the location's time zone.
-- One row per item, in item order:
--   shift_id set, refused null           the shift was made (assigned if the default
--                                         assignee passed every rule)
--   shift_id set, refused = a rule       made as an open shift; the rule that failed
--                                         (not_member | overlap | time_off | qualification)
--   shift_id null, refused = 'time_change'           not made: across a clock change
--                                                     the item would last over 24 hours
--   shift_id null, refused = 'position_unavailable'   not made: its position is archived
--                                                     or not at this location
-- M4: shift_edit is charged once per shift made (at least once per call); the
-- schedule cap of 2,000 scheduled shifts applies (all or nothing).
create function public.apply_shift_template(p_schedule_id uuid, p_template_id uuid, p_first_day integer default 0)
returns table (shift_id uuid, assigned_person_id uuid, refused text, item_id uuid)
language plpgsql
volatile
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_sc public.schedules%rowtype;
  v_t public.shift_templates%rowtype;
  v_i public.shift_template_items%rowtype;
  v_tz text;
  v_local timestamp;
  v_start timestamptz;
  v_end timestamptz;
  v_problems text[];
  v_s public.shifts%rowtype;
  v_people uuid[];
  v_count integer;
  v_made integer := 0;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_sc from public.schedules sc where sc.id = p_schedule_id;
  if not found or public.has_permission(v_sc.organization_id, v_sc.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.shift_templates t where t.id = p_template_id;
  if not found or v_t.organization_id <> v_sc.organization_id
     or public.has_permission(v_t.organization_id, v_t.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_edit');
  if v_t.location_id <> v_sc.location_id then
    raise exception 'that template belongs to another location' using errcode = 'invalid_parameter_value';
  end if;
  if v_t.archived_at is not null then
    raise exception 'that template is archived' using errcode = 'invalid_parameter_value';
  end if;
  if p_first_day is null or p_first_day < 0 or p_first_day + v_t.span_days > 7 then
    raise exception 'that day is outside the week' using errcode = 'invalid_parameter_value';
  end if;
  select * into v_sc from public.schedules sc where sc.id = p_schedule_id for update;
  if v_sc.status <> 'draft' then
    raise exception 'a template can only be added to a draft schedule' using errcode = 'invalid_parameter_value';
  end if;
  v_count := private.lock_schedule_shift_count(v_sc.id, 0);
  select l.timezone into v_tz from public.locations l where l.id = v_sc.location_id;
  select coalesce(array_agg(distinct i.assigned_person_id), '{}') into v_people
  from public.shift_template_items i where i.template_id = v_t.id and i.assigned_person_id is not null;
  perform private.lock_staffing_people(v_people);

  for v_i in
    select i.* from public.shift_template_items i
    where i.template_id = v_t.id and i.organization_id = v_t.organization_id
    order by i.day_offset, i.start_time, i.id
  loop
    shift_id := null;
    assigned_person_id := null;
    refused := null;
    item_id := v_i.id;
    if not exists (select 1 from public.positions p
                   where p.id = v_i.position_id and p.organization_id = v_i.organization_id and p.archived_at is null
                     and (p.location_id is null or p.location_id = v_sc.location_id)) then
      refused := 'position_unavailable';
      return next;
      continue;
    end if;
    v_local := (v_sc.week_start + p_first_day + v_i.day_offset)::timestamp + v_i.start_time;
    v_start := v_local at time zone v_tz;
    v_end := (v_local + make_interval(mins => v_i.duration_minutes)) at time zone v_tz;
    if v_end - v_start > interval '24 hours' or v_end <= v_start then
      refused := 'time_change';
      return next;
      continue;
    end if;
    if v_count + 1 > private.max_shifts_per_schedule() then
      raise exception 'a schedule holds at most 2000 shifts' using errcode = 'check_violation', detail = 'too_many_shifts';
    end if;
    if v_made > 0 then
      perform private.enforce_write_limit('shift_edit');   -- the call itself paid for the first one
    end if;
    insert into public.shifts (organization_id, location_id, schedule_id, position_id, starts_at, ends_at, notes,
                               created_by_person_id)
    values (v_sc.organization_id, v_sc.location_id, v_sc.id, v_i.position_id, v_start, v_end, v_i.notes,
            public.current_person_id(v_sc.organization_id))
    returning * into v_s;
    v_count := v_count + 1;
    v_made := v_made + 1;
    v_problems := '{}';
    if v_i.assigned_person_id is not null then
      v_problems := private.shift_assignment_problems(v_sc.organization_id, v_sc.location_id, v_i.position_id,
                                                      v_start, v_end, v_i.assigned_person_id, array[v_s.id], true);
      if cardinality(v_problems) = 0 then
        v_s := private.write_shift_assignee(v_s.id, v_i.assigned_person_id, '{}');
      end if;
    end if;
    shift_id := v_s.id;
    assigned_person_id := v_s.assigned_person_id;
    refused := v_problems[1];
    return next;
  end loop;
end;
$$;

-- ===========================================================================
-- Exchange: L3 (auto-approval only without a counter shift), M5 (cancel RPCs)
-- ===========================================================================
create or replace function public.respond_shift_swap(p_swap_id uuid, p_accept boolean)
returns text
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_w public.shift_swaps%rowtype;
  v_x public.shifts%rowtype;
  v_me uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_w from public.shift_swaps w where w.id = p_swap_id;
  v_me := case when found then public.current_person_id(v_w.organization_id) end;
  if v_me is null or v_w.kind <> 'swap' or v_w.to_person_id is distinct from v_me
     or public.has_permission(v_w.organization_id, v_w.location_id, 'shift_swaps', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_exchange');
  if p_accept is null then
    raise exception 'accept or decline' using errcode = 'invalid_parameter_value';
  end if;
  v_w := private.lock_swap_and_shifts(v_w.id);
  if v_w.status <> 'requested' then
    raise exception 'this swap is no longer open' using errcode = 'invalid_parameter_value';
  end if;
  if not p_accept then
    update public.shift_swaps w set status = 'denied', decided_at = now(), decided_by_person_id = v_me
    where w.id = v_w.id returning * into v_w;
    perform private.emit_swap_event('shift_swap.denied', v_w);
    return v_w.status;
  end if;
  select * into v_x from public.shifts s where s.id = v_w.shift_id;
  if v_x.assigned_person_id is distinct from v_w.from_person_id or private.shift_is_exchangeable(v_x) is not true then
    raise exception 'the shift changed since the swap was offered' using errcode = 'check_violation', detail = 'stale';
  end if;
  perform private.lock_staffing_people(array[v_w.from_person_id, v_w.to_person_id]);
  perform private.require_assignable(v_x.organization_id, v_x.location_id, v_x.position_id, v_x.starts_at, v_x.ends_at,
                                     v_me, array_remove(array[v_x.id, v_w.counter_shift_id], null), false, false);
  update public.shift_swaps w set status = 'accepted', accepted_at = now() where w.id = v_w.id returning * into v_w;
  perform private.emit_swap_event('shift_swap.accepted', v_w);
  -- L3: with a counter shift, the outcome would tell B whether A can work Y.
  if v_w.counter_shift_id is null
     and private.staffing_setting(v_w.organization_id, 'auto_approve_swaps')
     and private.execute_swap(v_w, false, true, true) then
    return 'approved';
  end if;
  return v_w.status;
end;
$$;

create or replace function public.cancel_shift_swap(p_swap_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_w public.shift_swaps%rowtype;
  v_me uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_w from public.shift_swaps w where w.id = p_swap_id;
  v_me := case when found then public.current_person_id(v_w.organization_id) end;
  if v_me is null or v_me not in (select private.my_person_ids())
     or v_me not in (v_w.from_person_id, coalesce(v_w.to_person_id, v_w.from_person_id)) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_exchange');
  v_w := private.lock_swap_and_shifts(v_w.id);
  if v_w.status not in ('requested', 'accepted') then
    raise exception 'this request is already closed' using errcode = 'invalid_parameter_value';
  end if;
  update public.shift_swaps w set status = 'cancelled', decided_at = now(), decided_by_person_id = v_me
  where w.id = v_w.id returning * into v_w;
  perform private.emit_swap_event('shift_swap.cancelled', v_w);
end;
$$;

create or replace function public.cancel_shift_claim(p_claim_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_c public.shift_claims%rowtype;
  v_me uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_c from public.shift_claims c where c.id = p_claim_id;
  v_me := case when found then public.current_person_id(v_c.organization_id) end;
  if v_me is null or v_me not in (select private.my_person_ids()) or v_c.person_id <> v_me then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_exchange');
  perform 1 from public.shifts s where s.id = v_c.shift_id for update;
  select * into v_c from public.shift_claims c where c.id = p_claim_id for update;
  if v_c.status <> 'requested' then
    raise exception 'this request is already closed' using errcode = 'invalid_parameter_value';
  end if;
  update public.shift_claims c set status = 'cancelled', decided_at = now(), decided_by_person_id = v_me
  where c.id = v_c.id returning * into v_c;
  perform private.emit_claim_event('shift_claim.cancelled', v_c);
end;
$$;

create or replace function public.cancel_time_off(p_time_off_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.time_off_requests%rowtype;
  v_prev text;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.time_off_requests t where t.id = p_time_off_id;
  if not found or v_t.person_id is distinct from public.current_person_id(v_t.organization_id)
     or v_t.person_id not in (select private.my_person_ids()) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('time_off_request');
  perform private.lock_staffing_people(array[v_t.person_id]);
  select * into v_t from public.time_off_requests t where t.id = p_time_off_id for update;
  if v_t.status not in ('pending', 'approved') or (v_t.status = 'approved' and v_t.ends_on < current_date) then
    raise exception 'this request can no longer be cancelled' using errcode = 'invalid_parameter_value';
  end if;
  v_prev := v_t.status;
  update public.time_off_requests t set status = 'cancelled', cancelled_at = now()
  where t.id = v_t.id returning * into v_t;
  perform private.emit_event(
    v_t.organization_id, null, 'time_off.cancelled', 'time_off_requests', v_t.id,
    jsonb_build_object('time_off_id', v_t.id, 'person_id', v_t.person_id, 'starts_on', v_t.starts_on,
                       'ends_on', v_t.ends_on, 'status', v_t.status, 'previous_status', v_prev));
end;
$$;

-- ===========================================================================
-- G1: who the assignee of a shift may offer it to
-- ===========================================================================
-- Only the shift's current assignee (a member under the MFA rules) with
-- shift_swaps >= edit at its location, on a shift they can see (42501 otherwise).
-- Returns the people request_shift_swap would accept as the other person: active
-- members who can work at the location, have shift_swaps >= edit there and are
-- visible to the caller; the caller excluded. It never looks at time off,
-- qualifications or other shifts. display_name = preferred name (else first name)
-- and last name, the same people rows the caller can already read. At most 500.
create function public.swap_candidates(p_shift_id uuid)
returns table (person_id uuid, display_name text)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_s public.shifts%rowtype;
  v_me uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_s from public.shifts s where s.id = p_shift_id;
  v_me := case when found then public.current_person_id(v_s.organization_id) end;
  if v_me is null or v_me not in (select private.my_person_ids())
     or v_s.assigned_person_id is distinct from v_me
     or public.has_permission(v_s.organization_id, v_s.location_id, 'shift_swaps', 'edit') is not true
     or private.can_see_shift(v_s.organization_id, v_s.location_id, v_s.schedule_id, v_s.assigned_person_id, v_s.status) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  return query
  select p.id,
         btrim(coalesce(nullif(btrim(p.preferred_name), ''), p.first_name) || ' ' || p.last_name)
  from public.people p
  where p.organization_id = v_s.organization_id and p.id <> v_me
    and p.id in (select private.visible_person_ids())
    and not private.assignee_not_member(v_s.organization_id, v_s.location_id, p.id, true)
    and coalesce(private.person_effective_level(v_s.organization_id, p.id, v_s.location_id, 'shift_swaps') >= 'edit', false)
  order by 2, 1
  limit 500;
end;
$$;

-- ===========================================================================
-- L7: change the staffing switches only, atomically
-- ===========================================================================
-- Same guard as a direct settings update (organization_settings_update policy:
-- the admin role at organization scope, which includes the admin-tier MFA rule).
-- null = keep that switch. One UPDATE: no read-modify-write, other keys untouched.
create function public.set_staffing_switches(
  p_organization_id uuid, p_auto_approve_swaps boolean default null, p_first_come_open_shifts boolean default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_organization_id is null or public.has_role(p_organization_id, null, 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  update public.organization_settings s
  set settings = coalesce(s.settings, '{}'::jsonb)
                 || jsonb_build_object('staffing',
                      coalesce(s.settings -> 'staffing', '{}'::jsonb)
                      || jsonb_strip_nulls(jsonb_build_object('auto_approve_swaps', p_auto_approve_swaps,
                                                              'first_come_open_shifts', p_first_come_open_shifts)))
  where s.organization_id = p_organization_id;
end;
$$;

-- ===========================================================================
-- Grants for the new and recreated functions
-- ===========================================================================
revoke all on function
  public.position_shifts_missing_qualification(uuid),
  public.apply_shift_template(uuid, uuid, integer),
  public.shift_overrides(uuid),
  public.swap_candidates(uuid),
  public.set_staffing_switches(uuid, boolean, boolean)
from public, anon, authenticated;
grant execute on function
  public.position_shifts_missing_qualification(uuid),
  public.apply_shift_template(uuid, uuid, integer),
  public.shift_overrides(uuid),
  public.swap_candidates(uuid),
  public.set_staffing_switches(uuid, boolean, boolean)
to authenticated, service_role;
