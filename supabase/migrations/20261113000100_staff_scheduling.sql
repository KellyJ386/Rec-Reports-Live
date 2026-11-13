-- Phase 3: staff scheduling (domain `staffing`).
--
--   positions               what a shift is for ("Lifeguard"); organization-wide or one location
--   qualifications          what a person must hold ("Lifeguard cert"); organization-wide
--   position_qualifications which qualifications a position requires
--   person_qualifications   who holds which qualification, valid_from .. expires_on
--   schedules               one per location per week; draft -> published (the publish lock)
--   shifts                  the work: schedule, position, time, assignee (null = open shift)
--   shift_templates (+ shift_template_items)  a reusable week or day pattern
--   availability            a person's recurring weekly windows (available / unavailable / preferred)
--   time_off_requests       a person's date range off (pending -> approved / denied / cancelled)
--   shift_swaps             swap (A offers shift X to B, optionally for B's shift Y) or drop (A releases X)
--   shift_claims            a request to take an open shift
--
-- Modules (keys seeded in 20261111000200; seeded defaults staff / manager / admin):
--   staff_schedule        (view / admin / admin)
--     view   see published schedules and their shifts at the location; your own shifts
--     edit   also see drafts; create schedules, add / change / assign / cancel shifts,
--            stamp templates, publish; manage shift templates at the location
--     admin  also override time off and qualification rules when assigning (recorded
--            on the shift, audited); manage positions, qualifications and who holds them
--   shift_swaps           (edit / admin / admin)
--     edit   offer and accept swaps, request drops, claim open shifts (your own only)
--     admin  see every swap, drop and claim at the location; approve or deny them
--   availability_time_off (edit / admin / admin)
--     view   read your own availability and time off
--     edit   also change your availability and request / cancel your own time off
--     admin  read and decide availability and time off of the people in scope
--            (organization scope: everyone; a location: people assigned there)
--
-- Assignment rules (one implementation, private.shift_assignment_problems, used by
-- every path that puts a person on a shift: create, assign, change time, template
-- stamp, swap accept / approve, claim, claim approve):
--   not_member     the person is an active member covering the location with
--                  staff_schedule >= view (and visible to the caller on manager paths)
--   overlap        no other scheduled shift of the person anywhere in the organization
--                  overlaps (also an exclusion constraint)
--   time_off       no approved time off overlapping the shift (dates in the shift's
--                  location time zone)
--   qualification  every qualification the position requires is held and valid on the
--                  shift date (local date of the start)
-- A staff_schedule admin may override time_off and qualification with p_override;
-- the override is recorded on the shift (override_kinds / _by / _at) and audited.
-- not_member and overlap can never be overridden. Every path takes the shift row lock
-- and then a per-person advisory lock, so rule checks and the move are atomic with
-- respect to other assignments and time off approvals for the same person.
--
-- Writes: tenants have no INSERT / UPDATE / DELETE on any table here; every change
-- goes through the RPCs below. service_role has SELECT only.
-- Events: shift.* events are emitted only for shifts of a published schedule (a draft
-- is invisible to staff, so it must not notify them). Payloads carry ids and times,
-- never notes, reasons or names.

-- ===========================================================================
-- Settings and limits
-- ===========================================================================

-- Organization settings live in organization_settings: week_starts_on (column,
-- 0 = Sunday) and settings -> 'staffing' (object):
--   auto_approve_swaps      boolean, default false: an accepted swap is approved at once
--                           when every rule passes (otherwise it waits for a manager)
--   first_come_open_shifts  boolean, default false: a valid claim of an open shift is
--                           approved at once (first come, first served)
alter table public.organization_settings
  add constraint organization_settings_staffing_valid check (
    not (settings ? 'staffing')
    or (jsonb_typeof(settings -> 'staffing') = 'object'
        and (not ((settings -> 'staffing') ? 'auto_approve_swaps')
             or jsonb_typeof(settings -> 'staffing' -> 'auto_approve_swaps') = 'boolean')
        and (not ((settings -> 'staffing') ? 'first_come_open_shifts')
             or jsonb_typeof(settings -> 'staffing' -> 'first_come_open_shifts') = 'boolean')));

create function private.staffing_setting(p_organization_id uuid, p_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((select (s.settings -> 'staffing' ->> p_key)::boolean
                   from public.organization_settings s
                   where s.organization_id = p_organization_id
                     and jsonb_typeof(s.settings -> 'staffing' -> p_key) = 'boolean'), false)
$$;
revoke all on function private.staffing_setting(uuid, text) from public, anon, authenticated;

-- Same signature as 000600, every earlier row kept, staffing rows added.
create or replace function private.write_limits()
returns table (action text, max_hits integer, window_seconds integer)
language sql
immutable
set search_path = ''
as $$
  values
    ('task_create',     60,   600),   -- create_task: 60 per 10 minutes
    ('task_comment',    60,   600),   -- add_task_comment: 60 per 10 minutes
    ('task_transition', 120,  600),   -- start/complete/reopen/assign/cancel: 120 per 10 minutes
    ('message_send',    30,   600),   -- send_message: 30 per 10 minutes
    ('notice_publish',  20,   3600),  -- publish_notice: 20 per hour
    ('notice_critical', 5,    86400), -- publish_notice of a critical notice: 5 per day (on top of the above)
    ('push_save',       10,   3600),  -- save_push_subscription: 10 per hour
    -- Phase 3 (20261113000100)
    ('staffing_config', 120,  600),   -- positions, qualifications, person qualifications, templates: 120 per 10 minutes
    ('shift_edit',      300,  600),   -- create_schedule/create/update/assign/cancel shift, apply template: 300 per 10 minutes
    ('schedule_publish', 20,  3600),  -- publish_schedule: 20 per hour
    ('shift_exchange',  30,   600),   -- request/respond/cancel swap, drop, claim: 30 per 10 minutes
    ('shift_decide',    120,  600),   -- decide_shift_swap, decide_shift_claim: 120 per 10 minutes
    ('availability_edit', 60, 600),   -- add/remove availability: 60 per 10 minutes
    ('time_off_request', 20,  3600),  -- request_time_off, cancel_time_off: 20 per hour
    ('time_off_decide', 120,  600)    -- decide_time_off: 120 per 10 minutes
$$;

-- ===========================================================================
-- Tables
-- ===========================================================================

-- positions -----------------------------------------------------------------
create table public.positions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid,   -- null = usable at every location of the organization
  name text not null check (char_length(btrim(name)) between 1 and 100),
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id)
);
create unique index positions_active_name_key on public.positions (organization_id, location_id, lower(name)) nulls not distinct
  where archived_at is null;
create index positions_location_idx on public.positions (location_id, organization_id) where location_id is not null;

-- qualifications --------------------------------------------------------------
create table public.qualifications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 100),
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id)
);
create unique index qualifications_active_name_key on public.qualifications (organization_id, lower(name))
  where archived_at is null;

-- position_qualifications -----------------------------------------------------
create table public.position_qualifications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  position_id uuid not null,
  qualification_id uuid not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (position_id, qualification_id),
  foreign key (position_id, organization_id) references public.positions (id, organization_id) on delete cascade,
  foreign key (qualification_id, organization_id) references public.qualifications (id, organization_id)
);
create index position_qualifications_position_idx on public.position_qualifications (organization_id, position_id);
create index position_qualifications_qualification_idx on public.position_qualifications (qualification_id, organization_id);

-- person_qualifications -------------------------------------------------------
create table public.person_qualifications (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  qualification_id uuid not null,
  valid_from date,       -- null = valid from any date
  expires_on date,       -- last valid day; null = does not expire
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (person_id, qualification_id),
  check (expires_on is null or valid_from is null or expires_on >= valid_from),
  foreign key (person_id, organization_id) references public.people (id, organization_id),
  foreign key (qualification_id, organization_id) references public.qualifications (id, organization_id)
);
create index person_qualifications_person_idx on public.person_qualifications (organization_id, person_id);
create index person_qualifications_qualification_idx on public.person_qualifications (qualification_id, organization_id);

-- schedules -------------------------------------------------------------------
create table public.schedules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  week_start date not null,   -- first day of the week, in the location's time zone
  status text not null default 'draft' check (status in ('draft', 'published')),
  published_at timestamptz,
  published_by_person_id uuid,
  created_by_person_id uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  unique (id, organization_id, location_id),
  unique (location_id, week_start),
  check ((status = 'published') = (published_at is not null)),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (published_by_person_id, organization_id) references public.people (id, organization_id),
  foreign key (created_by_person_id, organization_id) references public.people (id, organization_id),
  -- Weeks of one location never overlap (a change of week_starts_on cannot make two
  -- schedules cover the same day). organization_id first: see space_hours_no_overlap.
  constraint schedules_no_overlap exclude using gist (
    organization_id with =,
    location_id with =,
    daterange(week_start, week_start + 7, '[)') with &&)
);
create index schedules_org_location_idx on public.schedules (organization_id, location_id, week_start);
create index schedules_published_by_idx on public.schedules (published_by_person_id, organization_id)
  where published_by_person_id is not null;
create index schedules_created_by_idx on public.schedules (created_by_person_id, organization_id)
  where created_by_person_id is not null;

-- shifts ----------------------------------------------------------------------
create table public.shifts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  schedule_id uuid not null,
  position_id uuid not null,
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  assigned_person_id uuid,            -- null = open shift
  status text not null default 'scheduled' check (status in ('scheduled', 'cancelled')),
  notes text check (char_length(notes) <= 1000),
  created_by_person_id uuid,
  cancelled_at timestamptz,
  -- An admin override of the time off / qualification rule for the current assignee.
  override_kinds text[],
  override_by_person_id uuid,
  override_at timestamptz,
  -- starts_at for which shift.uncovered was emitted (sweep idempotency).
  uncovered_emitted_for timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  unique (id, organization_id, location_id),
  check (ends_at > starts_at),
  check (ends_at - starts_at <= interval '24 hours'),
  check ((status = 'cancelled') = (cancelled_at is not null)),
  check (override_kinds is null
         or (cardinality(override_kinds) between 1 and 2
             and override_kinds <@ array['time_off', 'qualification']::text[]
             and assigned_person_id is not null)),
  check ((override_kinds is null) = (override_at is null)),
  check (override_by_person_id is null or override_kinds is not null),
  foreign key (schedule_id, organization_id, location_id)
    references public.schedules (id, organization_id, location_id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (position_id, organization_id) references public.positions (id, organization_id),
  foreign key (assigned_person_id, organization_id) references public.people (id, organization_id),
  foreign key (created_by_person_id, organization_id) references public.people (id, organization_id),
  foreign key (override_by_person_id, organization_id) references public.people (id, organization_id),
  -- One person never holds two overlapping scheduled shifts anywhere in the
  -- organization. Built-in tstzrange only (no custom range type). organization_id
  -- first so the DETAIL can only print a row of the caller's own tenant; the RPCs
  -- check first and turn a race-time violation into a plain 23514.
  constraint shifts_no_overlap exclude using gist (
    organization_id with =,
    assigned_person_id with =,
    tstzrange(starts_at, ends_at, '[)') with &&)
    where (assigned_person_id is not null and status = 'scheduled')
);
create index shifts_schedule_idx on public.shifts (schedule_id, organization_id, location_id);
create index shifts_location_idx on public.shifts (location_id, organization_id);
create index shifts_org_location_time_idx on public.shifts (organization_id, location_id, starts_at);
create index shifts_position_idx on public.shifts (position_id, organization_id);
create index shifts_assigned_idx on public.shifts (assigned_person_id, organization_id, starts_at)
  where assigned_person_id is not null;
create index shifts_created_by_idx on public.shifts (created_by_person_id, organization_id) where created_by_person_id is not null;
create index shifts_override_by_idx on public.shifts (override_by_person_id, organization_id) where override_by_person_id is not null;
create index shifts_open_idx on public.shifts (starts_at) where assigned_person_id is null and status = 'scheduled';

-- shift_templates / shift_template_items ----------------------------------------
create table public.shift_templates (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  name text not null check (char_length(btrim(name)) between 1 and 100),
  span_days smallint not null default 7 check (span_days in (1, 7)),   -- 7 = a week pattern, 1 = a day pattern
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  unique (id, organization_id, location_id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id)
);
create index shift_templates_location_idx on public.shift_templates (organization_id, location_id);

create table public.shift_template_items (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  template_id uuid not null,
  position_id uuid not null,
  day_offset smallint not null check (day_offset between 0 and 6),   -- days after the first day
  start_time time not null,                                         -- local wall time
  duration_minutes integer not null check (duration_minutes between 15 and 1440),
  assigned_person_id uuid,                                          -- default assignee (null = open)
  notes text check (char_length(notes) <= 1000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (template_id, organization_id, location_id)
    references public.shift_templates (id, organization_id, location_id) on delete cascade,
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (position_id, organization_id) references public.positions (id, organization_id),
  foreign key (assigned_person_id, organization_id) references public.people (id, organization_id)
);
create index shift_template_items_template_idx on public.shift_template_items (organization_id, template_id, location_id);
create index shift_template_items_location_idx on public.shift_template_items (location_id, organization_id);
create index shift_template_items_position_idx on public.shift_template_items (position_id, organization_id);
create index shift_template_items_person_idx on public.shift_template_items (assigned_person_id, organization_id)
  where assigned_person_id is not null;

-- availability ------------------------------------------------------------------
create table public.availability (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  day_of_week smallint not null check (day_of_week between 1 and 7),   -- ISO: 1 = Monday
  start_time time not null,
  end_time time not null,          -- '24:00' allowed; overnight = two rows
  kind text not null check (kind in ('available', 'unavailable', 'preferred')),
  effective_from date,
  effective_to date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (end_time > start_time),
  check (effective_to is null or effective_from is null or effective_to >= effective_from),
  foreign key (person_id, organization_id) references public.people (id, organization_id)
);
create index availability_person_idx on public.availability (organization_id, person_id, day_of_week);

-- time_off_requests -------------------------------------------------------------
create table public.time_off_requests (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  starts_on date not null,
  ends_on date not null,            -- inclusive
  reason text check (char_length(reason) <= 500),
  status text not null default 'pending' check (status in ('pending', 'approved', 'denied', 'cancelled')),
  decided_by_person_id uuid,
  decided_at timestamptz,
  cancelled_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (ends_on >= starts_on and ends_on - starts_on <= 365),
  check (status <> 'pending' or (decided_at is null and decided_by_person_id is null)),
  check (status not in ('approved', 'denied') or decided_at is not null),
  check ((status = 'cancelled') = (cancelled_at is not null)),
  foreign key (person_id, organization_id) references public.people (id, organization_id),
  foreign key (decided_by_person_id, organization_id) references public.people (id, organization_id)
);
create index time_off_requests_person_idx on public.time_off_requests (person_id, organization_id, starts_on);
create index time_off_requests_decided_by_idx on public.time_off_requests (decided_by_person_id, organization_id)
  where decided_by_person_id is not null;
create index time_off_requests_pending_idx on public.time_off_requests (organization_id, status) where status = 'pending';

-- shift_swaps -------------------------------------------------------------------
create table public.shift_swaps (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  kind text not null check (kind in ('swap', 'drop')),
  shift_id uuid not null,               -- X, held by from_person when requested
  counter_shift_id uuid,                -- Y, held by to_person (swap only, optional)
  from_person_id uuid not null,         -- A
  to_person_id uuid,                    -- B (swap only)
  note text check (char_length(note) <= 500),
  status text not null default 'requested'
    check (status in ('requested', 'accepted', 'approved', 'denied', 'cancelled')),
  accepted_at timestamptz,
  decided_by_person_id uuid,            -- null on a decision = the system (auto-approval, or closed because the shift changed)
  decided_at timestamptz,
  auto_approved boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((kind = 'swap') = (to_person_id is not null)),
  check (kind = 'swap' or counter_shift_id is null),
  check (to_person_id is null or to_person_id <> from_person_id),
  check (counter_shift_id is null or counter_shift_id <> shift_id),
  check ((decided_at is not null) = (status in ('approved', 'denied', 'cancelled'))),
  check (kind = 'swap' or accepted_at is null),
  check (status <> 'accepted' or accepted_at is not null),
  foreign key (shift_id, organization_id, location_id) references public.shifts (id, organization_id, location_id),
  foreign key (counter_shift_id, organization_id, location_id) references public.shifts (id, organization_id, location_id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (from_person_id, organization_id) references public.people (id, organization_id),
  foreign key (to_person_id, organization_id) references public.people (id, organization_id),
  foreign key (decided_by_person_id, organization_id) references public.people (id, organization_id)
);
-- At most one open swap or drop per shift.
create unique index shift_swaps_one_open_key on public.shift_swaps (shift_id) where status in ('requested', 'accepted');
create index shift_swaps_shift_idx on public.shift_swaps (organization_id, shift_id, location_id);
create index shift_swaps_counter_idx on public.shift_swaps (counter_shift_id, organization_id, location_id)
  where counter_shift_id is not null;
create index shift_swaps_location_idx on public.shift_swaps (location_id, organization_id, status);
create index shift_swaps_from_idx on public.shift_swaps (from_person_id, organization_id);
create index shift_swaps_to_idx on public.shift_swaps (to_person_id, organization_id) where to_person_id is not null;
create index shift_swaps_decided_by_idx on public.shift_swaps (decided_by_person_id, organization_id)
  where decided_by_person_id is not null;

-- shift_claims ------------------------------------------------------------------
create table public.shift_claims (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  shift_id uuid not null,
  person_id uuid not null,
  status text not null default 'requested' check (status in ('requested', 'approved', 'denied', 'cancelled')),
  decided_by_person_id uuid,           -- null on a decision = the system
  decided_at timestamptz,
  auto_approved boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check ((decided_at is not null) = (status <> 'requested')),
  foreign key (shift_id, organization_id, location_id) references public.shifts (id, organization_id, location_id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (person_id, organization_id) references public.people (id, organization_id),
  foreign key (decided_by_person_id, organization_id) references public.people (id, organization_id)
);
create unique index shift_claims_one_open_key on public.shift_claims (shift_id, person_id) where status = 'requested';
create index shift_claims_shift_idx on public.shift_claims (organization_id, shift_id, location_id);
create index shift_claims_location_idx on public.shift_claims (location_id, organization_id, status);
create index shift_claims_person_idx on public.shift_claims (person_id, organization_id);
create index shift_claims_decided_by_idx on public.shift_claims (decided_by_person_id, organization_id)
  where decided_by_person_id is not null;

-- No timestamp or date column accepts +/-infinity (000600 rule): one finite_<column>
-- CHECK per column of the tables above.
do $$
declare
  r record;
begin
  for r in
    select c.relname, a.attname
    from pg_catalog.pg_attribute a
    join pg_catalog.pg_class c on c.oid = a.attrelid
    where c.relnamespace = 'public'::regnamespace and c.relkind in ('r', 'p')
      and c.relname in ('positions', 'qualifications', 'position_qualifications', 'person_qualifications',
                        'schedules', 'shifts', 'shift_templates', 'shift_template_items', 'availability',
                        'time_off_requests', 'shift_swaps', 'shift_claims')
      and a.attnum > 0 and not a.attisdropped
      and a.atttypid in ('timestamptz'::regtype, 'timestamp'::regtype, 'date'::regtype)
    order by c.relname, a.attnum
  loop
    execute format('alter table public.%I add constraint %I check (%I is null or isfinite(%I))',
                   r.relname, left('finite_' || r.attname, 63), r.attname, r.attname);
  end loop;
end;
$$;

-- ===========================================================================
-- Triggers: timestamps, immutable columns, structure
-- ===========================================================================
create trigger positions_timestamps before insert or update on public.positions
  for each row execute function private.tg_set_timestamps();
create trigger positions_immutable before update on public.positions
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id');
create trigger qualifications_timestamps before insert or update on public.qualifications
  for each row execute function private.tg_set_timestamps();
create trigger qualifications_immutable before update on public.qualifications
  for each row execute function private.tg_immutable_columns('id', 'organization_id');
create trigger position_qualifications_timestamps before insert or update on public.position_qualifications
  for each row execute function private.tg_set_timestamps();
create trigger position_qualifications_immutable before update on public.position_qualifications
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'position_id', 'qualification_id');
create trigger person_qualifications_timestamps before insert or update on public.person_qualifications
  for each row execute function private.tg_set_timestamps();
create trigger person_qualifications_immutable before update on public.person_qualifications
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id', 'qualification_id');
create trigger schedules_timestamps before insert or update on public.schedules
  for each row execute function private.tg_set_timestamps();
create trigger schedules_immutable before update on public.schedules
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'week_start',
                                                            'created_by_person_id');
create trigger shifts_timestamps before insert or update on public.shifts
  for each row execute function private.tg_set_timestamps();
create trigger shifts_immutable before update on public.shifts
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'schedule_id',
                                                            'created_by_person_id');
create trigger shift_templates_timestamps before insert or update on public.shift_templates
  for each row execute function private.tg_set_timestamps();
create trigger shift_templates_immutable before update on public.shift_templates
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'span_days');
create trigger shift_template_items_timestamps before insert or update on public.shift_template_items
  for each row execute function private.tg_set_timestamps();
create trigger shift_template_items_immutable before update on public.shift_template_items
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'template_id');
create trigger availability_timestamps before insert or update on public.availability
  for each row execute function private.tg_set_timestamps();
create trigger availability_immutable before update on public.availability
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id');
create trigger time_off_requests_timestamps before insert or update on public.time_off_requests
  for each row execute function private.tg_set_timestamps();
create trigger time_off_requests_immutable before update on public.time_off_requests
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id', 'starts_on',
                                                            'ends_on', 'reason');
create trigger shift_swaps_timestamps before insert or update on public.shift_swaps
  for each row execute function private.tg_set_timestamps();
create trigger shift_swaps_immutable before update on public.shift_swaps
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'kind', 'shift_id',
                                                            'counter_shift_id', 'from_person_id', 'to_person_id', 'note');
create trigger shift_claims_timestamps before insert or update on public.shift_claims
  for each row execute function private.tg_set_timestamps();
create trigger shift_claims_immutable before update on public.shift_claims
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'shift_id', 'person_id');

-- Structure of a shift (a backstop under the RPCs, which check the same first):
-- the shift starts during its schedule's week (local dates of the location), its
-- position is usable at the location, and a new or changed position is not archived.
-- Refuses a signed-in non-member first with the generic error.
create function private.tg_shifts_validate()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_week date;
  v_tz text;
  v_pos public.positions%rowtype;
begin
  perform private.assert_member_of(new.organization_id);
  select sc.week_start, l.timezone into v_week, v_tz
  from public.schedules sc
  join public.locations l on l.id = sc.location_id and l.organization_id = sc.organization_id
  where sc.id = new.schedule_id and sc.organization_id = new.organization_id and sc.location_id = new.location_id;
  if not found then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if (new.starts_at at time zone v_tz)::date not between v_week and v_week + 6 then
    raise exception 'the shift must start during the schedule week' using errcode = 'check_violation';
  end if;
  select * into v_pos from public.positions p where p.id = new.position_id and p.organization_id = new.organization_id;
  if not found or (v_pos.location_id is not null and v_pos.location_id <> new.location_id) then
    raise exception 'that position is not used at this location' using errcode = 'check_violation';
  end if;
  if v_pos.archived_at is not null and (tg_op = 'INSERT' or new.position_id is distinct from old.position_id) then
    raise exception 'that position is archived' using errcode = 'check_violation';
  end if;
  return new;
end;
$$;
revoke all on function private.tg_shifts_validate() from public, anon, authenticated;
create trigger shifts_validate before insert or update of schedule_id, position_id, starts_at, ends_at on public.shifts
  for each row execute function private.tg_shifts_validate();

-- Audit. Free text (names, notes, reasons) is redacted.
do $$
begin
  perform private.enable_audit('public.positions', 'id', array['name']);
  perform private.enable_audit('public.qualifications', 'id', array['name']);
  perform private.enable_audit('public.position_qualifications');
  perform private.enable_audit('public.person_qualifications');
  perform private.enable_audit('public.schedules');
  perform private.enable_audit('public.shifts', 'id', array['notes']);
  perform private.enable_audit('public.shift_templates', 'id', array['name']);
  perform private.enable_audit('public.shift_template_items', 'id', array['notes']);
  perform private.enable_audit('public.availability');
  perform private.enable_audit('public.time_off_requests', 'id', array['reason']);
  perform private.enable_audit('public.shift_swaps', 'id', array['note']);
  perform private.enable_audit('public.shift_claims');
end;
$$;

-- ===========================================================================
-- Access helpers (policies and RPCs)
-- ===========================================================================

-- Does the caller hold >= level on the module over this person: at organization
-- scope, or at a (non-archived) location where the person holds an assignment?
create function private.has_permission_over_person(
  p_organization_id uuid, p_person_id uuid, p_module_key text, p_min_level public.permission_level)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    public.has_permission(p_organization_id, null, p_module_key, p_min_level)
    or exists (
      select 1 from public.role_assignments ra
      join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
      where ra.person_id = p_person_id and ra.organization_id = p_organization_id
        and ra.location_id is not null and l.archived_at is null
        and public.has_permission(p_organization_id, ra.location_id, p_module_key, p_min_level)),
    false)
$$;

-- Schedules: staff_schedule >= edit at the location sees drafts too; >= view only published.
create function private.can_see_schedule(p_organization_id uuid, p_location_id uuid, p_status text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'edit')
    or (p_status = 'published' and public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'view')),
    false)
$$;

-- Shifts: edit at the location sees every shift there. Otherwise only shifts of a
-- published schedule: every non-cancelled one at a location where the caller has
-- staff_schedule >= view (co-workers and open shifts), plus the caller's own in any
-- status.
create function private.can_see_shift(
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
                 and p_assigned_person_id = public.current_person_id(p_organization_id)))),
    false)
$$;

revoke all on function
  private.has_permission_over_person(uuid, uuid, text, public.permission_level),
  private.can_see_schedule(uuid, uuid, text),
  private.can_see_shift(uuid, uuid, uuid, uuid, text)
from public, anon, authenticated;
grant execute on function
  private.has_permission_over_person(uuid, uuid, text, public.permission_level),
  private.can_see_schedule(uuid, uuid, text),
  private.can_see_shift(uuid, uuid, uuid, uuid, text)
to authenticated, service_role;

-- ===========================================================================
-- RLS, policies, grants
-- ===========================================================================
alter table public.positions enable row level security;
alter table public.qualifications enable row level security;
alter table public.position_qualifications enable row level security;
alter table public.person_qualifications enable row level security;
alter table public.schedules enable row level security;
alter table public.shifts enable row level security;
alter table public.shift_templates enable row level security;
alter table public.shift_template_items enable row level security;
alter table public.availability enable row level security;
alter table public.time_off_requests enable row level security;
alter table public.shift_swaps enable row level security;
alter table public.shift_claims enable row level security;

-- Positions and qualifications are configuration: any member with staff_schedule
-- >= view somewhere in the organization reads them.
create policy positions_select on public.positions for select to authenticated
  using (private.has_permission_anywhere(organization_id, 'staff_schedule', 'view'));
create policy qualifications_select on public.qualifications for select to authenticated
  using (private.has_permission_anywhere(organization_id, 'staff_schedule', 'view'));
create policy position_qualifications_select on public.position_qualifications for select to authenticated
  using (private.has_permission_anywhere(organization_id, 'staff_schedule', 'view'));
-- Who holds what: the person, and schedulers (staff_schedule >= edit) over that person.
create policy person_qualifications_select on public.person_qualifications for select to authenticated
  using (person_id in (select private.my_person_ids())
         or private.has_permission_over_person(organization_id, person_id, 'staff_schedule', 'edit'));
create policy schedules_select on public.schedules for select to authenticated
  using (private.can_see_schedule(organization_id, location_id, status));
create policy shifts_select on public.shifts for select to authenticated
  using (private.can_see_shift(organization_id, location_id, schedule_id, assigned_person_id, status));
create policy shift_templates_select on public.shift_templates for select to authenticated
  using (public.has_permission(organization_id, location_id, 'staff_schedule', 'edit'));
create policy shift_template_items_select on public.shift_template_items for select to authenticated
  using (public.has_permission(organization_id, location_id, 'staff_schedule', 'edit'));
-- Availability and time off (including the reason): the person, and
-- availability_time_off admins over that person. Nobody else.
create policy availability_select on public.availability for select to authenticated
  using (person_id in (select private.my_person_ids())
         or private.has_permission_over_person(organization_id, person_id, 'availability_time_off', 'admin'));
create policy time_off_requests_select on public.time_off_requests for select to authenticated
  using (person_id in (select private.my_person_ids())
         or private.has_permission_over_person(organization_id, person_id, 'availability_time_off', 'admin'));
-- Swaps / drops: the two parties, and shift_swaps admins at the location.
create policy shift_swaps_select on public.shift_swaps for select to authenticated
  using (from_person_id in (select private.my_person_ids())
         or to_person_id in (select private.my_person_ids())
         or public.has_permission(organization_id, location_id, 'shift_swaps', 'admin'));
create policy shift_claims_select on public.shift_claims for select to authenticated
  using (person_id in (select private.my_person_ids())
         or public.has_permission(organization_id, location_id, 'shift_swaps', 'admin'));

revoke all on table public.positions, public.qualifications, public.position_qualifications,
  public.person_qualifications, public.schedules, public.shifts, public.shift_templates,
  public.shift_template_items, public.availability, public.time_off_requests, public.shift_swaps,
  public.shift_claims
from public, anon, authenticated, service_role;
-- Reads only. Every write is an RPC below (tenants and service_role alike).
grant select on table public.positions, public.qualifications, public.position_qualifications,
  public.person_qualifications, public.schedules, public.shifts, public.shift_templates,
  public.shift_template_items, public.availability, public.time_off_requests, public.shift_swaps,
  public.shift_claims
to authenticated, service_role;

-- ===========================================================================
-- Internal building blocks (not granted to anyone; called by the definer RPCs)
-- ===========================================================================

-- Per-person advisory locks, in id order (callers always lock shift rows first).
create function private.lock_staffing_people(p_people uuid[])
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v uuid;
begin
  for v in select distinct x from unnest(p_people) x where x is not null order by 1 loop
    perform pg_advisory_xact_lock(hashtextextended('staffing:person:' || v::text, 0));
  end loop;
end;
$$;

-- THE assignment rules. Returns every rule the assignment would break, in order
-- not_member, overlap, time_off, qualification (empty = allowed). p_ignore: shifts
-- that do not count for overlap (the shift itself, a shift being swapped away).
-- p_check_visibility: also require that a signed-in caller can see the person
-- (manager paths; a person acting for themselves passes trivially).
create function private.shift_assignment_problems(
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
  if not exists (select 1 from public.people p
                 where p.id = p_person_id and p.organization_id = p_organization_id and p.archived_at is null)
     or not private.person_is_active_member(p_organization_id, p_person_id)
     or coalesce(private.person_effective_level(p_organization_id, p_person_id, p_location_id, 'staff_schedule')
                 >= 'view', false) is not true
     or (p_check_visibility and (select auth.uid()) is not null and not public.is_platform_admin()
         and p_person_id not in (select private.visible_person_ids())) then
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

-- Raise for the first rule that blocks (23514, stable message, DETAIL = the rule);
-- with p_override, time_off and qualification do not block and are returned as the
-- overrides used (empty = none needed). p_override needs staff_schedule = admin at
-- the location (42501 otherwise).
create function private.require_assignable(
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
begin
  if coalesce(p_override, false) and (select auth.uid()) is not null
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

-- Emit a shift.* event (only called for shifts of a published schedule).
create function private.emit_shift_event(p_type text, p_s public.shifts, p_extra jsonb default '{}'::jsonb)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  return private.emit_event(
    p_s.organization_id, p_s.location_id, p_type, 'shifts', p_s.id,
    jsonb_build_object(
      'shift_id', p_s.id, 'schedule_id', p_s.schedule_id, 'location_id', p_s.location_id,
      'position_id', p_s.position_id, 'person_id', p_s.assigned_person_id,
      'starts_at', p_s.starts_at, 'ends_at', p_s.ends_at, 'anchor_at', p_s.starts_at,
      'actor_person_id', case when (select auth.uid()) is not null then public.current_person_id(p_s.organization_id) end)
    || coalesce(p_extra, '{}'::jsonb));
end;
$$;

create function private.emit_swap_event(p_type text, p_w public.shift_swaps)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  return private.emit_event(
    p_w.organization_id, p_w.location_id, p_type, 'shift_swaps', p_w.id,
    jsonb_build_object(
      'swap_id', p_w.id, 'kind', p_w.kind, 'shift_id', p_w.shift_id, 'counter_shift_id', p_w.counter_shift_id,
      'location_id', p_w.location_id, 'from_person_id', p_w.from_person_id, 'to_person_id', p_w.to_person_id,
      'status', p_w.status, 'auto_approved', p_w.auto_approved,
      'actor_person_id', case when (select auth.uid()) is not null then public.current_person_id(p_w.organization_id) end));
end;
$$;

create function private.emit_claim_event(p_type text, p_c public.shift_claims)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
begin
  return private.emit_event(
    p_c.organization_id, p_c.location_id, p_type, 'shift_claims', p_c.id,
    jsonb_build_object(
      'claim_id', p_c.id, 'shift_id', p_c.shift_id, 'location_id', p_c.location_id, 'person_id', p_c.person_id,
      'status', p_c.status, 'auto_approved', p_c.auto_approved,
      'actor_person_id', case when (select auth.uid()) is not null then public.current_person_id(p_c.organization_id) end));
end;
$$;

-- Close what can no longer happen because a shift changed hands or was cancelled:
-- open swaps / drops of it (as X or as Y) become cancelled; when p_close_claims, open
-- claims of it become denied. Decided by the system (decided_by null). Events go out
-- only for a published schedule (exchanges exist only there anyway).
create function private.close_shift_exchanges(p_shift_id uuid, p_organization_id uuid, p_close_claims boolean)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_w public.shift_swaps%rowtype;
  v_c public.shift_claims%rowtype;
begin
  for v_w in
    update public.shift_swaps w set status = 'cancelled', decided_at = now(), decided_by_person_id = null
    where w.organization_id = p_organization_id and (w.shift_id = p_shift_id or w.counter_shift_id = p_shift_id)
      and w.status in ('requested', 'accepted')
    returning w.*
  loop
    perform private.emit_swap_event('shift_swap.cancelled', v_w);
  end loop;
  if p_close_claims then
    for v_c in
      update public.shift_claims c set status = 'denied', decided_at = now(), decided_by_person_id = null
      where c.organization_id = p_organization_id and c.shift_id = p_shift_id and c.status = 'requested'
      returning c.*
    loop
      perform private.emit_claim_event('shift_claim.denied', v_c);
    end loop;
  end if;
end;
$$;

-- Write a new assignee on a LOCKED shift (rules already checked by the caller).
-- Records or clears the override. A race-time exclusion violation becomes 23514.
create function private.write_shift_assignee(p_shift_id uuid, p_person_id uuid, p_overrides text[])
returns public.shifts
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_s public.shifts%rowtype;
  v_ov boolean := p_person_id is not null and cardinality(coalesce(p_overrides, '{}')) > 0;
begin
  begin
    update public.shifts s
    set assigned_person_id = p_person_id,
        override_kinds = case when v_ov then p_overrides end,
        override_at = case when v_ov then now() end,
        override_by_person_id = case when v_ov and (select auth.uid()) is not null
                                     then public.current_person_id(s.organization_id) end
    where s.id = p_shift_id
    returning * into v_s;
  exception when exclusion_violation then
    raise exception 'that person already has a shift at that time' using errcode = 'check_violation', detail = 'overlap';
  end;
  return v_s;
end;
$$;

-- After an assignee change on one shift: close exchanges that no longer apply and,
-- on a published schedule, emit shift.assigned / shift.unassigned / shift.opened.
-- p_via: manager | swap | drop | claim.
create function private.after_assignee_change(p_old public.shifts, p_new public.shifts, p_via text)
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
    perform private.emit_shift_event('shift.opened', p_new, jsonb_build_object('via', p_via));
  end if;
end;
$$;

-- Read a shift for a caller who needs staff_schedule >= p_level at its location
-- (check first, then lock, then return the locked row). 42501 for missing / other
-- organization / not permitted, without saying which.
create function private.lock_shift_for_scheduler(p_shift_id uuid, p_level public.permission_level)
returns public.shifts
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_s public.shifts%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_s from public.shifts s where s.id = p_shift_id;
  if not found or public.has_permission(v_s.organization_id, v_s.location_id, 'staff_schedule', p_level) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  select * into v_s from public.shifts s where s.id = p_shift_id for update;
  -- Serialize with publish_schedule (FOR UPDATE on the schedule), so a change is
  -- either a draft change (no events) or a published change (events), never lost.
  perform 1 from public.schedules sc where sc.id = v_s.schedule_id for share;
  return v_s;
end;
$$;

-- Is this shift open to exchange now: scheduled, on a published schedule, not started?
create function private.shift_is_exchangeable(p_s public.shifts)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(p_s.status = 'scheduled' and p_s.starts_at > now()
    and exists (select 1 from public.schedules sc
                where sc.id = p_s.schedule_id and sc.organization_id = p_s.organization_id and sc.status = 'published'),
    false)
$$;

-- People with >= level on a module at a location (active members, not archived).
create function private.staffing_location_people(
  p_organization_id uuid, p_location_id uuid, p_module_key text, p_min_level public.permission_level)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.id from public.people p
  where p.organization_id = p_organization_id and p.archived_at is null
    and private.person_is_active_member(p_organization_id, p.id)
    and coalesce(private.person_effective_level(p_organization_id, p.id, p_location_id, p_module_key) >= p_min_level, false)
  order by p.id
$$;

-- People with availability_time_off = admin over a person (organization scope, or a
-- location where that person holds an assignment), the person excluded.
create function private.time_off_approvers(p_organization_id uuid, p_person_id uuid)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.id from public.people p
  where p.organization_id = p_organization_id and p.archived_at is null and p.id <> p_person_id
    and private.person_is_active_member(p_organization_id, p.id)
    and (coalesce(private.person_effective_level(p_organization_id, p.id, null, 'availability_time_off') = 'admin', false)
         or exists (select 1 from public.role_assignments ra
                    join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
                    where ra.person_id = p_person_id and ra.organization_id = p_organization_id
                      and ra.location_id is not null and l.archived_at is null
                      and coalesce(private.person_effective_level(p_organization_id, p.id, ra.location_id,
                                                                  'availability_time_off') = 'admin', false)))
  order by p.id
$$;

revoke all on function
  private.lock_staffing_people(uuid[]),
  private.shift_assignment_problems(uuid, uuid, uuid, timestamptz, timestamptz, uuid, uuid[], boolean),
  private.require_assignable(uuid, uuid, uuid, timestamptz, timestamptz, uuid, uuid[], boolean, boolean),
  private.emit_shift_event(text, public.shifts, jsonb),
  private.emit_swap_event(text, public.shift_swaps),
  private.emit_claim_event(text, public.shift_claims),
  private.close_shift_exchanges(uuid, uuid, boolean),
  private.write_shift_assignee(uuid, uuid, text[]),
  private.after_assignee_change(public.shifts, public.shifts, text),
  private.lock_shift_for_scheduler(uuid, public.permission_level),
  private.shift_is_exchangeable(public.shifts),
  private.staffing_location_people(uuid, uuid, text, public.permission_level),
  private.time_off_approvers(uuid, uuid)
from public, anon, authenticated;

-- ===========================================================================
-- Configuration RPCs: positions, qualifications, person qualifications
-- ===========================================================================

-- Create (p_position_id null) or rename a position, and optionally set the
-- qualifications it requires (p_qualification_ids null = leave as is, '{}' = none).
-- An organization-wide position (p_location_id null) needs staff_schedule = admin
-- at organization scope; a location position, admin at that location. The location
-- of an existing position cannot change.
create function public.save_position(
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

create function public.archive_position(p_position_id uuid, p_archived boolean default true)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_p public.positions%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_p from public.positions p where p.id = p_position_id;
  if not found or public.has_permission(v_p.organization_id, v_p.location_id, 'staff_schedule', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  begin
    update public.positions p
    set archived_at = case when coalesce(p_archived, true) then coalesce(p.archived_at, now()) end
    where p.id = v_p.id;
  exception when unique_violation then
    raise exception 'a position with that name already exists' using errcode = 'invalid_parameter_value';
  end;
end;
$$;

-- Qualifications are organization-wide; staff_schedule = admin at organization
-- scope or at any location of the organization manages them.
create function public.save_qualification(p_organization_id uuid, p_name text, p_qualification_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_organization_id is null
     or private.has_permission_anywhere(p_organization_id, 'staff_schedule', 'admin') is not true
     or (p_qualification_id is not null and not exists (
           select 1 from public.qualifications q where q.id = p_qualification_id and q.organization_id = p_organization_id)) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  if p_name is null or char_length(btrim(p_name)) not between 1 and 100 then
    raise exception 'a name needs 1 to 100 characters' using errcode = 'invalid_parameter_value';
  end if;
  begin
    if p_qualification_id is null then
      insert into public.qualifications (organization_id, name) values (p_organization_id, btrim(p_name))
      returning id into v_id;
    else
      update public.qualifications q set name = btrim(p_name)
      where q.id = p_qualification_id and q.name is distinct from btrim(p_name);
      v_id := p_qualification_id;
    end if;
  exception when unique_violation then
    raise exception 'a qualification with that name already exists' using errcode = 'invalid_parameter_value';
  end;
  return v_id;
end;
$$;

-- Archive (or restore) a qualification. One still required by a position that is
-- not archived cannot be archived (take it off those positions first).
create function public.archive_qualification(p_qualification_id uuid, p_archived boolean default true)
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

-- Record that a person holds a qualification (or renew it: same person and
-- qualification updates the dates). Needs staff_schedule = admin over the person
-- (organization scope, or a location where they hold an assignment); not yourself.
create function public.set_person_qualification(
  p_organization_id uuid, p_person_id uuid, p_qualification_id uuid,
  p_valid_from date default null, p_expires_on date default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_organization_id is null or p_person_id is null
     or not exists (select 1 from public.people p where p.id = p_person_id and p.organization_id = p_organization_id)
     or not (public.is_platform_admin() or p_person_id in (select private.visible_person_ids()))
     or private.has_permission_over_person(p_organization_id, p_person_id, 'staff_schedule', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if p_person_id in (select private.my_person_ids()) then
    raise exception 'you cannot change your own qualifications' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  if not exists (select 1 from public.qualifications q
                 where q.id = p_qualification_id and q.organization_id = p_organization_id and q.archived_at is null) then
    raise exception 'unknown qualification' using errcode = 'invalid_parameter_value';
  end if;
  if (p_valid_from is not null and not isfinite(p_valid_from)) or (p_expires_on is not null and not isfinite(p_expires_on))
     or (p_valid_from is not null and p_expires_on is not null and p_expires_on < p_valid_from) then
    raise exception 'invalid dates' using errcode = 'invalid_parameter_value';
  end if;
  perform private.lock_staffing_people(array[p_person_id]);
  insert into public.person_qualifications as x (organization_id, person_id, qualification_id, valid_from, expires_on)
  values (p_organization_id, p_person_id, p_qualification_id, p_valid_from, p_expires_on)
  on conflict (person_id, qualification_id) do update
    set valid_from = excluded.valid_from, expires_on = excluded.expires_on
  returning x.id into v_id;
  return v_id;
end;
$$;

create function public.remove_person_qualification(p_person_qualification_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_x public.person_qualifications%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_x from public.person_qualifications x where x.id = p_person_qualification_id;
  if not found
     or not (public.is_platform_admin() or v_x.person_id in (select private.visible_person_ids()))
     or private.has_permission_over_person(v_x.organization_id, v_x.person_id, 'staff_schedule', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if v_x.person_id in (select private.my_person_ids()) then
    raise exception 'you cannot change your own qualifications' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  perform private.lock_staffing_people(array[v_x.person_id]);
  delete from public.person_qualifications x where x.id = v_x.id;
end;
$$;

-- ===========================================================================
-- Templates
-- ===========================================================================

-- Create (p_template_id null) or rename a template. staff_schedule >= edit at the
-- location. p_span_days: 7 = a week pattern (day_offset 0-6 from the week start),
-- 1 = a day pattern (day_offset 0, stamped onto a chosen day). Fixed at creation.
create function public.save_shift_template(
  p_organization_id uuid, p_location_id uuid, p_name text, p_span_days integer default 7,
  p_template_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.shift_templates%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_template_id is not null then
    select * into v_t from public.shift_templates t where t.id = p_template_id;
    if not found or v_t.organization_id is distinct from p_organization_id or v_t.location_id is distinct from p_location_id
       or public.has_permission(v_t.organization_id, v_t.location_id, 'staff_schedule', 'edit') is not true then
      raise exception 'not allowed' using errcode = 'insufficient_privilege';
    end if;
  elsif p_organization_id is null or p_location_id is null
        or public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  if p_name is null or char_length(btrim(p_name)) not between 1 and 100 then
    raise exception 'a name needs 1 to 100 characters' using errcode = 'invalid_parameter_value';
  end if;
  if p_template_id is null then
    if p_span_days is null or p_span_days not in (1, 7) then
      raise exception 'a template covers 1 day or 7 days' using errcode = 'invalid_parameter_value';
    end if;
    insert into public.shift_templates (organization_id, location_id, name, span_days)
    values (p_organization_id, p_location_id, btrim(p_name), p_span_days)
    returning * into v_t;
  else
    if p_span_days is not null and p_span_days <> v_t.span_days then
      raise exception 'the length of a template cannot change' using errcode = 'invalid_parameter_value';
    end if;
    update public.shift_templates t set name = btrim(p_name)
    where t.id = v_t.id and t.name is distinct from btrim(p_name);
  end if;
  return v_t.id;
end;
$$;

create function public.archive_shift_template(p_template_id uuid, p_archived boolean default true)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.shift_templates%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.shift_templates t where t.id = p_template_id;
  if not found or public.has_permission(v_t.organization_id, v_t.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  update public.shift_templates t
  set archived_at = case when coalesce(p_archived, true) then coalesce(t.archived_at, now()) end
  where t.id = v_t.id;
end;
$$;

-- Add one shift to a template. The position must be usable at the location and not
-- archived; a default assignee must be someone the caller can see who works there
-- (the full rules are checked when the template is stamped). At most 200 items.
create function public.add_shift_template_item(
  p_template_id uuid, p_position_id uuid, p_day_offset integer, p_start_time time, p_duration_minutes integer,
  p_assigned_person_id uuid default null, p_notes text default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.shift_templates%rowtype;
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.shift_templates t where t.id = p_template_id;
  if not found or public.has_permission(v_t.organization_id, v_t.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  if p_day_offset is null or p_day_offset < 0 or p_day_offset >= v_t.span_days then
    raise exception 'that day is outside the template' using errcode = 'invalid_parameter_value';
  end if;
  if p_start_time is null or p_duration_minutes is null or p_duration_minutes not between 15 and 1440 then
    raise exception 'a shift needs a start time and 15 minutes to 24 hours' using errcode = 'invalid_parameter_value';
  end if;
  if char_length(p_notes) > 1000 then
    raise exception 'notes are too long' using errcode = 'invalid_parameter_value';
  end if;
  if not exists (select 1 from public.positions p
                 where p.id = p_position_id and p.organization_id = v_t.organization_id and p.archived_at is null
                   and (p.location_id is null or p.location_id = v_t.location_id)) then
    raise exception 'unknown position at this location' using errcode = 'invalid_parameter_value';
  end if;
  if p_assigned_person_id is not null
     and 'not_member' = any (private.shift_assignment_problems(
           v_t.organization_id, v_t.location_id, p_position_id, now(), now() + interval '1 minute',
           p_assigned_person_id, '{}', true)) then
    raise exception 'that person cannot work at this location' using errcode = 'check_violation', detail = 'not_member';
  end if;
  select * into v_t from public.shift_templates t where t.id = p_template_id for update;
  if (select count(*) from public.shift_template_items i where i.template_id = v_t.id) >= 200 then
    raise exception 'a template holds at most 200 shifts' using errcode = 'invalid_parameter_value';
  end if;
  insert into public.shift_template_items (organization_id, location_id, template_id, position_id, day_offset,
                                           start_time, duration_minutes, assigned_person_id, notes)
  values (v_t.organization_id, v_t.location_id, v_t.id, p_position_id, p_day_offset, p_start_time, p_duration_minutes,
          p_assigned_person_id, nullif(btrim(p_notes), ''))
  returning id into v_id;
  return v_id;
end;
$$;

create function public.remove_shift_template_item(p_item_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_i public.shift_template_items%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_i from public.shift_template_items i where i.id = p_item_id;
  if not found or public.has_permission(v_i.organization_id, v_i.location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('staffing_config');
  delete from public.shift_template_items i where i.id = v_i.id;
end;
$$;

-- ===========================================================================
-- Schedules and shifts
-- ===========================================================================

-- The draft schedule for a location's week (created if missing; the existing one,
-- draft or published, is returned otherwise). p_week_start must be the
-- organization's first weekday (organization_settings.week_starts_on), within two
-- years of today.
create function public.create_schedule(p_organization_id uuid, p_location_id uuid, p_week_start date)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_id uuid;
  v_dow smallint;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_organization_id is null or p_location_id is null
     or public.has_permission(p_organization_id, p_location_id, 'staff_schedule', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_edit');
  select s.week_starts_on into v_dow from public.organization_settings s where s.organization_id = p_organization_id;
  if p_week_start is null or not isfinite(p_week_start)
     or p_week_start not between current_date - 731 and current_date + 731 then
    raise exception 'invalid week' using errcode = 'invalid_parameter_value';
  end if;
  if extract(dow from p_week_start)::smallint <> coalesce(v_dow, 0) then
    raise exception 'a week must start on the organization''s first day of the week' using errcode = 'invalid_parameter_value';
  end if;
  select sc.id into v_id from public.schedules sc where sc.location_id = p_location_id and sc.week_start = p_week_start;
  if v_id is not null then
    return v_id;
  end if;
  begin
    insert into public.schedules (organization_id, location_id, week_start, created_by_person_id)
    values (p_organization_id, p_location_id, p_week_start, public.current_person_id(p_organization_id))
    on conflict (location_id, week_start) do nothing
    returning id into v_id;
  exception when exclusion_violation then
    raise exception 'another schedule already covers part of that week' using errcode = 'check_violation';
  end;
  if v_id is null then
    select sc.id into v_id from public.schedules sc where sc.location_id = p_location_id and sc.week_start = p_week_start;
  end if;
  return v_id;
end;
$$;

-- Publish a draft. Emits schedule.published (the worker notifies everyone with a
-- shift in it) and shift.opened for each open shift. From now on every change to
-- its shifts emits shift.* events.
create function public.publish_schedule(p_schedule_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_sc public.schedules%rowtype;
  v_s public.shifts%rowtype;
  v_n integer;
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
  select count(*) into v_n from public.shifts s where s.schedule_id = v_sc.id and s.status = 'scheduled';
  perform private.emit_event(
    v_sc.organization_id, v_sc.location_id, 'schedule.published', 'schedules', v_sc.id,
    jsonb_build_object('schedule_id', v_sc.id, 'location_id', v_sc.location_id, 'week_start', v_sc.week_start,
                       'shift_count', v_n, 'actor_person_id', v_sc.published_by_person_id));
  for v_s in
    select * from public.shifts s
    where s.schedule_id = v_sc.id and s.status = 'scheduled' and s.assigned_person_id is null
    order by s.starts_at, s.id
  loop
    perform private.emit_shift_event('shift.opened', v_s, jsonb_build_object('via', 'publish'));
  end loop;
end;
$$;

-- Shared validation of shift times against a schedule (22023).
create function private.validate_shift_times(p_schedule public.schedules, p_starts_at timestamptz, p_ends_at timestamptz)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_tz text;
begin
  if p_starts_at is null or p_ends_at is null or not isfinite(p_starts_at) or not isfinite(p_ends_at) then
    raise exception 'a shift needs a start and an end' using errcode = 'invalid_parameter_value';
  end if;
  if p_ends_at <= p_starts_at or p_ends_at - p_starts_at > interval '24 hours' then
    raise exception 'a shift ends after it starts and lasts at most 24 hours' using errcode = 'invalid_parameter_value';
  end if;
  select l.timezone into v_tz from public.locations l where l.id = p_schedule.location_id;
  if (p_starts_at at time zone v_tz)::date not between p_schedule.week_start and p_schedule.week_start + 6 then
    raise exception 'the shift must start during the schedule week' using errcode = 'invalid_parameter_value';
  end if;
end;
$$;
revoke all on function private.validate_shift_times(public.schedules, timestamptz, timestamptz) from public, anon, authenticated;

create function private.validate_shift_position(p_schedule public.schedules, p_position_id uuid)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from public.positions p
                 where p.id = p_position_id and p.organization_id = p_schedule.organization_id and p.archived_at is null
                   and (p.location_id is null or p.location_id = p_schedule.location_id)) then
    raise exception 'unknown position at this location' using errcode = 'invalid_parameter_value';
  end if;
end;
$$;
revoke all on function private.validate_shift_position(public.schedules, uuid) from public, anon, authenticated;

-- Add a shift to a schedule (draft or published). staff_schedule >= edit at the
-- location; an assignee must pass every rule (p_override: see require_assignable).
create function public.create_shift(
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
  if p_assigned_person_id is not null then
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
    perform private.emit_shift_event('shift.opened', v_s, jsonb_build_object('via', 'manager'));
  end if;
  return v_s.id;
end;
$$;

-- Change a shift's position, times or notes (null = keep). The current assignee is
-- checked against every rule again for the new time / position. On a published
-- schedule a change of time or position of an assigned shift emits shift.changed.
create function public.update_shift(
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
  v_ov := v_s.override_kinds;
  if v_s.assigned_person_id is not null
     and (v_new_pos <> v_s.position_id or v_new_start <> v_s.starts_at or v_new_end <> v_s.ends_at) then
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
  if v_sc.status = 'published' and v_after.assigned_person_id is not null
     and (v_after.position_id <> v_s.position_id or v_after.starts_at <> v_s.starts_at or v_after.ends_at <> v_s.ends_at) then
    perform private.emit_shift_event('shift.changed', v_after,
      jsonb_build_object('previous_starts_at', v_s.starts_at, 'previous_ends_at', v_s.ends_at,
                         'previous_position_id', v_s.position_id));
  end if;
end;
$$;

-- Assign a shift to a person, or open it (p_person_id null). Every rule is checked;
-- p_override (staff_schedule = admin) lets time off / qualification through.
create function public.assign_shift(p_shift_id uuid, p_person_id uuid, p_override boolean default false)
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
    perform private.lock_staffing_people(array[p_person_id]);
    v_ov := private.require_assignable(v_s.organization_id, v_s.location_id, v_s.position_id, v_s.starts_at, v_s.ends_at,
                                       p_person_id, array[v_s.id], p_override);
  end if;
  v_after := private.write_shift_assignee(v_s.id, p_person_id, v_ov);
  perform private.after_assignee_change(v_s, v_after, 'manager');
end;
$$;

-- Remove a shift: a draft schedule's shift is deleted; a published one is cancelled
-- (kept, visible to its assignee) and emits shift.cancelled. Open exchanges close.
create function public.cancel_shift(p_shift_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_s public.shifts%rowtype := private.lock_shift_for_scheduler(p_shift_id, 'edit');
  v_published boolean;
begin
  perform private.enforce_write_limit('shift_edit');
  if v_s.status = 'cancelled' then
    raise exception 'this shift is already cancelled' using errcode = 'invalid_parameter_value';
  end if;
  v_published := exists (select 1 from public.schedules sc where sc.id = v_s.schedule_id and sc.status = 'published');
  perform private.close_shift_exchanges(v_s.id, v_s.organization_id, true);
  if not v_published then
    delete from public.shift_swaps w where w.organization_id = v_s.organization_id
      and (w.shift_id = v_s.id or w.counter_shift_id = v_s.id);
    delete from public.shift_claims c where c.organization_id = v_s.organization_id and c.shift_id = v_s.id;
    delete from public.shifts s where s.id = v_s.id;
    return;
  end if;
  update public.shifts s set status = 'cancelled', cancelled_at = now() where s.id = v_s.id returning * into v_s;
  perform private.emit_shift_event('shift.cancelled', v_s);
end;
$$;

-- Stamp a template into a DRAFT schedule of the same location. A week template
-- starts on the week's first day (p_first_day 0); a day template on day p_first_day
-- (0-6). Local wall times in the location's time zone. A default assignee who fails
-- any rule (no override here) leaves that shift open; the result says why
-- (refused: not_member | overlap | time_off | qualification). Archived templates and
-- items whose position is archived or no longer at the location are refused / skipped.
create function public.apply_shift_template(p_schedule_id uuid, p_template_id uuid, p_first_day integer default 0)
returns table (shift_id uuid, assigned_person_id uuid, refused text)
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
  select l.timezone into v_tz from public.locations l where l.id = v_sc.location_id;
  select coalesce(array_agg(distinct i.assigned_person_id), '{}') into v_people
  from public.shift_template_items i where i.template_id = v_t.id and i.assigned_person_id is not null;
  perform private.lock_staffing_people(v_people);

  for v_i in
    select i.* from public.shift_template_items i
    join public.positions p on p.id = i.position_id and p.organization_id = i.organization_id
    where i.template_id = v_t.id and p.archived_at is null
      and (p.location_id is null or p.location_id = v_sc.location_id)
    order by i.day_offset, i.start_time, i.id
  loop
    v_local := (v_sc.week_start + p_first_day + v_i.day_offset)::timestamp + v_i.start_time;
    v_start := v_local at time zone v_tz;
    v_end := (v_local + make_interval(mins => v_i.duration_minutes)) at time zone v_tz;
    if v_end - v_start > interval '24 hours' or v_end <= v_start then
      continue;   -- a 24-hour item across a DST change; skipped
    end if;
    insert into public.shifts (organization_id, location_id, schedule_id, position_id, starts_at, ends_at, notes,
                               created_by_person_id)
    values (v_sc.organization_id, v_sc.location_id, v_sc.id, v_i.position_id, v_start, v_end, v_i.notes,
            public.current_person_id(v_sc.organization_id))
    returning * into v_s;
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
-- Shift exchange: swaps, drops, claims
-- ===========================================================================

-- Lock the shifts (in id order), then the swap row; re-read both.
create function private.lock_swap_and_shifts(p_swap_id uuid)
returns public.shift_swaps
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_w public.shift_swaps%rowtype;
begin
  select * into v_w from public.shift_swaps w where w.id = p_swap_id;
  perform 1 from public.shifts s where s.id in (v_w.shift_id, v_w.counter_shift_id) order by s.id for update;
  select * into v_w from public.shift_swaps w where w.id = p_swap_id for update;
  return v_w;
end;
$$;
revoke all on function private.lock_swap_and_shifts(uuid) from public, anon, authenticated;

-- A (the assignee of a published, future shift X) offers X to B, optionally in
-- exchange for B's shift Y at the same location. Needs shift_swaps >= edit there.
-- B must be someone A can see who works at the location; B's rules are checked
-- when B accepts (so A never learns B's time off). Emits shift_swap.requested.
create function public.request_shift_swap(
  p_shift_id uuid, p_to_person_id uuid, p_counter_shift_id uuid default null, p_note text default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_x public.shifts%rowtype;
  v_y public.shifts%rowtype;
  v_w public.shift_swaps%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_x from public.shifts s where s.id = p_shift_id;
  v_me := case when found then public.current_person_id(v_x.organization_id) end;
  if v_me is null or v_x.assigned_person_id is distinct from v_me
     or public.has_permission(v_x.organization_id, v_x.location_id, 'shift_swaps', 'edit') is not true
     or private.can_see_shift(v_x.organization_id, v_x.location_id, v_x.schedule_id, v_x.assigned_person_id, v_x.status) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_exchange');
  if char_length(p_note) > 500 then
    raise exception 'the note is too long' using errcode = 'invalid_parameter_value';
  end if;
  if p_to_person_id is null or p_to_person_id = v_me
     or 'not_member' = any (private.shift_assignment_problems(v_x.organization_id, v_x.location_id, v_x.position_id,
                                                              v_x.starts_at, v_x.ends_at, p_to_person_id, '{}', true))
     or coalesce(private.person_effective_level(v_x.organization_id, p_to_person_id, v_x.location_id, 'shift_swaps')
                 >= 'edit', false) is not true then
    raise exception 'you cannot swap with that person' using errcode = 'check_violation', detail = 'not_member';
  end if;
  if p_counter_shift_id is not null then
    select * into v_y from public.shifts s where s.id = p_counter_shift_id;
    if not found or v_y.organization_id <> v_x.organization_id or v_y.location_id <> v_x.location_id
       or v_y.assigned_person_id is distinct from p_to_person_id
       or private.can_see_shift(v_y.organization_id, v_y.location_id, v_y.schedule_id, v_y.assigned_person_id, v_y.status) is not true then
      raise exception 'that shift cannot be part of this swap' using errcode = 'invalid_parameter_value';
    end if;
  end if;
  perform 1 from public.shifts s where s.id in (v_x.id, v_y.id) order by s.id for update;
  select * into v_x from public.shifts s where s.id = p_shift_id;
  if v_x.assigned_person_id is distinct from v_me or private.shift_is_exchangeable(v_x) is not true then
    raise exception 'this shift cannot be swapped now' using errcode = 'invalid_parameter_value';
  end if;
  if p_counter_shift_id is not null then
    select * into v_y from public.shifts s where s.id = p_counter_shift_id;
    if v_y.assigned_person_id is distinct from p_to_person_id or private.shift_is_exchangeable(v_y) is not true then
      raise exception 'that shift cannot be part of this swap' using errcode = 'invalid_parameter_value';
    end if;
  end if;
  begin
    insert into public.shift_swaps (organization_id, location_id, kind, shift_id, counter_shift_id, from_person_id,
                                    to_person_id, note)
    values (v_x.organization_id, v_x.location_id, 'swap', v_x.id, p_counter_shift_id, v_me, p_to_person_id,
            nullif(btrim(p_note), ''))
    returning * into v_w;
  exception when unique_violation then
    raise exception 'this shift already has an open swap or drop' using errcode = 'invalid_parameter_value';
  end;
  perform private.emit_swap_event('shift_swap.requested', v_w);
  return v_w.id;
end;
$$;

-- Approve a swap: check every rule for B on X (and A on Y) and move both in this
-- transaction. Shared by decide_shift_swap and auto-approval. The swap and its
-- shifts are locked by the caller. Returns false (and changes nothing) when
-- p_soft and a rule fails; raises otherwise.
create function private.execute_swap(p_w public.shift_swaps, p_override boolean, p_soft boolean, p_auto boolean)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_x public.shifts%rowtype;
  v_y public.shifts%rowtype;
  v_x_after public.shifts%rowtype;
  v_y_after public.shifts%rowtype;
  v_ov_b text[] := '{}';
  v_ov_a text[] := '{}';
  v_w public.shift_swaps%rowtype;
begin
  select * into v_x from public.shifts s where s.id = p_w.shift_id;
  if p_w.counter_shift_id is not null then
    select * into v_y from public.shifts s where s.id = p_w.counter_shift_id;
  end if;
  if v_x.assigned_person_id is distinct from p_w.from_person_id or private.shift_is_exchangeable(v_x) is not true
     or (p_w.counter_shift_id is not null
         and (v_y.assigned_person_id is distinct from p_w.to_person_id or private.shift_is_exchangeable(v_y) is not true)) then
    if p_soft then
      return false;
    end if;
    raise exception 'the shift changed since the swap was offered' using errcode = 'check_violation', detail = 'stale';
  end if;
  perform private.lock_staffing_people(array[p_w.from_person_id, p_w.to_person_id]);
  if p_soft then
    if cardinality(private.shift_assignment_problems(v_x.organization_id, v_x.location_id, v_x.position_id, v_x.starts_at,
                     v_x.ends_at, p_w.to_person_id, array_remove(array[v_x.id, v_y.id], null), false)) > 0
       or (v_y.id is not null and cardinality(private.shift_assignment_problems(v_y.organization_id, v_y.location_id,
                     v_y.position_id, v_y.starts_at, v_y.ends_at, p_w.from_person_id, array[v_x.id, v_y.id], false)) > 0) then
      return false;
    end if;
  else
    v_ov_b := private.require_assignable(v_x.organization_id, v_x.location_id, v_x.position_id, v_x.starts_at, v_x.ends_at,
                                         p_w.to_person_id, array_remove(array[v_x.id, v_y.id], null), p_override, true);
    if v_y.id is not null then
      v_ov_a := private.require_assignable(v_y.organization_id, v_y.location_id, v_y.position_id, v_y.starts_at,
                                           v_y.ends_at, p_w.from_person_id, array[v_x.id, v_y.id], p_override, true);
    end if;
  end if;
  update public.shift_swaps w
  set status = 'approved', decided_at = now(), auto_approved = p_auto,
      decided_by_person_id = case when p_auto then null else public.current_person_id(w.organization_id) end
  where w.id = p_w.id
  returning * into v_w;
  -- X leaves A first, so neither person ever holds both at once.
  v_x_after := private.write_shift_assignee(v_x.id, null, '{}');
  if v_y.id is not null then
    v_y_after := private.write_shift_assignee(v_y.id, p_w.from_person_id, v_ov_a);
  end if;
  v_x_after := private.write_shift_assignee(v_x.id, p_w.to_person_id, v_ov_b);
  perform private.emit_swap_event('shift_swap.approved', v_w);
  perform private.after_assignee_change(v_x, v_x_after, 'swap');
  if v_y.id is not null then
    perform private.after_assignee_change(v_y, v_y_after, 'swap');
  end if;
  return true;
end;
$$;
revoke all on function private.execute_swap(public.shift_swaps, boolean, boolean, boolean) from public, anon, authenticated;

-- B accepts or declines an offered swap. Accepting checks B's own rules for X
-- (B learns only about B). Emits shift_swap.accepted (or .denied). When the
-- organization allows auto-approval and every rule passes for both people, the
-- swap is approved and moved at once; otherwise it waits for a manager.
-- Returns the new status.
create function public.respond_shift_swap(p_swap_id uuid, p_accept boolean)
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
  if private.staffing_setting(v_w.organization_id, 'auto_approve_swaps')
     and private.execute_swap(v_w, false, true, true) then
    return 'approved';
  end if;
  return v_w.status;
end;
$$;

-- A manager (shift_swaps = admin at the location, not a party) approves or denies
-- an accepted swap or a requested drop. Approval re-checks every rule now (p_override
-- for time off / qualification needs staff_schedule = admin) and moves the shift(s)
-- in the same transaction. A drop's approval opens the shift (shift.opened).
create function public.decide_shift_swap(p_swap_id uuid, p_approve boolean, p_override boolean default false)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_w public.shift_swaps%rowtype;
  v_x public.shifts%rowtype;
  v_after public.shifts%rowtype;
  v_me uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_w from public.shift_swaps w where w.id = p_swap_id;
  if not found or public.has_permission(v_w.organization_id, v_w.location_id, 'shift_swaps', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(v_w.organization_id);
  if v_me is not null and v_me in (v_w.from_person_id, v_w.to_person_id) then
    raise exception 'you cannot decide your own swap' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_decide');
  if p_approve is null then
    raise exception 'approve or deny' using errcode = 'invalid_parameter_value';
  end if;
  if coalesce(p_override, false)
     and public.has_permission(v_w.organization_id, v_w.location_id, 'staff_schedule', 'admin') is not true then
    raise exception 'only a schedule admin can override' using errcode = 'insufficient_privilege';
  end if;
  v_w := private.lock_swap_and_shifts(v_w.id);
  if v_w.status <> (case when v_w.kind = 'swap' then 'accepted' else 'requested' end) then
    raise exception 'this request is not waiting for a decision' using errcode = 'invalid_parameter_value';
  end if;
  if not p_approve then
    update public.shift_swaps w set status = 'denied', decided_at = now(), decided_by_person_id = v_me
    where w.id = v_w.id returning * into v_w;
    perform private.emit_swap_event('shift_swap.denied', v_w);
    return;
  end if;
  if v_w.kind = 'swap' then
    perform private.execute_swap(v_w, p_override, false, false);
    return;
  end if;
  -- drop
  select * into v_x from public.shifts s where s.id = v_w.shift_id;
  if v_x.assigned_person_id is distinct from v_w.from_person_id or private.shift_is_exchangeable(v_x) is not true then
    raise exception 'the shift changed since the drop was requested' using errcode = 'check_violation', detail = 'stale';
  end if;
  update public.shift_swaps w set status = 'approved', decided_at = now(), decided_by_person_id = v_me
  where w.id = v_w.id returning * into v_w;
  perform private.emit_swap_event('shift_swap.approved', v_w);
  v_after := private.write_shift_assignee(v_x.id, null, '{}');
  perform private.after_assignee_change(v_x, v_after, 'drop');
end;
$$;

-- Either party withdraws an open swap; the requester withdraws an open drop.
create function public.cancel_shift_swap(p_swap_id uuid)
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
  if v_me is null or v_me not in (v_w.from_person_id, coalesce(v_w.to_person_id, v_w.from_person_id)) then
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

-- A gives up a published, future shift they hold. It stays theirs until a manager
-- approves the drop (decide_shift_swap), then it opens for claims. Emits
-- shift_swap.requested with kind 'drop'. Drops always need a manager.
create function public.request_shift_drop(p_shift_id uuid, p_note text default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_x public.shifts%rowtype;
  v_w public.shift_swaps%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_x from public.shifts s where s.id = p_shift_id;
  v_me := case when found then public.current_person_id(v_x.organization_id) end;
  if v_me is null or v_x.assigned_person_id is distinct from v_me
     or public.has_permission(v_x.organization_id, v_x.location_id, 'shift_swaps', 'edit') is not true
     or private.can_see_shift(v_x.organization_id, v_x.location_id, v_x.schedule_id, v_x.assigned_person_id, v_x.status) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_exchange');
  if char_length(p_note) > 500 then
    raise exception 'the note is too long' using errcode = 'invalid_parameter_value';
  end if;
  select * into v_x from public.shifts s where s.id = p_shift_id for update;
  if v_x.assigned_person_id is distinct from v_me or private.shift_is_exchangeable(v_x) is not true then
    raise exception 'this shift cannot be dropped now' using errcode = 'invalid_parameter_value';
  end if;
  begin
    insert into public.shift_swaps (organization_id, location_id, kind, shift_id, from_person_id, note)
    values (v_x.organization_id, v_x.location_id, 'drop', v_x.id, v_me, nullif(btrim(p_note), ''))
    returning * into v_w;
  exception when unique_violation then
    raise exception 'this shift already has an open swap or drop' using errcode = 'invalid_parameter_value';
  end;
  perform private.emit_swap_event('shift_swap.requested', v_w);
  return v_w.id;
end;
$$;

-- Approve a claim on a locked open shift: rules again, assign, close the others.
create function private.execute_claim(p_c public.shift_claims, p_override boolean, p_auto boolean)
returns public.shift_claims
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_s public.shifts%rowtype;
  v_after public.shifts%rowtype;
  v_ov text[];
  v_c public.shift_claims%rowtype;
begin
  select * into v_s from public.shifts s where s.id = p_c.shift_id;
  if v_s.assigned_person_id is not null or private.shift_is_exchangeable(v_s) is not true then
    raise exception 'this shift is no longer open' using errcode = 'check_violation', detail = 'stale';
  end if;
  perform private.lock_staffing_people(array[p_c.person_id]);
  v_ov := private.require_assignable(v_s.organization_id, v_s.location_id, v_s.position_id, v_s.starts_at, v_s.ends_at,
                                     p_c.person_id, array[v_s.id], p_override, not p_auto);
  update public.shift_claims c
  set status = 'approved', decided_at = now(), auto_approved = p_auto,
      decided_by_person_id = case when p_auto then null else public.current_person_id(c.organization_id) end
  where c.id = p_c.id
  returning * into v_c;
  perform private.emit_claim_event('shift_claim.approved', v_c);
  v_after := private.write_shift_assignee(v_s.id, p_c.person_id, v_ov);
  perform private.after_assignee_change(v_s, v_after, 'claim');
  return v_c;
end;
$$;
revoke all on function private.execute_claim(public.shift_claims, boolean, boolean) from public, anon, authenticated;

-- Ask for an open, published, future shift. Needs shift_swaps >= edit at the
-- location, and the caller must pass every rule now. With first_come_open_shifts the
-- claim is approved at once (the first valid claim wins under the shift lock);
-- otherwise it waits for a manager. Returns the claim id.
create function public.request_shift_claim(p_shift_id uuid)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_s public.shifts%rowtype;
  v_c public.shift_claims%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_s from public.shifts s where s.id = p_shift_id;
  v_me := case when found then public.current_person_id(v_s.organization_id) end;
  if v_me is null
     or public.has_permission(v_s.organization_id, v_s.location_id, 'shift_swaps', 'edit') is not true
     or private.can_see_shift(v_s.organization_id, v_s.location_id, v_s.schedule_id, v_s.assigned_person_id, v_s.status) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_exchange');
  select * into v_s from public.shifts s where s.id = p_shift_id for update;
  if v_s.assigned_person_id is not null or private.shift_is_exchangeable(v_s) is not true then
    raise exception 'this shift is no longer open' using errcode = 'check_violation', detail = 'stale';
  end if;
  perform private.lock_staffing_people(array[v_me]);
  perform private.require_assignable(v_s.organization_id, v_s.location_id, v_s.position_id, v_s.starts_at, v_s.ends_at,
                                     v_me, array[v_s.id], false, false);
  begin
    insert into public.shift_claims (organization_id, location_id, shift_id, person_id)
    values (v_s.organization_id, v_s.location_id, v_s.id, v_me)
    returning * into v_c;
  exception when unique_violation then
    raise exception 'you already asked for this shift' using errcode = 'invalid_parameter_value';
  end;
  if private.staffing_setting(v_s.organization_id, 'first_come_open_shifts') then
    v_c := private.execute_claim(v_c, false, true);
  else
    perform private.emit_claim_event('shift_claim.requested', v_c);
  end if;
  return v_c.id;
end;
$$;

-- A manager (shift_swaps = admin at the location, not the claimant) approves or
-- denies a claim. Approval re-checks every rule and assigns in this transaction;
-- other open claims of the shift are denied.
create function public.decide_shift_claim(p_claim_id uuid, p_approve boolean, p_override boolean default false)
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
  if not found or public.has_permission(v_c.organization_id, v_c.location_id, 'shift_swaps', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(v_c.organization_id);
  if v_me is not null and v_me = v_c.person_id then
    raise exception 'you cannot decide your own request' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('shift_decide');
  if p_approve is null then
    raise exception 'approve or deny' using errcode = 'invalid_parameter_value';
  end if;
  if coalesce(p_override, false)
     and public.has_permission(v_c.organization_id, v_c.location_id, 'staff_schedule', 'admin') is not true then
    raise exception 'only a schedule admin can override' using errcode = 'insufficient_privilege';
  end if;
  perform 1 from public.shifts s where s.id = v_c.shift_id for update;
  select * into v_c from public.shift_claims c where c.id = p_claim_id for update;
  if v_c.status <> 'requested' then
    raise exception 'this request is not waiting for a decision' using errcode = 'invalid_parameter_value';
  end if;
  if not p_approve then
    update public.shift_claims c set status = 'denied', decided_at = now(), decided_by_person_id = v_me
    where c.id = v_c.id returning * into v_c;
    perform private.emit_claim_event('shift_claim.denied', v_c);
    return;
  end if;
  perform private.execute_claim(v_c, p_override, false);
end;
$$;

create function public.cancel_shift_claim(p_claim_id uuid)
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
  if v_me is null or v_c.person_id <> v_me then
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

-- Open, published, future shifts the caller may claim right now (every rule passes),
-- soonest first, at most 200.
create function public.my_claimable_shifts(p_organization_id uuid, p_limit integer default 50)
returns table (shift_id uuid, location_id uuid, schedule_id uuid, position_id uuid, starts_at timestamptz,
               ends_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select s.id, s.location_id, s.schedule_id, s.position_id, s.starts_at, s.ends_at
  from public.shifts s
  join public.schedules sc on sc.id = s.schedule_id and sc.organization_id = s.organization_id and sc.status = 'published'
  where s.organization_id = p_organization_id
    and (select auth.uid()) is not null
    and public.current_person_id(p_organization_id) is not null
    and s.assigned_person_id is null and s.status = 'scheduled' and s.starts_at > now()
    and s.location_id in (select public.auth_location_ids())
    and public.has_permission(s.organization_id, s.location_id, 'shift_swaps', 'edit')
    and cardinality(private.shift_assignment_problems(s.organization_id, s.location_id, s.position_id, s.starts_at,
                    s.ends_at, public.current_person_id(p_organization_id), array[s.id], false)) = 0
    and not exists (select 1 from public.shift_claims c
                    where c.shift_id = s.id and c.person_id = public.current_person_id(p_organization_id)
                      and c.status = 'requested')
  order by s.starts_at, s.id
  limit least(greatest(coalesce(p_limit, 50), 1), 200)
$$;

-- ===========================================================================
-- Availability and time off
-- ===========================================================================

-- The caller's own weekly window. availability_time_off >= edit somewhere in the
-- organization. No overlap rule: windows are preferences, not rules.
create function public.add_availability(
  p_organization_id uuid, p_day_of_week integer, p_start_time time, p_end_time time, p_kind text,
  p_effective_from date default null, p_effective_to date default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or private.has_permission_anywhere(p_organization_id, 'availability_time_off', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('availability_edit');
  if p_day_of_week is null or p_day_of_week not between 1 and 7 then
    raise exception 'invalid day' using errcode = 'invalid_parameter_value';
  end if;
  if p_start_time is null or p_end_time is null or p_end_time <= p_start_time then
    raise exception 'the end must be after the start' using errcode = 'invalid_parameter_value';
  end if;
  if p_kind is null or p_kind not in ('available', 'unavailable', 'preferred') then
    raise exception 'invalid kind' using errcode = 'invalid_parameter_value';
  end if;
  if (p_effective_from is not null and not isfinite(p_effective_from))
     or (p_effective_to is not null and not isfinite(p_effective_to))
     or (p_effective_from is not null and p_effective_to is not null and p_effective_to < p_effective_from) then
    raise exception 'invalid dates' using errcode = 'invalid_parameter_value';
  end if;
  if (select count(*) from public.availability a where a.person_id = v_me) >= 100 then
    raise exception 'at most 100 availability windows' using errcode = 'invalid_parameter_value';
  end if;
  insert into public.availability (organization_id, person_id, day_of_week, start_time, end_time, kind,
                                   effective_from, effective_to)
  values (p_organization_id, v_me, p_day_of_week, p_start_time, p_end_time, p_kind, p_effective_from, p_effective_to)
  returning id into v_id;
  return v_id;
end;
$$;

create function public.remove_availability(p_availability_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_a public.availability%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_a from public.availability a where a.id = p_availability_id;
  if not found or v_a.person_id is distinct from public.current_person_id(v_a.organization_id)
     or private.has_permission_anywhere(v_a.organization_id, 'availability_time_off', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('availability_edit');
  delete from public.availability a where a.id = v_a.id;
end;
$$;

-- The caller asks for days off (inclusive dates, up to 366 days, not ending in the
-- past). availability_time_off >= edit somewhere in the organization. Emits
-- time_off.requested (no reason in the event).
create function public.request_time_off(
  p_organization_id uuid, p_starts_on date, p_ends_on date, p_reason text default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_t public.time_off_requests%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or private.has_permission_anywhere(p_organization_id, 'availability_time_off', 'edit') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('time_off_request');
  if p_starts_on is null or p_ends_on is null or not isfinite(p_starts_on) or not isfinite(p_ends_on)
     or p_ends_on < p_starts_on or p_ends_on - p_starts_on > 365 then
    raise exception 'choose a first and last day, at most a year apart' using errcode = 'invalid_parameter_value';
  end if;
  if p_ends_on < current_date - 1 or p_starts_on > current_date + 731 then
    raise exception 'those days are too far in the past or future' using errcode = 'invalid_parameter_value';
  end if;
  if char_length(p_reason) > 500 then
    raise exception 'the reason is too long' using errcode = 'invalid_parameter_value';
  end if;
  insert into public.time_off_requests (organization_id, person_id, starts_on, ends_on, reason)
  values (p_organization_id, v_me, p_starts_on, p_ends_on, nullif(btrim(p_reason), ''))
  returning * into v_t;
  perform private.emit_event(
    v_t.organization_id, null, 'time_off.requested', 'time_off_requests', v_t.id,
    jsonb_build_object('time_off_id', v_t.id, 'person_id', v_t.person_id, 'starts_on', v_t.starts_on,
                       'ends_on', v_t.ends_on, 'status', v_t.status));
  return v_t.id;
end;
$$;

-- The person withdraws a pending request, or an approved one that has not ended.
-- Emits time_off.cancelled.
create function public.cancel_time_off(p_time_off_id uuid)
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
  if not found or v_t.person_id is distinct from public.current_person_id(v_t.organization_id) then
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

-- An availability_time_off admin over the person (not the person) approves or
-- denies a pending request. Approval is refused while the person holds a scheduled
-- shift in those days (at that shift's location's local dates): reassign it first.
-- Emits time_off.decided.
create function public.decide_time_off(p_time_off_id uuid, p_approve boolean)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.time_off_requests%rowtype;
  v_me uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.time_off_requests t where t.id = p_time_off_id;
  if not found
     or private.has_permission_over_person(v_t.organization_id, v_t.person_id, 'availability_time_off', 'admin') is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(v_t.organization_id);
  if v_me is not null and v_me = v_t.person_id then
    raise exception 'you cannot decide your own request' using errcode = 'insufficient_privilege';
  end if;
  perform private.enforce_write_limit('time_off_decide');
  if p_approve is null then
    raise exception 'approve or deny' using errcode = 'invalid_parameter_value';
  end if;
  perform private.lock_staffing_people(array[v_t.person_id]);
  select * into v_t from public.time_off_requests t where t.id = p_time_off_id for update;
  if v_t.status <> 'pending' then
    raise exception 'this request is not waiting for a decision' using errcode = 'invalid_parameter_value';
  end if;
  if p_approve and exists (
       select 1 from public.shifts s
       join public.locations l on l.id = s.location_id and l.organization_id = s.organization_id
       where s.organization_id = v_t.organization_id and s.assigned_person_id = v_t.person_id and s.status = 'scheduled'
         and tstzrange(s.starts_at, s.ends_at, '[)')
             && tstzrange(v_t.starts_on::timestamp at time zone l.timezone,
                          (v_t.ends_on + 1)::timestamp at time zone l.timezone, '[)')) then
    raise exception 'that person has shifts on those days; reassign them first'
      using errcode = 'check_violation', detail = 'has_shifts';
  end if;
  update public.time_off_requests t
  set status = case when p_approve then 'approved' else 'denied' end, decided_at = now(), decided_by_person_id = v_me
  where t.id = v_t.id returning * into v_t;
  perform private.emit_event(
    v_t.organization_id, null, 'time_off.decided', 'time_off_requests', v_t.id,
    jsonb_build_object('time_off_id', v_t.id, 'person_id', v_t.person_id, 'starts_on', v_t.starts_on,
                       'ends_on', v_t.ends_on, 'status', v_t.status, 'decided_by_person_id', v_me));
end;
$$;

revoke all on function
  public.save_position(uuid, uuid, text, uuid[], uuid),
  public.archive_position(uuid, boolean),
  public.save_qualification(uuid, text, uuid),
  public.archive_qualification(uuid, boolean),
  public.set_person_qualification(uuid, uuid, uuid, date, date),
  public.remove_person_qualification(uuid),
  public.save_shift_template(uuid, uuid, text, integer, uuid),
  public.archive_shift_template(uuid, boolean),
  public.add_shift_template_item(uuid, uuid, integer, time, integer, uuid, text),
  public.remove_shift_template_item(uuid),
  public.apply_shift_template(uuid, uuid, integer),
  public.create_schedule(uuid, uuid, date),
  public.publish_schedule(uuid),
  public.create_shift(uuid, uuid, timestamptz, timestamptz, uuid, text, boolean),
  public.update_shift(uuid, uuid, timestamptz, timestamptz, text, boolean),
  public.assign_shift(uuid, uuid, boolean),
  public.cancel_shift(uuid),
  public.request_shift_swap(uuid, uuid, uuid, text),
  public.respond_shift_swap(uuid, boolean),
  public.decide_shift_swap(uuid, boolean, boolean),
  public.cancel_shift_swap(uuid),
  public.request_shift_drop(uuid, text),
  public.request_shift_claim(uuid),
  public.decide_shift_claim(uuid, boolean, boolean),
  public.cancel_shift_claim(uuid),
  public.my_claimable_shifts(uuid, integer),
  public.add_availability(uuid, integer, time, time, text, date, date),
  public.remove_availability(uuid),
  public.request_time_off(uuid, date, date, text),
  public.cancel_time_off(uuid),
  public.decide_time_off(uuid, boolean)
from public, anon, authenticated;
grant execute on function
  public.save_position(uuid, uuid, text, uuid[], uuid),
  public.archive_position(uuid, boolean),
  public.save_qualification(uuid, text, uuid),
  public.archive_qualification(uuid, boolean),
  public.set_person_qualification(uuid, uuid, uuid, date, date),
  public.remove_person_qualification(uuid),
  public.save_shift_template(uuid, uuid, text, integer, uuid),
  public.archive_shift_template(uuid, boolean),
  public.add_shift_template_item(uuid, uuid, integer, time, integer, uuid, text),
  public.remove_shift_template_item(uuid),
  public.apply_shift_template(uuid, uuid, integer),
  public.create_schedule(uuid, uuid, date),
  public.publish_schedule(uuid),
  public.create_shift(uuid, uuid, timestamptz, timestamptz, uuid, text, boolean),
  public.update_shift(uuid, uuid, timestamptz, timestamptz, text, boolean),
  public.assign_shift(uuid, uuid, boolean),
  public.cancel_shift(uuid),
  public.request_shift_swap(uuid, uuid, uuid, text),
  public.respond_shift_swap(uuid, boolean),
  public.decide_shift_swap(uuid, boolean, boolean),
  public.cancel_shift_swap(uuid),
  public.request_shift_drop(uuid, text),
  public.request_shift_claim(uuid),
  public.decide_shift_claim(uuid, boolean, boolean),
  public.cancel_shift_claim(uuid),
  public.my_claimable_shifts(uuid, integer),
  public.add_availability(uuid, integer, time, time, text, date, date),
  public.remove_availability(uuid),
  public.request_time_off(uuid, date, date, text),
  public.cancel_time_off(uuid),
  public.decide_time_off(uuid, boolean)
to authenticated, service_role;

-- ===========================================================================
-- Worker functions (service_role only; each refuses a JWT with a sub)
-- ===========================================================================

-- shift.uncovered once per open shift per start time: open (no assignee),
-- scheduled, on a published schedule, starting within p_within from now (1 minute
-- to 14 days). Round-robin by organization (each organization's soonest first),
-- SKIP LOCKED, so concurrent and repeated runs never emit twice for the same fact.
-- A shift whose start time changes becomes eligible again for its new start.
create function public.emit_uncovered_shift_events(p_within interval, p_limit integer default 500)
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_s public.shifts%rowtype;
  v_n integer := 0;
begin
  perform private.assert_service_caller();
  if p_within is null or p_within < interval '1 minute' or p_within > interval '14 days' then
    raise exception 'invalid window' using errcode = 'invalid_parameter_value';
  end if;
  if p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid limit' using errcode = 'invalid_parameter_value';
  end if;
  for v_s in
    select * from public.shifts s
    where s.id in (
        select r.id from (
          select x.id, x.starts_at,
                 row_number() over (partition by x.organization_id order by x.starts_at, x.id) as rn
          from public.shifts x
          join public.schedules sc on sc.id = x.schedule_id and sc.organization_id = x.organization_id
          where x.assigned_person_id is null and x.status = 'scheduled' and sc.status = 'published'
            and x.starts_at > now() and x.starts_at <= now() + p_within
            and x.uncovered_emitted_for is distinct from x.starts_at) r
        order by r.rn, r.starts_at
        limit p_limit)
      and s.assigned_person_id is null and s.status = 'scheduled'
      and s.starts_at > now() and s.starts_at <= now() + p_within
      and s.uncovered_emitted_for is distinct from s.starts_at
    order by s.starts_at
    for update skip locked
  loop
    update public.shifts s set uncovered_emitted_for = s.starts_at where s.id = v_s.id;
    perform private.emit_shift_event('shift.uncovered', v_s);
    v_n := v_n + 1;
  end loop;
  return v_n;
end;
$$;

-- The shift an event is about: entity shifts, or the shift of a shift_swaps /
-- shift_claims event; same organization as the event. No notes.
create function public.worker_shift_for_event(p_event_id uuid)
returns table (shift_id uuid, organization_id uuid, location_id uuid, location_name text, location_timezone text,
               schedule_id uuid, schedule_status text, week_start date, position_id uuid, position_name text,
               starts_at timestamptz, ends_at timestamptz, assigned_person_id uuid, status text)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
begin
  perform private.assert_service_caller();
  return query
  select s.id, s.organization_id, s.location_id, l.name, l.timezone, sc.id, sc.status, sc.week_start,
         p.id, p.name, s.starts_at, s.ends_at, s.assigned_person_id, s.status
  from public.outbox_events e
  join public.shifts s on s.organization_id = e.organization_id
   and s.id = case e.entity_table
                when 'shifts' then e.entity_id
                when 'shift_swaps' then (select w.shift_id from public.shift_swaps w
                                         where w.id = e.entity_id and w.organization_id = e.organization_id)
                when 'shift_claims' then (select c.shift_id from public.shift_claims c
                                          where c.id = e.entity_id and c.organization_id = e.organization_id)
              end
  join public.locations l on l.id = s.location_id and l.organization_id = s.organization_id
  join public.schedules sc on sc.id = s.schedule_id and sc.organization_id = s.organization_id
  join public.positions p on p.id = s.position_id and p.organization_id = s.organization_id
  where e.id = p_event_id and e.entity_table in ('shifts', 'shift_swaps', 'shift_claims');
end;
$$;

-- Who to notify for a staffing event (one row per person, active members of the
-- event's organization only). See docs/SECURITY.md for the table of events and
-- reasons. Reads current state where the event needs a decision still pending.
create function public.worker_shift_event_recipients(p_event_id uuid)
returns table (person_id uuid, reason text)
language plpgsql
stable
security definer
set search_path = ''
as $$
#variable_conflict use_column
declare
  v_e public.outbox_events%rowtype;
  v_s public.shifts%rowtype;
  v_w public.shift_swaps%rowtype;
  v_c public.shift_claims%rowtype;
  v_t public.time_off_requests%rowtype;
  v_p uuid;
begin
  perform private.assert_service_caller();
  select * into v_e from public.outbox_events e where e.id = p_event_id;
  if not found then
    return;
  end if;
  if v_e.entity_table = 'shifts' then
    select * into v_s from public.shifts s where s.id = v_e.entity_id and s.organization_id = v_e.organization_id;
    if not found then
      return;
    end if;
  elsif v_e.entity_table = 'shift_swaps' then
    select * into v_w from public.shift_swaps w where w.id = v_e.entity_id and w.organization_id = v_e.organization_id;
    if not found then
      return;
    end if;
  elsif v_e.entity_table = 'shift_claims' then
    select * into v_c from public.shift_claims c where c.id = v_e.entity_id and c.organization_id = v_e.organization_id;
    if not found then
      return;
    end if;
  elsif v_e.entity_table = 'time_off_requests' then
    select * into v_t from public.time_off_requests t where t.id = v_e.entity_id and t.organization_id = v_e.organization_id;
    if not found then
      return;
    end if;
  elsif v_e.entity_table <> 'schedules' then
    return;
  end if;
  begin
    v_p := (v_e.payload ->> 'person_id')::uuid;
  exception when others then
    v_p := null;
  end;

  return query
  with r (person_id, reason) as (
    -- schedule.published: everyone holding a scheduled shift in it
    select distinct s.assigned_person_id, 'schedule_published'
    from public.schedules sc
    join public.shifts s on s.schedule_id = sc.id and s.organization_id = sc.organization_id
    where v_e.type = 'schedule.published' and sc.id = v_e.entity_id and sc.organization_id = v_e.organization_id
      and sc.status = 'published' and s.status = 'scheduled' and s.assigned_person_id is not null
    union all
    -- shift.assigned / unassigned / changed / cancelled: the person in the payload
    select v_p, case v_e.type when 'shift.assigned' then 'assigned' when 'shift.unassigned' then 'unassigned'
                              when 'shift.changed' then 'changed' else 'cancelled' end
    where v_e.type in ('shift.assigned', 'shift.unassigned', 'shift.changed', 'shift.cancelled') and v_p is not null
    union all
    -- shift.opened: people who could claim it now (still open, published, future)
    select x, 'can_claim'
    from private.staffing_location_people(v_e.organization_id, v_s.location_id, 'shift_swaps', 'edit') x
    where v_e.type = 'shift.opened' and v_s.id is not null and v_s.assigned_person_id is null
      and private.shift_is_exchangeable(v_s)
      and cardinality(private.shift_assignment_problems(v_s.organization_id, v_s.location_id, v_s.position_id,
                      v_s.starts_at, v_s.ends_at, x, array[v_s.id], false)) = 0
    union all
    -- shift.uncovered: schedulers and exchange approvers at the location, while still open
    select x, 'uncovered'
    from (select y from private.staffing_location_people(v_e.organization_id, v_s.location_id, 'staff_schedule', 'edit') y
          union
          select y from private.staffing_location_people(v_e.organization_id, v_s.location_id, 'shift_swaps', 'admin') y) q (x)
    where v_e.type = 'shift.uncovered' and v_s.id is not null and v_s.assigned_person_id is null and v_s.status = 'scheduled'
    union all
    -- shift_swap.requested: the person offered the swap; for a drop, the approvers
    select v_w.to_person_id, 'swap_offered'
    where v_e.type = 'shift_swap.requested' and v_w.kind = 'swap' and v_w.status = 'requested'
    union all
    select x, 'needs_approval'
    from private.staffing_location_people(v_e.organization_id, v_w.location_id, 'shift_swaps', 'admin') x
    where ((v_e.type = 'shift_swap.requested' and v_w.kind = 'drop' and v_w.status = 'requested')
           or (v_e.type = 'shift_swap.accepted' and v_w.status = 'accepted'))
      and x <> v_w.from_person_id and x is distinct from v_w.to_person_id
    union all
    -- shift_swap.accepted: the person who offered it
    select v_w.from_person_id, 'swap_accepted' where v_e.type = 'shift_swap.accepted'
    union all
    -- shift_swap.approved / denied / cancelled: the parties (not the one who acted)
    select x, case v_e.type when 'shift_swap.approved' then 'swap_approved' when 'shift_swap.denied' then 'swap_denied'
                            else 'swap_cancelled' end
    from unnest(array[v_w.from_person_id, v_w.to_person_id]) x
    where v_e.type in ('shift_swap.approved', 'shift_swap.denied', 'shift_swap.cancelled') and x is not null
      and x is distinct from (case when v_e.payload ->> 'actor_person_id' ~ '^[0-9a-f-]{36}$'
                                   then (v_e.payload ->> 'actor_person_id')::uuid end)
    union all
    -- shift_claim.requested: approvers while it is still waiting
    select x, 'needs_approval'
    from private.staffing_location_people(v_e.organization_id, v_c.location_id, 'shift_swaps', 'admin') x
    where v_e.type = 'shift_claim.requested' and v_c.status = 'requested' and x <> v_c.person_id
    union all
    -- shift_claim.approved / denied: the claimant
    select v_c.person_id, case v_e.type when 'shift_claim.approved' then 'claim_approved' else 'claim_denied' end
    where v_e.type in ('shift_claim.approved', 'shift_claim.denied')
    union all
    -- time_off.requested: approvers over the person while still pending; .cancelled of an approved request too
    select x, case v_e.type when 'time_off.requested' then 'needs_approval' else 'time_off_cancelled' end
    from private.time_off_approvers(v_e.organization_id, v_t.person_id) x
    where (v_e.type = 'time_off.requested' and v_t.status = 'pending')
       or (v_e.type = 'time_off.cancelled' and v_e.payload ->> 'previous_status' = 'approved')
    union all
    -- time_off.decided: the person
    select v_t.person_id, 'time_off_decided' where v_e.type = 'time_off.decided'
  )
  select distinct on (r.person_id) r.person_id, r.reason
  from r
  join public.people p on p.id = r.person_id and p.organization_id = v_e.organization_id and p.archived_at is null
  where private.person_is_active_member(v_e.organization_id, r.person_id)
  order by r.person_id, r.reason;
end;
$$;

revoke all on function
  public.emit_uncovered_shift_events(interval, integer),
  public.worker_shift_for_event(uuid),
  public.worker_shift_event_recipients(uuid)
from public, anon, authenticated;
grant execute on function
  public.emit_uncovered_shift_events(interval, integer),
  public.worker_shift_for_event(uuid),
  public.worker_shift_event_recipients(uuid)
to service_role;
