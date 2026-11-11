-- Phase 2: tasks and workflows.
--
--   task_templates   what a generated task looks like, and who it goes to
--   workflow_rules   "when event X (matching a simple condition) happens, create
--                    a task from template T" (created disabled)
--   tasks            the work itself
--   task_events      append-only history of every change to a task
--
-- Permission levels on the `tasks` module (seeded defaults: staff = edit,
-- manager = admin, admin = admin):
--   view   see tasks at the location that are assigned to you, to one of your
--          job titles there (when no person is assigned), or to nobody
--   edit   also start, complete, reopen (from done) and comment on those tasks,
--          and create a task for yourself or for nobody
--   admin  see and manage every task at the location: create for anyone,
--          assign, cancel, reopen cancelled; manage templates and rules
-- Scope as everywhere else: organization-scope permission covers every
-- location of the organization.
--
-- Job titles only NARROW which tasks a member already permitted at that
-- location sees; they never grant reach to a location or a module.
--
-- Tenants never write these tables' status columns directly: every task change
-- goes through the RPCs below, which write the task_events row and emit the
-- matching outbox event in the same transaction.

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------

-- Does the caller hold >= level on module at organization scope or at ANY
-- location of the organization?
create function private.has_permission_anywhere(
  p_organization_id uuid, p_module_key text, p_min_level public.permission_level)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.has_permission(p_organization_id, null, p_module_key, p_min_level)
      or exists (select 1 from public.locations l
                 where l.organization_id = p_organization_id
                   and l.id in (select public.auth_location_ids())
                   and public.has_permission(p_organization_id, l.id, p_module_key, p_min_level))
$$;

-- (job_title_id, location_id) pairs the caller holds, in organizations where
-- they are a member. A title held "everywhere" (location_id null) expands to
-- every location of that organization. Routing only.
create function private.my_job_title_scopes()
returns table (job_title_id uuid, location_id uuid)
language sql
stable
security definer
set search_path = ''
as $$
  select pjt.job_title_id, pjt.location_id
  from public.person_job_titles pjt
  where pjt.person_id in (select private.my_person_ids()) and pjt.location_id is not null
  union
  select pjt.job_title_id, l.id
  from public.person_job_titles pjt
  join public.locations l on l.organization_id = pjt.organization_id
  where pjt.person_id in (select private.my_person_ids()) and pjt.location_id is null
$$;

-- Generic: BEFORE UPDATE/DELETE trigger for append-only tables.
create function private.tg_append_only()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception '% is append-only (% blocked)', tg_table_name, tg_op using errcode = 'insufficient_privilege';
end;
$$;

revoke all on function private.has_permission_anywhere(uuid, text, public.permission_level) from public, anon, authenticated;
revoke all on function private.my_job_title_scopes() from public, anon, authenticated;
revoke all on function private.tg_append_only() from public, anon, authenticated;
grant execute on function private.has_permission_anywhere(uuid, text, public.permission_level),
                          private.my_job_title_scopes()
  to authenticated, service_role;

-- Event types a workflow rule may react to (the single list; extend it with a
-- migration). task.* events other than task.overdue are excluded on purpose:
-- a rule on task.created could create tasks forever.
create function private.workflow_trigger_types()
returns text[]
language sql
immutable
set search_path = ''
as $$
  select array[
    'booking.confirmed', 'booking.rescheduled', 'booking.cancelled',
    'shift.uncovered',
    'checklist.item_failed', 'checklist.completed',
    'incident.submitted', 'incident.reviewed',
    'task.overdue',
    'notice.published']
$$;

-- Workflow condition, deliberately simple:
--   {}                                          always matches
--   {"all": [ clause, ... ]}                    1-10 clauses, all must match
--   clause = {"field": "<payload key>", "op": "eq", "value": <scalar>}
--          | {"field": "<payload key>", "op": "in", "value": [<scalar>, ... 1-50]}
-- scalar = string (<= 200 chars), number or boolean. Nothing else is accepted.
create function private.validate_workflow_condition(p jsonb)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select p is not null and jsonb_typeof(p) = 'object' and octet_length(p::text) <= 8192
     and (p = '{}'::jsonb or (
       (select array_agg(k) from jsonb_object_keys(p) k) = array['all']
       and jsonb_typeof(p -> 'all') = 'array'
       and jsonb_array_length(p -> 'all') between 1 and 10
       and not exists (
         select 1 from jsonb_array_elements(p -> 'all') c
         where jsonb_typeof(c) <> 'object'
            or (select array_agg(k order by k) from jsonb_object_keys(c) k) <> array['field', 'op', 'value']
            or jsonb_typeof(c -> 'field') <> 'string'
            or (c ->> 'field') !~ '^[a-z][a-z0-9_]{0,62}$'
            or not (
              (c ->> 'op' = 'eq'
               and (jsonb_typeof(c -> 'value') in ('number', 'boolean')
                    or (jsonb_typeof(c -> 'value') = 'string' and char_length(c ->> 'value') <= 200)))
              or (c ->> 'op' = 'in'
                  and jsonb_typeof(c -> 'value') = 'array'
                  and jsonb_array_length(c -> 'value') between 1 and 50
                  and not exists (
                    select 1 from jsonb_array_elements(c -> 'value') v
                    where not (jsonb_typeof(v) in ('number', 'boolean')
                               or (jsonb_typeof(v) = 'string' and char_length(v #>> '{}') <= 200))))))))
$$;

-- Does an event payload satisfy a (valid) condition? JSON equality, so the
-- string "5" does not equal the number 5.
create function private.workflow_condition_matches(p_condition jsonb, p_payload jsonb)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select coalesce(p_condition, '{}'::jsonb) = '{}'::jsonb
      or not exists (
        select 1 from jsonb_array_elements(p_condition -> 'all') c
        where not (
          (c ->> 'op' = 'eq' and (p_payload -> (c ->> 'field')) = (c -> 'value'))
          or (c ->> 'op' = 'in' and exists (
                select 1 from jsonb_array_elements(c -> 'value') v
                where (p_payload -> (c ->> 'field')) = v))))
$$;

revoke all on function private.workflow_trigger_types() from public, anon, authenticated;
revoke all on function private.validate_workflow_condition(jsonb) from public, anon, authenticated;
revoke all on function private.workflow_condition_matches(jsonb, jsonb) from public, anon, authenticated;
-- The two validators back CHECK constraints on workflow_rules, which run with
-- the writer's privileges. They are pure and reveal nothing.
grant execute on function private.workflow_trigger_types(), private.validate_workflow_condition(jsonb)
  to authenticated, service_role;

-- Config read rule for templates and rules: a location row needs tasks =
-- admin there; an organization-wide row (location_id null) is readable by
-- anyone with tasks = admin at organization scope or at any location (they
-- build rules on it), and writable only at organization scope.
create function private.can_read_task_config(p_organization_id uuid, p_location_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select case when p_location_id is not null
              then public.has_permission(p_organization_id, p_location_id, 'tasks', 'admin')
              else private.has_permission_anywhere(p_organization_id, 'tasks', 'admin') end
$$;
revoke all on function private.can_read_task_config(uuid, uuid) from public, anon, authenticated;
grant execute on function private.can_read_task_config(uuid, uuid) to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- task_templates
-- ---------------------------------------------------------------------------
create table public.task_templates (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid,   -- null = usable at every location of the organization
  title text not null check (char_length(btrim(title)) between 1 and 200),
  instructions text check (char_length(instructions) <= 4000),
  default_priority text not null default 'normal' check (default_priority in ('low', 'normal', 'high', 'urgent')),
  -- due = anchor time + offset. Anchor: the event's anchor_at payload field
  -- (e.g. a booking's start), else the event time. Negative = before the
  -- anchor (setup tasks). Null = no due time.
  due_offset_minutes integer check (due_offset_minutes between -525600 and 525600),
  -- who gets the task: nobody, a job title, a specific person, or (Phase 3
  -- placeholder) whoever is on shift at the location, which is unassigned
  -- until the staff schedule exists.
  assign_to text not null default 'none' check (assign_to in ('none', 'job_title', 'person', 'on_shift')),
  assign_job_title_id uuid,
  assign_person_id uuid,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  check ((assign_to = 'job_title') = (assign_job_title_id is not null)),
  check ((assign_to = 'person') = (assign_person_id is not null)),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (assign_job_title_id, organization_id) references public.job_titles (id, organization_id),
  foreign key (assign_person_id, organization_id) references public.people (id, organization_id)
);

create index task_templates_org_location_idx on public.task_templates (organization_id, location_id);
create index task_templates_location_idx on public.task_templates (location_id, organization_id) where location_id is not null;
create index task_templates_job_title_idx on public.task_templates (assign_job_title_id, organization_id)
  where assign_job_title_id is not null;
create index task_templates_person_idx on public.task_templates (assign_person_id, organization_id)
  where assign_person_id is not null;

create trigger task_templates_timestamps before insert or update on public.task_templates
  for each row execute function private.tg_set_timestamps();
create trigger task_templates_immutable before update on public.task_templates
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id');

-- ---------------------------------------------------------------------------
-- workflow_rules
-- ---------------------------------------------------------------------------
create table public.workflow_rules (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid,   -- null = events at every location of the organization
  name text not null check (char_length(btrim(name)) between 1 and 200),
  event_type text not null check (event_type = any (private.workflow_trigger_types())),
  condition jsonb not null default '{}'::jsonb check (private.validate_workflow_condition(condition)),
  task_template_id uuid not null,
  enabled boolean not null default false,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  check (archived_at is null or not enabled),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (task_template_id, organization_id) references public.task_templates (id, organization_id)
);

create index workflow_rules_org_type_idx on public.workflow_rules (organization_id, event_type) where enabled;
create index workflow_rules_location_idx on public.workflow_rules (location_id, organization_id) where location_id is not null;
create index workflow_rules_template_idx on public.workflow_rules (task_template_id, organization_id);

-- BEFORE trigger (runs before RLS WITH CHECK): first refuse non-members with
-- the generic error, then validate only against the caller's own organization.
--   * a new rule is always created disabled (RRP rule)
--   * a location template only serves rules of that same location
--   * an archived template cannot back an enabled rule
create function private.tg_workflow_rules_validate()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_t public.task_templates%rowtype;
begin
  perform private.assert_member_of(new.organization_id);
  if tg_op = 'INSERT' then
    new.enabled := false;
  end if;
  select * into v_t from public.task_templates t
  where t.id = new.task_template_id and t.organization_id = new.organization_id;
  if not found then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if v_t.location_id is not null and new.location_id is distinct from v_t.location_id then
    raise exception 'that task template belongs to a different location' using errcode = 'check_violation';
  end if;
  if new.enabled and v_t.archived_at is not null then
    raise exception 'that task template is archived' using errcode = 'check_violation';
  end if;
  return new;
end;
$$;
revoke all on function private.tg_workflow_rules_validate() from public, anon, authenticated;

create trigger workflow_rules_validate before insert or update on public.workflow_rules
  for each row execute function private.tg_workflow_rules_validate();
create trigger workflow_rules_timestamps before insert or update on public.workflow_rules
  for each row execute function private.tg_set_timestamps();
create trigger workflow_rules_immutable before update on public.workflow_rules
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id');

-- ---------------------------------------------------------------------------
-- tasks
-- ---------------------------------------------------------------------------
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  space_id uuid,
  title text not null check (char_length(btrim(title)) between 1 and 200),
  instructions text check (char_length(instructions) <= 4000),
  status text not null default 'open' check (status in ('open', 'in_progress', 'done', 'cancelled')),
  priority text not null default 'normal' check (priority in ('low', 'normal', 'high', 'urgent')),
  due_at timestamptz,
  assigned_person_id uuid,
  assigned_job_title_id uuid,
  created_by_person_id uuid,           -- null = created by the system (a workflow rule)
  completed_by_person_id uuid,
  completed_at timestamptz,
  cancelled_at timestamptz,
  -- Idempotency key, not a reference: outbox events are purged after their
  -- retention period, tasks are kept. Only create_task_from_event sets it.
  source_event_id uuid,
  source_rule_id uuid,
  task_template_id uuid,
  overdue_emitted_for timestamptz,      -- due_at for which task.overdue was emitted
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  unique (id, organization_id, location_id),
  unique (source_event_id, task_template_id),
  check ((status = 'done') = (completed_at is not null)),
  check ((status = 'cancelled') = (cancelled_at is not null)),
  check (source_event_id is null or (source_rule_id is not null and task_template_id is not null)),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (space_id, organization_id, location_id) references public.spaces (id, organization_id, location_id),
  foreign key (assigned_person_id, organization_id) references public.people (id, organization_id),
  foreign key (assigned_job_title_id, organization_id) references public.job_titles (id, organization_id),
  foreign key (created_by_person_id, organization_id) references public.people (id, organization_id),
  foreign key (completed_by_person_id, organization_id) references public.people (id, organization_id),
  foreign key (source_rule_id, organization_id) references public.workflow_rules (id, organization_id),
  foreign key (task_template_id, organization_id) references public.task_templates (id, organization_id)
);

create index tasks_org_location_status_idx on public.tasks (organization_id, location_id, status);
create index tasks_location_idx on public.tasks (location_id, organization_id);
create index tasks_space_idx on public.tasks (space_id, organization_id, location_id) where space_id is not null;
create index tasks_assigned_person_idx on public.tasks (assigned_person_id, organization_id) where assigned_person_id is not null;
create index tasks_assigned_title_idx on public.tasks (assigned_job_title_id, organization_id) where assigned_job_title_id is not null;
create index tasks_created_by_idx on public.tasks (created_by_person_id, organization_id) where created_by_person_id is not null;
create index tasks_completed_by_idx on public.tasks (completed_by_person_id, organization_id) where completed_by_person_id is not null;
create index tasks_rule_idx on public.tasks (source_rule_id, organization_id) where source_rule_id is not null;
create index tasks_template_idx on public.tasks (task_template_id, organization_id) where task_template_id is not null;
create index tasks_overdue_idx on public.tasks (due_at) where status in ('open', 'in_progress') and due_at is not null;

create trigger tasks_timestamps before insert or update on public.tasks
  for each row execute function private.tg_set_timestamps();
create trigger tasks_immutable before update on public.tasks
  for each row execute function private.tg_immutable_columns(
    'id', 'organization_id', 'location_id', 'created_by_person_id',
    'source_event_id', 'source_rule_id', 'task_template_id');

-- ---------------------------------------------------------------------------
-- task_events (append-only)
-- ---------------------------------------------------------------------------
create table public.task_events (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  task_id uuid not null,
  kind text not null check (kind in ('created', 'assigned', 'started', 'completed', 'reopened',
                                     'cancelled', 'commented', 'escalated')),
  actor_person_id uuid,                 -- null = the system
  from_status text,
  to_status text,
  assigned_person_id uuid,              -- 'assigned': the new assignee (both null = unassigned)
  assigned_job_title_id uuid,
  body text check (char_length(body) <= 2000),   -- comment, completion note, reason
  source_event_id uuid,                 -- the outbox event that caused it (system rows)
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  foreign key (task_id, organization_id, location_id)
    references public.tasks (id, organization_id, location_id) on delete cascade,
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (actor_person_id, organization_id) references public.people (id, organization_id),
  foreign key (assigned_person_id, organization_id) references public.people (id, organization_id),
  foreign key (assigned_job_title_id, organization_id) references public.job_titles (id, organization_id)
);

create index task_events_task_idx on public.task_events (organization_id, task_id, location_id, created_at);
create index task_events_location_idx on public.task_events (location_id, organization_id);
create index task_events_actor_idx on public.task_events (actor_person_id, organization_id) where actor_person_id is not null;
create index task_events_assigned_person_idx on public.task_events (assigned_person_id, organization_id) where assigned_person_id is not null;
create index task_events_assigned_title_idx on public.task_events (assigned_job_title_id, organization_id) where assigned_job_title_id is not null;

create trigger task_events_timestamps before insert on public.task_events
  for each row execute function private.tg_set_timestamps();
create trigger task_events_append_only before update on public.task_events
  for each row execute function private.tg_append_only();
-- (tg_immutable_columns too, so the catalog's organization_id guard holds.)
create trigger task_events_immutable before update on public.task_events
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'task_id');

-- Audit. Free text (instructions, comments) is redacted: the audit row keeps
-- that it changed, the text itself stays in the tables.
do $$
begin
  perform private.enable_audit('public.task_templates', 'id', array['instructions']);
  perform private.enable_audit('public.workflow_rules');
  perform private.enable_audit('public.tasks', 'id', array['instructions']);
  perform private.enable_audit('public.task_events', 'id', array['body']);
end;
$$;

-- ---------------------------------------------------------------------------
-- Task access (one implementation, used by the policy and every RPC)
-- ---------------------------------------------------------------------------
create function private.can_see_task(
  p_organization_id uuid, p_location_id uuid, p_assigned_person_id uuid, p_assigned_job_title_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  -- Never NULL (a NULL here would read as "allowed" in an IF NOT ... check).
  select coalesce(
    public.has_permission(p_organization_id, p_location_id, 'tasks', 'admin')
    or (public.has_permission(p_organization_id, p_location_id, 'tasks', 'view')
        and (p_assigned_person_id is not distinct from public.current_person_id(p_organization_id)
             and p_assigned_person_id is not null
             or (p_assigned_person_id is null
                 and (p_assigned_job_title_id is null
                      or exists (select 1 from private.my_job_title_scopes() j
                                 where j.job_title_id = p_assigned_job_title_id
                                   and j.location_id = p_location_id))))),
    false)
$$;
revoke all on function private.can_see_task(uuid, uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function private.can_see_task(uuid, uuid, uuid, uuid) to authenticated, service_role;

-- May p_person_id be assigned work at this location? Not archived, an active
-- member covering the location (an organization-scope assignment or one at
-- that location), and visible to the caller (skipped for service code).
create function private.valid_task_assignee(p_organization_id uuid, p_location_id uuid, p_person_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(p_person_id is null or (
    private.person_effective_level(p_organization_id, p_person_id, p_location_id, 'tasks') is not null
    and ((select auth.uid()) is null
         or public.is_platform_admin()
         or p_person_id in (select private.visible_person_ids()))), false)
$$;
revoke all on function private.valid_task_assignee(uuid, uuid, uuid) from public, anon, authenticated;

-- Lock and return a task the caller can see (and work on, at >= p_level), or
-- raise the uniform 'not allowed' (also for a task that does not exist or
-- belongs to another organization).
create function private.lock_task_for_caller(p_task_id uuid, p_level public.permission_level)
returns public.tasks
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_t from public.tasks t where t.id = p_task_id for update;
  if not found
     or private.can_see_task(v_t.organization_id, v_t.location_id, v_t.assigned_person_id, v_t.assigned_job_title_id) is not true
     or public.has_permission(v_t.organization_id, v_t.location_id, 'tasks', p_level) is not true then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  return v_t;
end;
$$;
revoke all on function private.lock_task_for_caller(uuid, public.permission_level) from public, anon, authenticated;

-- Write the history row and the outbox event for a task change.
create function private.record_task_change(
  p_task public.tasks, p_kind text, p_from_status text, p_body text,
  p_source_event_id uuid default null, p_correlation_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_actor uuid := case when (select auth.uid()) is not null then public.current_person_id(p_task.organization_id) end;
  v_te uuid;
begin
  insert into public.task_events (
    organization_id, location_id, task_id, kind, actor_person_id, from_status, to_status,
    assigned_person_id, assigned_job_title_id, body, source_event_id)
  values (
    p_task.organization_id, p_task.location_id, p_task.id, p_kind, v_actor, p_from_status, p_task.status,
    case when p_kind in ('created', 'assigned') then p_task.assigned_person_id end,
    case when p_kind in ('created', 'assigned') then p_task.assigned_job_title_id end,
    p_body, p_source_event_id)
  returning id into v_te;

  perform private.emit_event(
    p_task.organization_id, p_task.location_id, 'task.' || p_kind, 'tasks', p_task.id,
    jsonb_build_object(
      'task_id', p_task.id,
      'task_event_id', v_te,
      'location_id', p_task.location_id,
      'status', p_task.status,
      'priority', p_task.priority,
      'assigned_person_id', p_task.assigned_person_id,
      'assigned_job_title_id', p_task.assigned_job_title_id,
      'actor_person_id', v_actor,
      'due_at', p_task.due_at),
    1, p_correlation_id);
  return v_te;
end;
$$;
revoke all on function private.record_task_change(public.tasks, text, text, text, uuid, uuid) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Task RPCs (authenticated). All raise 42501 'not allowed' without saying
-- whether the task exists; state errors (only for tasks the caller can see)
-- are 22023.
-- ---------------------------------------------------------------------------

create function public.create_task(
  p_organization_id uuid,
  p_location_id uuid,
  p_title text,
  p_instructions text default null,
  p_due_at timestamptz default null,
  p_priority text default 'normal',
  p_space_id uuid default null,
  p_assigned_person_id uuid default null,
  p_assigned_job_title_id uuid default null)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_t public.tasks%rowtype;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if p_organization_id is null or p_location_id is null
     or not public.has_permission(p_organization_id, p_location_id, 'tasks', 'edit') then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  v_me := public.current_person_id(p_organization_id);
  if not public.has_permission(p_organization_id, p_location_id, 'tasks', 'admin')
     and (p_assigned_job_title_id is not null
          or (p_assigned_person_id is not null and p_assigned_person_id is distinct from v_me)) then
    raise exception 'only a manager can assign tasks to others' using errcode = 'insufficient_privilege';
  end if;
  if not private.valid_task_assignee(p_organization_id, p_location_id, p_assigned_person_id) then
    raise exception 'that person cannot be given tasks at this location' using errcode = 'invalid_parameter_value';
  end if;
  if p_assigned_job_title_id is not null and not exists (
       select 1 from public.job_titles j
       where j.id = p_assigned_job_title_id and j.organization_id = p_organization_id and j.archived_at is null) then
    raise exception 'unknown job title' using errcode = 'invalid_parameter_value';
  end if;
  if p_space_id is not null and not exists (
       select 1 from public.spaces s
       where s.id = p_space_id and s.organization_id = p_organization_id and s.location_id = p_location_id) then
    raise exception 'unknown space at this location' using errcode = 'invalid_parameter_value';
  end if;
  if p_priority is null or p_priority not in ('low', 'normal', 'high', 'urgent') then
    raise exception 'invalid priority' using errcode = 'invalid_parameter_value';
  end if;

  insert into public.tasks (
    organization_id, location_id, space_id, title, instructions, priority, due_at,
    assigned_person_id, assigned_job_title_id, created_by_person_id)
  values (
    p_organization_id, p_location_id, p_space_id, btrim(p_title), nullif(btrim(p_instructions), ''),
    p_priority, p_due_at, p_assigned_person_id, p_assigned_job_title_id, v_me)
  returning * into v_t;

  perform private.record_task_change(v_t, 'created', null, null);
  return v_t.id;
end;
$$;

-- open -> in_progress. An unassigned task (or one routed to a job title) is
-- claimed by the person who starts it.
create function public.start_task(p_task_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
begin
  if v_t.status <> 'open' then
    raise exception 'only an open task can be started' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set status = 'in_progress',
      assigned_person_id = coalesce(t.assigned_person_id, public.current_person_id(t.organization_id))
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'started', 'open', null);
end;
$$;

-- open | in_progress -> done.
create function public.complete_task(p_task_id uuid, p_note text default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
  v_from text := v_t.status;
begin
  if v_t.status not in ('open', 'in_progress') then
    raise exception 'this task is already closed' using errcode = 'invalid_parameter_value';
  end if;
  if char_length(p_note) > 2000 then
    raise exception 'note is too long' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set status = 'done', completed_at = now(),
      completed_by_person_id = public.current_person_id(t.organization_id),
      assigned_person_id = coalesce(t.assigned_person_id, public.current_person_id(t.organization_id))
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'completed', v_from, nullif(btrim(p_note), ''));
end;
$$;

-- done -> open (edit); cancelled -> open (admin).
create function public.reopen_task(p_task_id uuid, p_reason text default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
  v_from text := v_t.status;
begin
  if v_t.status not in ('done', 'cancelled') then
    raise exception 'only a closed task can be reopened' using errcode = 'invalid_parameter_value';
  end if;
  if v_t.status = 'cancelled' and not public.has_permission(v_t.organization_id, v_t.location_id, 'tasks', 'admin') then
    raise exception 'only a manager can reopen a cancelled task' using errcode = 'insufficient_privilege';
  end if;
  if char_length(p_reason) > 2000 then
    raise exception 'reason is too long' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set status = 'open', completed_at = null, completed_by_person_id = null, cancelled_at = null
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'reopened', v_from, nullif(btrim(p_reason), ''));
end;
$$;

-- Assign to a person and/or a job title (both null = unassign). Manager only.
create function public.assign_task(p_task_id uuid, p_person_id uuid, p_job_title_id uuid)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'admin');
begin
  if v_t.status not in ('open', 'in_progress') then
    raise exception 'a closed task cannot be reassigned' using errcode = 'invalid_parameter_value';
  end if;
  if not private.valid_task_assignee(v_t.organization_id, v_t.location_id, p_person_id) then
    raise exception 'that person cannot be given tasks at this location' using errcode = 'invalid_parameter_value';
  end if;
  if p_job_title_id is not null and not exists (
       select 1 from public.job_titles j
       where j.id = p_job_title_id and j.organization_id = v_t.organization_id and j.archived_at is null) then
    raise exception 'unknown job title' using errcode = 'invalid_parameter_value';
  end if;
  if v_t.assigned_person_id is not distinct from p_person_id
     and v_t.assigned_job_title_id is not distinct from p_job_title_id then
    raise exception 'nothing to change' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t
  set assigned_person_id = p_person_id, assigned_job_title_id = p_job_title_id
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'assigned', v_t.status, null);
end;
$$;

-- open | in_progress -> cancelled. Manager only.
create function public.cancel_task(p_task_id uuid, p_reason text default null)
returns void
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'admin');
  v_from text := v_t.status;
begin
  if v_t.status not in ('open', 'in_progress') then
    raise exception 'this task is already closed' using errcode = 'invalid_parameter_value';
  end if;
  if char_length(p_reason) > 2000 then
    raise exception 'reason is too long' using errcode = 'invalid_parameter_value';
  end if;
  update public.tasks t set status = 'cancelled', cancelled_at = now()
  where t.id = v_t.id
  returning * into v_t;
  perform private.record_task_change(v_t, 'cancelled', v_from, nullif(btrim(p_reason), ''));
end;
$$;

-- Comment on a task the caller can work on. Returns the task_events id.
create function public.add_task_comment(p_task_id uuid, p_body text)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype := private.lock_task_for_caller(p_task_id, 'edit');
begin
  if p_body is null or char_length(btrim(p_body)) not between 1 and 2000 then
    raise exception 'a comment needs 1 to 2000 characters' using errcode = 'invalid_parameter_value';
  end if;
  return private.record_task_change(v_t, 'commented', v_t.status, btrim(p_body));
end;
$$;

-- ---------------------------------------------------------------------------
-- Worker functions (service_role only)
-- ---------------------------------------------------------------------------

-- Enabled, non-archived rules that apply to this event: same organization,
-- same type, organization-wide or at the event's location, template not
-- archived, condition matches the payload.
create function public.match_workflow_rules(p_event_id uuid)
returns table (rule_id uuid, task_template_id uuid)
language sql
stable
security definer
set search_path = ''
as $$
  select r.id, r.task_template_id
  from public.outbox_events e
  join public.workflow_rules r on r.organization_id = e.organization_id and r.event_type = e.type
  join public.task_templates t on t.id = r.task_template_id and t.organization_id = r.organization_id
  where e.id = p_event_id
    and (select auth.uid()) is null
    and r.enabled and r.archived_at is null and t.archived_at is null
    and (r.location_id is null or r.location_id = e.location_id)
    and (t.location_id is null or t.location_id = e.location_id)
    and e.location_id is not null
    and private.workflow_condition_matches(r.condition, e.payload)
  order by r.id
$$;

-- Create the task a rule asks for, at most once per (event, template).
-- Returns the task id: the new one, or the existing one when this event
-- already produced a task from this template (a retry, or two rules sharing a
-- template). Returns null when the rule no longer applies to the event
-- (disabled, archived, other type/location, condition no longer matches).
create function public.create_task_from_event(p_event_id uuid, p_rule_id uuid)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_e public.outbox_events%rowtype;
  v_r public.workflow_rules%rowtype;
  v_tpl public.task_templates%rowtype;
  v_anchor timestamptz;
  v_space uuid;
  v_person uuid;
  v_t public.tasks%rowtype;
begin
  perform private.assert_service_caller();
  select * into v_e from public.outbox_events e where e.id = p_event_id;
  if not found then
    raise exception 'no such event' using errcode = 'invalid_parameter_value';
  end if;
  if not exists (select 1 from public.match_workflow_rules(p_event_id) m where m.rule_id = p_rule_id) then
    return null;
  end if;
  select * into v_r from public.workflow_rules r where r.id = p_rule_id;
  select * into v_tpl from public.task_templates t where t.id = v_r.task_template_id;

  -- Fast path for a retry.
  select * into v_t from public.tasks t where t.source_event_id = v_e.id and t.task_template_id = v_tpl.id;
  if found then
    return v_t.id;
  end if;

  begin
    v_anchor := (v_e.payload ->> 'anchor_at')::timestamptz;
  exception when others then
    v_anchor := null;
  end;
  v_anchor := coalesce(v_anchor, v_e.created_at);

  begin
    v_space := (v_e.payload ->> 'space_id')::uuid;
  exception when others then
    v_space := null;
  end;
  if v_space is not null and not exists (
       select 1 from public.spaces s
       where s.id = v_space and s.organization_id = v_e.organization_id and s.location_id = v_e.location_id) then
    v_space := null;
  end if;

  v_person := case when v_tpl.assign_to = 'person'
                        and private.valid_task_assignee(v_e.organization_id, v_e.location_id, v_tpl.assign_person_id)
                   then v_tpl.assign_person_id end;

  insert into public.tasks (
    organization_id, location_id, space_id, title, instructions, priority, due_at,
    assigned_person_id, assigned_job_title_id, source_event_id, source_rule_id, task_template_id)
  values (
    v_e.organization_id, v_e.location_id, v_space, v_tpl.title, v_tpl.instructions, v_tpl.default_priority,
    case when v_tpl.due_offset_minutes is not null then v_anchor + make_interval(mins => v_tpl.due_offset_minutes) end,
    v_person,
    case when v_tpl.assign_to = 'job_title' then v_tpl.assign_job_title_id end,
    v_e.id, v_r.id, v_tpl.id)
  on conflict (source_event_id, task_template_id) do nothing
  returning * into v_t;

  if v_t.id is null then
    -- A concurrent run inserted it first.
    select t.id into v_t.id from public.tasks t where t.source_event_id = v_e.id and t.task_template_id = v_tpl.id;
    return v_t.id;
  end if;

  perform private.record_task_change(v_t, 'created', null, null, v_e.id, v_e.correlation_id);
  return v_t.id;
end;
$$;

-- Emit task.overdue once per task per due time, for open / in-progress tasks
-- past due. Safe to run concurrently (SKIP LOCKED) and repeatedly. Returns the
-- number of events emitted. A task whose due_at later changes becomes eligible
-- again for its new due time.
create function public.emit_overdue_task_events(p_limit integer default 500)
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_t public.tasks%rowtype;
  v_n integer := 0;
begin
  perform private.assert_service_caller();
  if p_limit is null or p_limit not between 1 and 5000 then
    raise exception 'invalid limit' using errcode = 'invalid_parameter_value';
  end if;
  for v_t in
    select * from public.tasks t
    where t.status in ('open', 'in_progress') and t.due_at < now()
      and t.overdue_emitted_for is distinct from t.due_at
    order by t.due_at
    limit p_limit
    for update skip locked
  loop
    update public.tasks t set overdue_emitted_for = t.due_at where t.id = v_t.id;
    perform private.emit_event(
      v_t.organization_id, v_t.location_id, 'task.overdue', 'tasks', v_t.id,
      jsonb_build_object(
        'task_id', v_t.id, 'location_id', v_t.location_id, 'due_at', v_t.due_at,
        'priority', v_t.priority, 'space_id', v_t.space_id,
        'assigned_person_id', v_t.assigned_person_id, 'assigned_job_title_id', v_t.assigned_job_title_id));
    v_n := v_n + 1;
  end loop;
  return v_n;
end;
$$;

revoke all on function
  public.create_task(uuid, uuid, text, text, timestamptz, text, uuid, uuid, uuid),
  public.start_task(uuid),
  public.complete_task(uuid, text),
  public.reopen_task(uuid, text),
  public.assign_task(uuid, uuid, uuid),
  public.cancel_task(uuid, text),
  public.add_task_comment(uuid, text),
  public.match_workflow_rules(uuid),
  public.create_task_from_event(uuid, uuid),
  public.emit_overdue_task_events(integer)
from public, anon, authenticated;
grant execute on function
  public.create_task(uuid, uuid, text, text, timestamptz, text, uuid, uuid, uuid),
  public.start_task(uuid),
  public.complete_task(uuid, text),
  public.reopen_task(uuid, text),
  public.assign_task(uuid, uuid, uuid),
  public.cancel_task(uuid, text),
  public.add_task_comment(uuid, text)
to authenticated, service_role;
grant execute on function
  public.match_workflow_rules(uuid),
  public.create_task_from_event(uuid, uuid),
  public.emit_overdue_task_events(integer)
to service_role;

-- ---------------------------------------------------------------------------
-- RLS, policies, grants
-- ---------------------------------------------------------------------------
alter table public.task_templates enable row level security;
alter table public.workflow_rules enable row level security;
alter table public.tasks enable row level security;
alter table public.task_events enable row level security;

create policy task_templates_select on public.task_templates for select to authenticated
  using (private.can_read_task_config(organization_id, location_id));
create policy task_templates_insert on public.task_templates for insert to authenticated
  with check (public.has_permission(organization_id, location_id, 'tasks', 'admin')
              and (assign_person_id is null or (select public.is_platform_admin())
                   or assign_person_id in (select private.visible_person_ids())));
create policy task_templates_update on public.task_templates for update to authenticated
  using (public.has_permission(organization_id, location_id, 'tasks', 'admin'))
  with check (public.has_permission(organization_id, location_id, 'tasks', 'admin')
              and (assign_person_id is null or (select public.is_platform_admin())
                   or assign_person_id in (select private.visible_person_ids())));

create policy workflow_rules_select on public.workflow_rules for select to authenticated
  using (private.can_read_task_config(organization_id, location_id));
create policy workflow_rules_insert on public.workflow_rules for insert to authenticated
  with check (public.has_permission(organization_id, location_id, 'tasks', 'admin'));
create policy workflow_rules_update on public.workflow_rules for update to authenticated
  using (public.has_permission(organization_id, location_id, 'tasks', 'admin'))
  with check (public.has_permission(organization_id, location_id, 'tasks', 'admin'));

create policy tasks_select on public.tasks for select to authenticated
  using (private.can_see_task(organization_id, location_id, assigned_person_id, assigned_job_title_id));

create policy task_events_select on public.task_events for select to authenticated
  using (task_id in (select t.id from public.tasks t));

revoke all on table public.task_templates, public.workflow_rules, public.tasks, public.task_events
  from public, anon, authenticated, service_role;

grant select on table public.task_templates, public.workflow_rules, public.tasks, public.task_events to authenticated;
grant insert on public.task_templates to authenticated;
grant update (title, instructions, default_priority, due_offset_minutes, assign_to, assign_job_title_id,
              assign_person_id, archived_at)
  on public.task_templates to authenticated;
grant insert on public.workflow_rules to authenticated;
grant update (name, event_type, condition, task_template_id, enabled, archived_at)
  on public.workflow_rules to authenticated;
-- tasks / task_events: no tenant writes at all; the RPCs above are the only path.

-- service_role: configuration tables like Phase 1; tasks and history only
-- through the functions (so the worker cannot skip the history row and event).
grant select, insert, update, delete on table public.task_templates, public.workflow_rules to service_role;
grant select on table public.tasks, public.task_events to service_role;
