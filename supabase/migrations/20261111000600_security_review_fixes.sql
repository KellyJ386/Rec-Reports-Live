-- Security review fixes (F1, F2, F5, F6, F8, F9, F10, L6) plus two admin RPCs:
-- public.person_effective_permission and public.replace_role_assignment.
-- Earlier migrations are committed; everything here replaces functions and
-- policies in place (same signatures, so existing grants are kept) or adds new
-- objects.

-- ===========================================================================
-- F10 + shared permission core
-- ===========================================================================

-- Does the scope exist? location null = the organization exists; otherwise the
-- location exists AND belongs to that organization. Internal only.
create function private.scope_exists(p_organization_id uuid, p_location_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when p_organization_id is null then false
    when p_location_id is null then exists (select 1 from public.organizations o where o.id = p_organization_id)
    else exists (select 1 from public.locations l where l.id = p_location_id and l.organization_id = p_organization_id)
  end
$$;

-- THE permission computation, for any person. Used by effective_permission
-- (the caller) and person_effective_permission (someone else), so the two can
-- never drift. Returns NULL when the person is not a member in that scope:
--   membership in scope = account not disabled, person not archived, and an
--   assignment on a non-archived role that is organization scoped, or at
--   p_location_id on a non-archived location.
-- Then: override at the location > org-wide override > highest role default > 'none'.
-- A person whose account belongs to a platform admin gets 'admin' (as the
-- caller-side platform check does). Internal only.
create function private.person_effective_level(
  p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text)
returns public.permission_level
language sql
stable
security definer
set search_path = ''
as $$
  with covering as (
    select ra.role_id
    from public.role_assignments ra
    join public.people p on p.id = ra.person_id and p.organization_id = ra.organization_id
    join public.accounts a on a.person_id = p.id and a.organization_id = p.organization_id
    join public.roles r on r.id = ra.role_id
    left join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
    where ra.person_id = p_person_id
      and ra.organization_id = p_organization_id
      and a.disabled_at is null
      and p.archived_at is null
      and r.archived_at is null
      and (ra.location_id is null or (ra.location_id = p_location_id and l.archived_at is null))
  )
  select case
    when p_person_id is null or not private.scope_exists(p_organization_id, p_location_id) then null
    when exists (
      select 1 from public.accounts a
      join public.platform_admins pa on pa.user_id = a.user_id
      where a.person_id = p_person_id and a.organization_id = p_organization_id
    ) then 'admin'::public.permission_level
    when not exists (select 1 from covering) then null
    else coalesce(
      (select up.level from public.user_permissions up
        where up.organization_id = p_organization_id and up.person_id = p_person_id
          and up.module_key = p_module_key and up.location_id = p_location_id),
      (select up.level from public.user_permissions up
        where up.organization_id = p_organization_id and up.person_id = p_person_id
          and up.module_key = p_module_key and up.location_id is null),
      (select max(d.level) from public.role_default_permissions d
        where d.module_key = p_module_key and d.role_id in (select c.role_id from covering c)),
      'none'::public.permission_level)
  end
$$;

revoke all on function private.scope_exists(uuid, uuid) from public, anon, authenticated;
revoke all on function private.person_effective_level(uuid, uuid, uuid, text) from public, anon, authenticated;

-- Same signatures as 000300; grants are kept.
create or replace function public.effective_permission(p_organization_id uuid, p_location_id uuid, p_module_key text)
returns public.permission_level
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when not private.scope_exists(p_organization_id, p_location_id) then 'none'::public.permission_level
    when public.is_platform_admin() then 'admin'::public.permission_level
    else coalesce(
      private.person_effective_level(p_organization_id, public.current_person_id(p_organization_id), p_location_id, p_module_key),
      'none'::public.permission_level)
  end
$$;

-- False for a scope that does not exist and for anyone who is not a member in
-- that scope, whatever p_min_level is (so 'none' is no longer true for strangers).
create or replace function public.has_permission(
  p_organization_id uuid, p_location_id uuid, p_module_key text, p_min_level public.permission_level)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when not private.scope_exists(p_organization_id, p_location_id) then false
    when public.is_platform_admin() then true
    else coalesce(
      private.person_effective_level(p_organization_id, public.current_person_id(p_organization_id), p_location_id, p_module_key)
        >= p_min_level,
      false)
  end
$$;

create or replace function public.has_role(p_organization_id uuid, p_location_id uuid, p_role_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.scope_exists(p_organization_id, p_location_id)
     and (public.is_platform_admin() or exists (
       select 1 from private.my_assignments() m
       where m.organization_id = p_organization_id
         and m.role_key = p_role_key
         and (m.location_id is null or m.location_id = p_location_id)))
$$;

create or replace function public.actor_rank(p_organization_id uuid, p_location_id uuid)
returns integer
language sql
stable
security definer
set search_path = ''
as $$
  select case
    when not private.scope_exists(p_organization_id, p_location_id) then 0
    when public.is_platform_admin() then 100
    else coalesce((
      select max(m.rank) from private.my_assignments() m
      where m.organization_id = p_organization_id
        and (m.location_id is null or m.location_id = p_location_id)), 0)
  end
$$;

-- ===========================================================================
-- F1 + F2: role assignment rules
-- ===========================================================================

-- Core grant/remove rule, WITHOUT the visibility requirement. Used directly only
-- by create_person_with_assignment (for the person it has just created).
--   caller is not the target; target is in the org; role is a system role or a
--   custom role of the org; caller has people_roles = admin in exactly that
--   scope; caller's rank in scope > target's highest rank and > the role's
--   effective rank; and (F1) for every default of the role, the caller's own
--   effective level for that module in that scope is >= the default.
create function private.can_grant_role(
  p_organization_id uuid, p_person_id uuid, p_role_id uuid, p_location_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_actor_rank integer;
  v_role_rank integer;
begin
  if public.is_platform_admin() then
    return true;
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or v_me = p_person_id then
    return false;
  end if;
  if not exists (select 1 from public.people p where p.id = p_person_id and p.organization_id = p_organization_id) then
    return false;
  end if;
  select r.rank + case when p_location_id is null then 10 else 0 end into v_role_rank
  from public.roles r
  where r.id = p_role_id and (r.organization_id is null or r.organization_id = p_organization_id);
  if v_role_rank is null then
    return false;
  end if;
  if not public.has_permission(p_organization_id, p_location_id, 'people_roles', 'admin') then
    return false;
  end if;
  v_actor_rank := public.actor_rank(p_organization_id, p_location_id);
  if not (v_actor_rank > private.person_max_rank(p_person_id) and v_actor_rank > v_role_rank) then
    return false;
  end if;
  return not exists (
    select 1 from public.role_default_permissions d
    where d.role_id = p_role_id
      and d.level > public.effective_permission(p_organization_id, p_location_id, d.module_key));
end;
$$;
revoke all on function private.can_grant_role(uuid, uuid, uuid, uuid) from public, anon, authenticated;

-- Policy rule for inserting or deleting a role_assignments row (same signature
-- as 000300). F2: the target must be visible to the caller (no more "or has no
-- assignments yet" branch), and an archived target needs an organization-scope
-- people_roles admin.
create or replace function private.can_manage_role_assignment(
  p_organization_id uuid, p_person_id uuid, p_role_id uuid, p_location_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if public.is_platform_admin() then
    return true;
  end if;
  if not (p_person_id in (select private.visible_person_ids())) then
    return false;
  end if;
  if exists (select 1 from public.people p where p.id = p_person_id and p.archived_at is not null)
     and not public.has_permission(p_organization_id, null, 'people_roles', 'admin') then
    return false;
  end if;
  return private.can_grant_role(p_organization_id, p_person_id, p_role_id, p_location_id);
end;
$$;

-- F2: archived targets need an organization-scope people_roles admin (so a
-- location admin cannot un-archive someone). Otherwise unchanged from 000300.
create or replace function private.can_manage_person(p_organization_id uuid, p_person_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_me uuid;
  v_target_rank integer;
begin
  if public.is_platform_admin() then
    return true;
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or v_me = p_person_id then
    return false;
  end if;
  if not exists (select 1 from public.people p where p.id = p_person_id and p.organization_id = p_organization_id) then
    return false;
  end if;
  if exists (select 1 from public.people p where p.id = p_person_id and p.archived_at is not null)
     and not public.has_permission(p_organization_id, null, 'people_roles', 'admin') then
    return false;
  end if;
  v_target_rank := private.person_max_rank(p_person_id);
  if public.has_permission(p_organization_id, null, 'people_roles', 'admin')
     and public.actor_rank(p_organization_id, null) > v_target_rank then
    return true;
  end if;
  return exists (
    select 1 from public.role_assignments ra
    where ra.person_id = p_person_id
      and ra.organization_id = p_organization_id
      and ra.location_id is not null
      and public.has_permission(p_organization_id, ra.location_id, 'people_roles', 'admin')
      and public.actor_rank(p_organization_id, ra.location_id) > v_target_rank
  );
end;
$$;

create or replace function private.can_manage_user_permission(
  p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text, p_level public.permission_level)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_me uuid;
begin
  if public.is_platform_admin() then
    return true;
  end if;
  v_me := public.current_person_id(p_organization_id);
  if v_me is null or v_me = p_person_id then
    return false;
  end if;
  if not exists (select 1 from public.people p where p.id = p_person_id and p.organization_id = p_organization_id) then
    return false;
  end if;
  if exists (select 1 from public.people p where p.id = p_person_id and p.archived_at is not null)
     and not public.has_permission(p_organization_id, null, 'people_roles', 'admin') then
    return false;
  end if;
  if not public.has_permission(p_organization_id, p_location_id, 'people_roles', 'admin') then
    return false;
  end if;
  if p_person_id not in (select private.visible_person_ids()) then
    return false;
  end if;
  if public.actor_rank(p_organization_id, p_location_id) <= private.person_max_rank(p_person_id) then
    return false;
  end if;
  return p_level is null
      or public.effective_permission(p_organization_id, p_location_id, p_module_key) >= p_level;
end;
$$;

-- F1 mirror: defaults of a custom role can only be set up to the caller's own
-- organization-scope level for that module (an org admin with a lowered
-- override cannot mint a role that out-ranks them).
drop policy role_default_permissions_insert on public.role_default_permissions;
drop policy role_default_permissions_update on public.role_default_permissions;
create policy role_default_permissions_insert on public.role_default_permissions for insert to authenticated
  with check (organization_id is not null
              and public.has_role(organization_id, null, 'admin')
              and public.effective_permission(organization_id, null, module_key) >= level);
create policy role_default_permissions_update on public.role_default_permissions for update to authenticated
  using (organization_id is not null and public.has_role(organization_id, null, 'admin'))
  with check (organization_id is not null
              and public.has_role(organization_id, null, 'admin')
              and public.effective_permission(organization_id, null, module_key) >= level);

-- F2: direct inserts into people only by organization-scope people_roles
-- admins (they see every person, unassigned ones included). Location-scoped
-- admins onboard through create_person_with_assignment.
drop policy people_insert on public.people;
create policy people_insert on public.people for insert to authenticated
  with check (public.has_permission(organization_id, null, 'people_roles', 'admin'));

-- create_person_with_assignment: same signature; the assignment check now uses
-- the core rule (the new person is not yet visible to a location admin, and it
-- is the only person this call can attach a first assignment to).
create or replace function public.create_person_with_assignment(
  p_organization_id uuid,
  p_first_name text,
  p_last_name text,
  p_role_id uuid,
  p_location_id uuid,
  p_preferred_name text default null,
  p_email text default null,
  p_phone text default null,
  p_employee_number text default null
)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_person_id uuid := gen_random_uuid();
begin
  if p_organization_id is null or p_role_id is null then
    raise exception 'organization and role are required' using errcode = 'invalid_parameter_value';
  end if;
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if not private.can_create_person(p_organization_id) then
    raise exception 'not allowed to add people here' using errcode = 'insufficient_privilege';
  end if;

  insert into public.people (id, organization_id, first_name, last_name, preferred_name, email, phone, employee_number)
  values (
    v_person_id, p_organization_id,
    btrim(p_first_name), btrim(p_last_name),
    nullif(btrim(p_preferred_name), ''),
    nullif(btrim(p_email), ''),
    nullif(btrim(p_phone), ''),
    nullif(btrim(p_employee_number), ''));

  if not private.can_grant_role(p_organization_id, v_person_id, p_role_id, p_location_id) then
    raise exception 'not allowed to give that role in that scope' using errcode = 'insufficient_privilege';
  end if;

  insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (p_organization_id, v_person_id, p_role_id, p_location_id);

  return v_person_id;
end;
$$;

-- A person's LAST role assignment can be removed only by an organization-scope
-- people_roles admin (or platform admin / service code without a user JWT).
-- Otherwise a location admin could make a person invisible to every
-- location-scoped user. Location admins offboard by archiving the person.
-- Fires at end of statement, so multi-row deletes and replace_role_assignment
-- (insert new, then delete old) are judged on the final state.
create function private.tg_role_assignments_keep_last()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is not null
     and exists (select 1 from public.people p where p.id = old.person_id)
     and not exists (select 1 from public.role_assignments ra where ra.person_id = old.person_id)
     and not public.has_permission(old.organization_id, null, 'people_roles', 'admin') then
    raise exception 'only an organization admin can remove a person''s last role; archive the person instead'
      using errcode = 'insufficient_privilege';
  end if;
  return null;
end;
$$;
revoke all on function private.tg_role_assignments_keep_last() from public, anon, authenticated;

create trigger role_assignments_keep_last after delete on public.role_assignments
  for each row execute function private.tg_role_assignments_keep_last();

-- ===========================================================================
-- F5: archiving/restoring a location needs an organization-scope admin.
-- ===========================================================================
create function private.tg_locations_archive_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.archived_at is distinct from old.archived_at
     and (select auth.uid()) is not null
     and not public.has_role(new.organization_id, null, 'admin') then
    raise exception 'only an organization admin can archive or restore a location'
      using errcode = 'insufficient_privilege';
  end if;
  return new;
end;
$$;
revoke all on function private.tg_locations_archive_guard() from public, anon, authenticated;

create trigger locations_archive_guard before update of archived_at on public.locations
  for each row execute function private.tg_locations_archive_guard();

-- ===========================================================================
-- F6: BEFORE triggers must not reveal anything about rows the caller cannot see.
-- BEFORE triggers run before RLS WITH CHECK, so each one first refuses a
-- signed-in caller who is not a member of the row's organization, with the same
-- generic error, and never names keys or other rows.
-- ===========================================================================
create function private.assert_member_of(p_organization_id uuid)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is not null
     and (p_organization_id is null or not (p_organization_id in (select public.auth_org_ids()))) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
end;
$$;
revoke all on function private.assert_member_of(uuid) from public, anon, authenticated;

create or replace function private.tg_role_assignments_validate()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_role public.roles%rowtype;
begin
  perform private.assert_member_of(new.organization_id);
  select * into v_role from public.roles r
  where r.id = new.role_id and (r.organization_id is null or r.organization_id = new.organization_id);
  if not found then
    -- missing, or another organization's role: indistinguishable
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if v_role.key = 'super_admin' then
    raise exception 'this role cannot be assigned' using errcode = 'check_violation';
  end if;
  if v_role.archived_at is not null then
    raise exception 'this role is archived' using errcode = 'check_violation';
  end if;
  if new.location_id is null and (v_role.organization_id is not null or v_role.key <> 'admin') then
    raise exception 'this role must be given at a location' using errcode = 'check_violation';
  end if;
  return new;
end;
$$;

create or replace function private.tg_spaces_hierarchy()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.assert_member_of(new.organization_id);
  if new.parent_space_id is not null then
    -- Only a parent in the same organization and location is considered; any
    -- other parent id falls through to the composite foreign key error.
    if exists (select 1 from public.spaces s
               where s.id = new.parent_space_id
                 and s.organization_id = new.organization_id
                 and s.location_id = new.location_id
                 and s.parent_space_id is not null) then
      raise exception 'a sub-space cannot have its own sub-spaces' using errcode = 'check_violation';
    end if;
    if exists (select 1 from public.spaces s
               where s.parent_space_id = new.id and s.organization_id = new.organization_id) then
      raise exception 'a space with sub-spaces cannot become a sub-space' using errcode = 'check_violation';
    end if;
  end if;
  return new;
end;
$$;

-- ===========================================================================
-- F8: no TRUNCATE on audited tables, and audit_log is written only by the trigger.
-- ===========================================================================
revoke truncate, trigger, references on table
  public.organizations, public.organization_settings, public.locations, public.space_kinds,
  public.spaces, public.space_hours, public.space_closures, public.platform_admins, public.modules,
  public.roles, public.role_default_permissions, public.people, public.accounts,
  public.role_assignments, public.user_permissions, public.job_titles, public.person_job_titles,
  public.audit_log
from service_role;
alter default privileges in schema public revoke truncate, trigger, references on tables from service_role;

revoke insert on table public.audit_log from service_role;
-- audit_log now: authenticated SELECT (RLS), service_role SELECT. Inserts come
-- only from private.tg_audit_row() (security definer, owned by the migration role).

create function private.tg_audit_no_truncate()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  raise exception 'TRUNCATE is not allowed on audited table %', tg_table_name
    using errcode = 'insufficient_privilege';
end;
$$;
revoke all on function private.tg_audit_no_truncate() from public, anon, authenticated;

-- Same signature as 000400; now also installs a statement-level TRUNCATE guard.
create or replace function private.enable_audit(
  p_table regclass, p_pk_column text default 'id', p_redact text[] default '{}')
returns void
language plpgsql
set search_path = ''
as $$
declare
  v_args text := pg_catalog.quote_literal(p_pk_column);
  v_col text;
begin
  foreach v_col in array p_redact loop
    v_args := v_args || ', ' || pg_catalog.quote_literal(v_col);
  end loop;
  if exists (select 1 from pg_catalog.pg_trigger t where t.tgrelid = p_table and t.tgname = 'zz_audit') then
    execute format('drop trigger zz_audit on %s', p_table);
  end if;
  execute format(
    'create trigger zz_audit after insert or update or delete on %s '
    'for each row execute function private.tg_audit_row(%s)', p_table, v_args);
  if not exists (select 1 from pg_catalog.pg_trigger t where t.tgrelid = p_table and t.tgname = 'zz_audit_no_truncate') then
    execute format(
      'create trigger zz_audit_no_truncate before truncate on %s '
      'for each statement execute function private.tg_audit_no_truncate()', p_table);
  end if;
end;
$$;

do $$
begin
  perform private.enable_audit('public.organizations');
  perform private.enable_audit('public.organization_settings');
  perform private.enable_audit('public.locations');
  perform private.enable_audit('public.space_kinds');
  perform private.enable_audit('public.spaces');
  perform private.enable_audit('public.space_hours');
  perform private.enable_audit('public.space_closures');
  perform private.enable_audit('public.platform_admins', 'user_id');
  perform private.enable_audit('public.modules', 'key');
  perform private.enable_audit('public.roles');
  perform private.enable_audit('public.role_default_permissions');
  perform private.enable_audit('public.people');
  perform private.enable_audit('public.accounts');
  perform private.enable_audit('public.role_assignments');
  perform private.enable_audit('public.user_permissions');
  perform private.enable_audit('public.job_titles');
  perform private.enable_audit('public.person_job_titles');
end;
$$;

-- ===========================================================================
-- F9: bound tenant-writable jsonb. (Every tenant-writable text column already
-- has a length check; settings was the only unbounded value.)
-- ===========================================================================
alter table public.organization_settings
  add constraint organization_settings_settings_size check (octet_length(settings::text) <= 65536);

-- ===========================================================================
-- L6: weekly hours for one space cannot overlap on the same weekday when their
-- effective date ranges overlap (null bounds = open ended).
-- ===========================================================================
create extension if not exists btree_gist with schema extensions;

create type public.time_range as range (subtype = time);
-- The constructor is evaluated by the exclusion constraint on every write;
-- default privileges withheld EXECUTE, so grant it (it reveals nothing).
revoke all on function public.time_range(time, time), public.time_range(time, time, text) from public, anon;
grant execute on function public.time_range(time, time), public.time_range(time, time, text)
  to authenticated, service_role;

-- organization_id and location_id are part of the key on purpose: the
-- exclusion check runs before the deferred-to-end-of-statement foreign key
-- check, and its error DETAIL prints the conflicting row. Without them, an
-- org A admin could write an org A row naming an org B space_id and read org
-- B's hours from the error. With them, rows of different tenants never
-- conflict and the composite FK rejects the row instead.
alter table public.space_hours
  add constraint space_hours_no_overlap exclude using gist (
    organization_id with =,
    location_id with =,
    space_id with =,
    day_of_week with =,
    public.time_range(opens_at, closes_at, '[)') with &&,
    daterange(effective_from, effective_to, '[]') with &&
  );

-- ===========================================================================
-- New admin RPCs
-- ===========================================================================

-- Another person's effective permission (same computation as
-- effective_permission, via private.person_effective_level). Allowed for a
-- platform admin, an organization-scope people_roles admin, or a people_roles
-- admin at a location where the person holds an assignment. Otherwise 42501
-- (also when the person or organization does not exist). Read-only, so it
-- writes no audit row.
create function public.person_effective_permission(
  p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text)
returns public.permission_level
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  if not exists (select 1 from public.people p where p.id = p_person_id and p.organization_id = p_organization_id)
     or not (
       public.is_platform_admin()
       or public.has_permission(p_organization_id, null, 'people_roles', 'admin')
       or exists (
         select 1 from public.role_assignments ra
         where ra.person_id = p_person_id
           and ra.organization_id = p_organization_id
           and ra.location_id is not null
           and public.has_permission(p_organization_id, ra.location_id, 'people_roles', 'admin'))) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  return coalesce(
    private.person_effective_level(p_organization_id, p_person_id, p_location_id, p_module_key),
    'none'::public.permission_level);
end;
$$;

-- Swap one assignment for another for the same person in one transaction.
-- Removal and grant both pass private.can_manage_role_assignment (tier rule,
-- scope, visibility, archived target, permission cap). The new row is inserted
-- before the old one is deleted, so the person never has zero assignments.
-- If the person already holds the replacement, the old row is just removed
-- and the existing id is returned. Audited through the normal triggers.
create function public.replace_role_assignment(p_assignment_id uuid, p_role_id uuid, p_location_id uuid)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_old public.role_assignments%rowtype;
  v_new_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;
  select * into v_old from public.role_assignments ra where ra.id = p_assignment_id;
  if not found
     or not private.can_manage_role_assignment(v_old.organization_id, v_old.person_id, v_old.role_id, v_old.location_id) then
    raise exception 'not allowed' using errcode = 'insufficient_privilege';
  end if;
  if p_role_id is null then
    raise exception 'role is required' using errcode = 'invalid_parameter_value';
  end if;
  if v_old.role_id = p_role_id and v_old.location_id is not distinct from p_location_id then
    raise exception 'nothing to change' using errcode = 'invalid_parameter_value';
  end if;
  if not private.can_manage_role_assignment(v_old.organization_id, v_old.person_id, p_role_id, p_location_id) then
    raise exception 'not allowed to give that role in that scope' using errcode = 'insufficient_privilege';
  end if;

  select ra.id into v_new_id from public.role_assignments ra
  where ra.person_id = v_old.person_id and ra.role_id = p_role_id
    and ra.location_id is not distinct from p_location_id;
  if v_new_id is null then
    insert into public.role_assignments (organization_id, person_id, role_id, location_id)
    values (v_old.organization_id, v_old.person_id, p_role_id, p_location_id)
    returning id into v_new_id;
  end if;

  delete from public.role_assignments ra where ra.id = v_old.id;
  return v_new_id;
end;
$$;

revoke all on function public.person_effective_permission(uuid, uuid, uuid, text) from public, anon, authenticated;
revoke all on function public.replace_role_assignment(uuid, uuid, uuid) from public, anon, authenticated;
grant execute on function public.person_effective_permission(uuid, uuid, uuid, text) to authenticated, service_role;
grant execute on function public.replace_role_assignment(uuid, uuid, uuid) to authenticated, service_role;
