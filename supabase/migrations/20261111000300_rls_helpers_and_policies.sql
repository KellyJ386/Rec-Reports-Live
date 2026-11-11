-- Phase 1 (roadmap 1.4): RLS helper functions, policies and table grants.
--
-- Rules every helper follows:
--   * security definer, stable, set search_path = '' with schema-qualified names
--   * identity comes ONLY from auth.uid(), never from an argument
--   * revoke from public/anon; grant execute to authenticated + service_role
--     only where a policy (or the app) needs it
--   * a caller learns nothing about organizations they are not a member of
--     (helpers answer false / 0 / 'none' / empty set)
--
-- Membership in an organization = an account for auth.uid() in that org that
-- is not disabled, whose person is not archived, holding at least one role
-- assignment on a non-archived role (and, if location scoped, a non-archived
-- location). user_permissions rows alone never make anyone a member.

-- ---------------------------------------------------------------------------
-- Internal building blocks (private schema; NOT granted to authenticated)
-- ---------------------------------------------------------------------------

-- The caller's active assignments, across all organizations.
-- rank is the EFFECTIVE rank: roles.rank, +10 when organization scoped.
create function private.my_assignments()
returns table (organization_id uuid, person_id uuid, location_id uuid, role_id uuid, role_key text, rank integer)
language sql
stable
security definer
set search_path = ''
as $$
  select ra.organization_id, ra.person_id, ra.location_id, r.id, r.key,
         r.rank + case when ra.location_id is null then 10 else 0 end
  from public.accounts a
  join public.people p on p.id = a.person_id and p.organization_id = a.organization_id
  join public.role_assignments ra on ra.person_id = p.id and ra.organization_id = p.organization_id
  join public.roles r on r.id = ra.role_id
  left join public.locations l on l.id = ra.location_id and l.organization_id = ra.organization_id
  where a.user_id = (select auth.uid())
    and a.disabled_at is null
    and p.archived_at is null
    and r.archived_at is null
    and (ra.location_id is null or l.archived_at is null)
$$;

-- Highest effective rank a person holds anywhere in their organization
-- (archived roles/locations still count, to stay conservative). A person whose
-- account belongs to a platform admin ranks 100. No assignments = 0.
create function private.person_max_rank(p_person uuid)
returns integer
language sql
stable
security definer
set search_path = ''
as $$
  select greatest(
    coalesce((
      select max(r.rank + case when ra.location_id is null then 10 else 0 end)
      from public.role_assignments ra
      join public.roles r on r.id = ra.role_id
      where ra.person_id = p_person
    ), 0),
    case when exists (
      select 1 from public.accounts a
      join public.platform_admins pa on pa.user_id = a.user_id
      where a.person_id = p_person
    ) then 100 else 0 end
  )
$$;

revoke all on function private.my_assignments() from public, anon, authenticated;
revoke all on function private.person_max_rank(uuid) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- Public helpers (callable by authenticated, also through /rpc)
-- ---------------------------------------------------------------------------

create function public.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.platform_admins pa where pa.user_id = (select auth.uid()))
$$;

-- Organizations the caller is a member of (every organization for a platform admin).
create function public.auth_org_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select o.id from public.organizations o where public.is_platform_admin()
  union
  select m.organization_id from private.my_assignments() m
$$;

-- Locations the caller can reach: every location of an org where they hold an
-- organization-scope assignment, plus each location they are assigned to.
-- Platform admin: every location. Includes archived locations of org-scope orgs.
create function public.auth_location_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select l.id from public.locations l where public.is_platform_admin()
  union
  select l.id
  from public.locations l
  join private.my_assignments() m on m.organization_id = l.organization_id and m.location_id is null
  union
  select m.location_id from private.my_assignments() m where m.location_id is not null
$$;

-- The caller's person id in an organization (active account, person not
-- archived), or null. Does not by itself imply membership.
create function public.current_person_id(p_organization_id uuid)
returns uuid
language sql
stable
security definer
set search_path = ''
as $$
  select a.person_id
  from public.accounts a
  join public.people p on p.id = a.person_id
  where a.user_id = (select auth.uid())
    and a.organization_id = p_organization_id
    and a.disabled_at is null
    and p.archived_at is null
$$;

-- Does the caller hold role p_role_key in scope? p_location_id null = an
-- organization-scope assignment; a location = org scope OR that location.
-- Always true for a platform admin.
create function public.has_role(p_organization_id uuid, p_location_id uuid, p_role_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_platform_admin() or exists (
    select 1 from private.my_assignments() m
    where m.organization_id = p_organization_id
      and m.role_key = p_role_key
      and (m.location_id is null or m.location_id = p_location_id)
  )
$$;

-- Caller's highest effective rank in scope (org scope only when location is
-- null; org scope + that location otherwise). 100 for platform admin, 0 if none.
create function public.actor_rank(p_organization_id uuid, p_location_id uuid)
returns integer
language sql
stable
security definer
set search_path = ''
as $$
  select case when public.is_platform_admin() then 100 else coalesce((
    select max(m.rank) from private.my_assignments() m
    where m.organization_id = p_organization_id
      and (m.location_id is null or m.location_id = p_location_id)
  ), 0) end
$$;

-- Effective permission for the caller on a module in scope:
--   no assignment covering the scope            -> 'none'
--   user_permissions row at that location        -> its level
--   else user_permissions row org wide (loc null) -> its level
--   else highest role default among assignments covering the scope
-- Scope covering: location null = organization-scope assignments only;
-- a location = organization-scope assignments + assignments at that location.
-- Platform admin: 'admin'.
create function public.effective_permission(p_organization_id uuid, p_location_id uuid, p_module_key text)
returns public.permission_level
language sql
stable
security definer
set search_path = ''
as $$
  with mine as (
    select m.person_id, m.role_id
    from private.my_assignments() m
    where m.organization_id = p_organization_id
      and (m.location_id is null or m.location_id = p_location_id)
  )
  select case
    when public.is_platform_admin() then 'admin'::public.permission_level
    when not exists (select 1 from mine) then 'none'::public.permission_level
    else coalesce(
      (select up.level from public.user_permissions up
        where up.organization_id = p_organization_id
          and up.person_id = (select person_id from mine limit 1)
          and up.module_key = p_module_key
          and up.location_id = p_location_id),
      (select up.level from public.user_permissions up
        where up.organization_id = p_organization_id
          and up.person_id = (select person_id from mine limit 1)
          and up.module_key = p_module_key
          and up.location_id is null),
      (select max(d.level) from public.role_default_permissions d
        where d.module_key = p_module_key
          and d.role_id in (select role_id from mine)),
      'none'::public.permission_level)
  end
$$;

create function public.has_permission(
  p_organization_id uuid, p_location_id uuid, p_module_key text, p_min_level public.permission_level)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.effective_permission(p_organization_id, p_location_id, p_module_key) >= p_min_level
$$;

-- ---------------------------------------------------------------------------
-- Policy helpers (private schema: usable in policies, not exposed as /rpc)
-- ---------------------------------------------------------------------------

-- Organizations where the caller has >= level on module at ORGANIZATION scope.
create function private.permitted_org_ids(p_module_key text, p_min_level public.permission_level)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select distinct m.organization_id
  from private.my_assignments() m
  where m.location_id is null
    and public.has_permission(m.organization_id, null, p_module_key, p_min_level)
$$;

-- Locations where the caller has >= level on module (org-scope grants count).
create function private.permitted_location_ids(p_module_key text, p_min_level public.permission_level)
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select l.id
  from public.locations l
  where l.id in (select public.auth_location_ids())
    and public.has_permission(l.organization_id, l.id, p_module_key, p_min_level)
$$;

-- People the caller may see (excluding the platform-admin shortcut, which
-- policies add themselves):
--   * themselves (only in orgs where they are a member)
--   * everyone in an org where they hold an organization-scope assignment
--   * anyone holding an assignment at a location they are assigned to
create function private.visible_person_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select m.person_id from private.my_assignments() m
  union
  select p.id from public.people p
  where p.organization_id in (select m.organization_id from private.my_assignments() m where m.location_id is null)
  union
  select ra.person_id
  from public.role_assignments ra
  join private.my_assignments() m
    on m.organization_id = ra.organization_id and m.location_id = ra.location_id
$$;

-- The caller's own person ids, in orgs where they are a member.
create function private.my_person_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select distinct m.person_id from private.my_assignments() m
$$;

-- People for whom the caller holds people_roles at 'admin' in scope: everyone
-- in an org where that holds at org scope; people with an assignment at a
-- location where it holds.
create function private.people_admin_person_ids()
returns setof uuid
language sql
stable
security definer
set search_path = ''
as $$
  select p.id from public.people p
  where p.organization_id in (select private.permitted_org_ids('people_roles', 'admin'))
  union
  select ra.person_id from public.role_assignments ra
  where ra.location_id in (select private.permitted_location_ids('people_roles', 'admin'))
$$;

-- Tier rule for a person row (and that person's account):
--   caller is not the target, and there is a scope where the caller holds
--   people_roles 'admin' and an effective rank strictly above the target's
--   highest rank in the organization. Location scopes considered are the
--   locations the target is assigned to.
create function private.can_manage_person(p_organization_id uuid, p_person_id uuid)
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

-- Creating a new person: people_roles 'admin' at org scope or at any location.
create function private.can_create_person(p_organization_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select public.is_platform_admin()
    or public.has_permission(p_organization_id, null, 'people_roles', 'admin')
    or exists (
      select 1 from public.locations l
      where l.organization_id = p_organization_id
        and l.id in (select private.permitted_location_ids('people_roles', 'admin'))
    )
$$;

-- Tier rule for creating/removing a role assignment (person, role, scope).
--   (a) people_roles 'admin' in exactly that scope (location null = org scope,
--       which a location-scoped admin never has)
--   (b) target's highest rank in the org < caller's rank in scope
--   (c) effective rank of the role being granted (+10 if org scope) < caller's rank
--   caller is not the target; target is visible to the caller or has no
--   assignments yet (a brand-new person).
create function private.can_manage_role_assignment(
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
  if not (p_person_id in (select private.visible_person_ids())
          or not exists (select 1 from public.role_assignments ra where ra.person_id = p_person_id)) then
    return false;
  end if;
  v_actor_rank := public.actor_rank(p_organization_id, p_location_id);
  return v_actor_rank > private.person_max_rank(p_person_id) and v_actor_rank > v_role_rank;
end;
$$;

-- Tier rule for a user_permissions row. p_level null = removing/reading the
-- old row; otherwise the caller cannot grant a level above their own
-- effective level for that module in that scope.
create function private.can_manage_user_permission(
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

-- ---------------------------------------------------------------------------
-- Function privileges
-- ---------------------------------------------------------------------------
revoke all on function public.is_platform_admin() from public, anon, authenticated;
revoke all on function public.auth_org_ids() from public, anon, authenticated;
revoke all on function public.auth_location_ids() from public, anon, authenticated;
revoke all on function public.current_person_id(uuid) from public, anon, authenticated;
revoke all on function public.has_role(uuid, uuid, text) from public, anon, authenticated;
revoke all on function public.actor_rank(uuid, uuid) from public, anon, authenticated;
revoke all on function public.effective_permission(uuid, uuid, text) from public, anon, authenticated;
revoke all on function public.has_permission(uuid, uuid, text, public.permission_level) from public, anon, authenticated;
revoke all on function private.permitted_org_ids(text, public.permission_level) from public, anon, authenticated;
revoke all on function private.permitted_location_ids(text, public.permission_level) from public, anon, authenticated;
revoke all on function private.visible_person_ids() from public, anon, authenticated;
revoke all on function private.my_person_ids() from public, anon, authenticated;
revoke all on function private.people_admin_person_ids() from public, anon, authenticated;
revoke all on function private.can_manage_person(uuid, uuid) from public, anon, authenticated;
revoke all on function private.can_create_person(uuid) from public, anon, authenticated;
revoke all on function private.can_manage_role_assignment(uuid, uuid, uuid, uuid) from public, anon, authenticated;
revoke all on function private.can_manage_user_permission(uuid, uuid, uuid, text, public.permission_level) from public, anon, authenticated;

grant execute on function
  public.is_platform_admin(),
  public.auth_org_ids(),
  public.auth_location_ids(),
  public.current_person_id(uuid),
  public.has_role(uuid, uuid, text),
  public.actor_rank(uuid, uuid),
  public.effective_permission(uuid, uuid, text),
  public.has_permission(uuid, uuid, text, public.permission_level),
  private.permitted_org_ids(text, public.permission_level),
  private.permitted_location_ids(text, public.permission_level),
  private.visible_person_ids(),
  private.my_person_ids(),
  private.people_admin_person_ids(),
  private.can_manage_person(uuid, uuid),
  private.can_create_person(uuid),
  private.can_manage_role_assignment(uuid, uuid, uuid, uuid),
  private.can_manage_user_permission(uuid, uuid, uuid, text, public.permission_level)
to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- Policies. All are `to authenticated`; anon has no grants and no policies.
-- Helper calls without row arguments are wrapped in (select ...) so Postgres
-- evaluates them once per statement.
-- ---------------------------------------------------------------------------

-- organizations: members read; org-scope admin updates name. Insert/delete: service_role only.
create policy organizations_select on public.organizations for select to authenticated
  using (id in (select public.auth_org_ids()));
create policy organizations_update on public.organizations for update to authenticated
  using (public.has_role(id, null, 'admin'))
  with check (public.has_role(id, null, 'admin'));

-- organization_settings: members read; org-scope admin updates.
create policy organization_settings_select on public.organization_settings for select to authenticated
  using (organization_id in (select public.auth_org_ids()));
create policy organization_settings_update on public.organization_settings for update to authenticated
  using (public.has_role(organization_id, null, 'admin'))
  with check (public.has_role(organization_id, null, 'admin'));

-- locations: members read; org-scope admin creates; admin of the location (or org) updates/archives.
create policy locations_select on public.locations for select to authenticated
  using (organization_id in (select public.auth_org_ids()));
create policy locations_insert on public.locations for insert to authenticated
  with check (public.has_role(organization_id, null, 'admin'));
create policy locations_update on public.locations for update to authenticated
  using (public.has_role(organization_id, id, 'admin'))
  with check (public.has_role(organization_id, id, 'admin'));

-- space_kinds: members read; locations_spaces >= edit at org scope writes.
create policy space_kinds_select on public.space_kinds for select to authenticated
  using (organization_id in (select public.auth_org_ids()));
create policy space_kinds_insert on public.space_kinds for insert to authenticated
  with check (public.has_permission(organization_id, null, 'locations_spaces', 'edit'));
create policy space_kinds_update on public.space_kinds for update to authenticated
  using (public.has_permission(organization_id, null, 'locations_spaces', 'edit'))
  with check (public.has_permission(organization_id, null, 'locations_spaces', 'edit'));

-- spaces / space_hours / space_closures: members read; locations_spaces >= edit at the location writes.
create policy spaces_select on public.spaces for select to authenticated
  using (organization_id in (select public.auth_org_ids()));
create policy spaces_insert on public.spaces for insert to authenticated
  with check (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));
create policy spaces_update on public.spaces for update to authenticated
  using (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'))
  with check (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));

create policy space_hours_select on public.space_hours for select to authenticated
  using (organization_id in (select public.auth_org_ids()));
create policy space_hours_insert on public.space_hours for insert to authenticated
  with check (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));
create policy space_hours_update on public.space_hours for update to authenticated
  using (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'))
  with check (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));
create policy space_hours_delete on public.space_hours for delete to authenticated
  using (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));

create policy space_closures_select on public.space_closures for select to authenticated
  using (organization_id in (select public.auth_org_ids()));
create policy space_closures_insert on public.space_closures for insert to authenticated
  with check (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));
create policy space_closures_update on public.space_closures for update to authenticated
  using (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'))
  with check (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));
create policy space_closures_delete on public.space_closures for delete to authenticated
  using (public.has_permission(organization_id, location_id, 'locations_spaces', 'edit'));

-- platform_admins: no policies, no grants. service_role only.

-- modules: any member of any organization reads.
create policy modules_select on public.modules for select to authenticated
  using (exists (select 1 from public.auth_org_ids()));

-- roles: system roles readable by any member; custom roles by members of their org.
-- Custom roles written by org-scope admins (rank range enforced by constraint).
create policy roles_select on public.roles for select to authenticated
  using ((organization_id is null and exists (select 1 from public.auth_org_ids()))
         or organization_id in (select public.auth_org_ids()));
create policy roles_insert on public.roles for insert to authenticated
  with check (organization_id is not null and public.has_role(organization_id, null, 'admin'));
create policy roles_update on public.roles for update to authenticated
  using (organization_id is not null and public.has_role(organization_id, null, 'admin'))
  with check (organization_id is not null and public.has_role(organization_id, null, 'admin'));

create policy role_default_permissions_select on public.role_default_permissions for select to authenticated
  using ((organization_id is null and exists (select 1 from public.auth_org_ids()))
         or organization_id in (select public.auth_org_ids()));
create policy role_default_permissions_insert on public.role_default_permissions for insert to authenticated
  with check (organization_id is not null and public.has_role(organization_id, null, 'admin'));
create policy role_default_permissions_update on public.role_default_permissions for update to authenticated
  using (organization_id is not null and public.has_role(organization_id, null, 'admin'))
  with check (organization_id is not null and public.has_role(organization_id, null, 'admin'));
create policy role_default_permissions_delete on public.role_default_permissions for delete to authenticated
  using (organization_id is not null and public.has_role(organization_id, null, 'admin'));

-- people
create policy people_select on public.people for select to authenticated
  using ((select public.is_platform_admin()) or id in (select private.visible_person_ids()));
create policy people_insert on public.people for insert to authenticated
  with check (private.can_create_person(organization_id));
create policy people_update on public.people for update to authenticated
  using (private.can_manage_person(organization_id, id))
  with check (private.can_manage_person(organization_id, id));

-- accounts: own row (in member orgs) + people_roles admins in scope.
-- Insert is service_role only (invites need the auth admin API anyway).
create policy accounts_select on public.accounts for select to authenticated
  using ((select public.is_platform_admin())
         or person_id in (select private.my_person_ids())
         or person_id in (select private.people_admin_person_ids()));
create policy accounts_update on public.accounts for update to authenticated
  using (private.can_manage_person(organization_id, person_id))
  with check (private.can_manage_person(organization_id, person_id));
create policy accounts_delete on public.accounts for delete to authenticated
  using (private.can_manage_person(organization_id, person_id));

-- role_assignments: visible with the person; insert/delete under the tier rule; no update.
create policy role_assignments_select on public.role_assignments for select to authenticated
  using ((select public.is_platform_admin()) or person_id in (select private.visible_person_ids()));
create policy role_assignments_insert on public.role_assignments for insert to authenticated
  with check (private.can_manage_role_assignment(organization_id, person_id, role_id, location_id));
create policy role_assignments_delete on public.role_assignments for delete to authenticated
  using (private.can_manage_role_assignment(organization_id, person_id, role_id, location_id));

-- user_permissions: own rows + people_roles admins in scope; writes under the tier rule.
create policy user_permissions_select on public.user_permissions for select to authenticated
  using ((select public.is_platform_admin())
         or person_id in (select private.my_person_ids())
         or person_id in (select private.people_admin_person_ids()));
create policy user_permissions_insert on public.user_permissions for insert to authenticated
  with check (private.can_manage_user_permission(organization_id, person_id, location_id, module_key, level));
create policy user_permissions_update on public.user_permissions for update to authenticated
  using (private.can_manage_user_permission(organization_id, person_id, location_id, module_key, null))
  with check (private.can_manage_user_permission(organization_id, person_id, location_id, module_key, level));
create policy user_permissions_delete on public.user_permissions for delete to authenticated
  using (private.can_manage_user_permission(organization_id, person_id, location_id, module_key, null));

-- job_titles: members read; org-scope admins write.
create policy job_titles_select on public.job_titles for select to authenticated
  using (organization_id in (select public.auth_org_ids()));
create policy job_titles_insert on public.job_titles for insert to authenticated
  with check (public.has_role(organization_id, null, 'admin'));
create policy job_titles_update on public.job_titles for update to authenticated
  using (public.has_role(organization_id, null, 'admin'))
  with check (public.has_role(organization_id, null, 'admin'));

-- person_job_titles: visible with the person; people_roles >= edit in scope assigns/removes.
create policy person_job_titles_select on public.person_job_titles for select to authenticated
  using ((select public.is_platform_admin()) or person_id in (select private.visible_person_ids()));
create policy person_job_titles_insert on public.person_job_titles for insert to authenticated
  with check (public.has_permission(organization_id, location_id, 'people_roles', 'edit')
              and ((select public.is_platform_admin()) or person_id in (select private.visible_person_ids())));
create policy person_job_titles_delete on public.person_job_titles for delete to authenticated
  using (public.has_permission(organization_id, location_id, 'people_roles', 'edit')
         and ((select public.is_platform_admin()) or person_id in (select private.visible_person_ids())));

-- ---------------------------------------------------------------------------
-- Table grants for authenticated: only the operations a policy allows, and
-- UPDATE only on columns that may change. anon gets nothing.
-- ---------------------------------------------------------------------------
grant select on table
  public.organizations, public.organization_settings, public.locations, public.space_kinds,
  public.spaces, public.space_hours, public.space_closures, public.modules, public.roles,
  public.role_default_permissions, public.people, public.accounts, public.role_assignments,
  public.user_permissions, public.job_titles, public.person_job_titles
to authenticated;

grant update (name) on public.organizations to authenticated;
grant update (default_timezone, week_starts_on, settings) on public.organization_settings to authenticated;

grant insert on public.locations to authenticated;
grant update (name, code, timezone, address, phone, archived_at) on public.locations to authenticated;

grant insert on public.space_kinds to authenticated;
grant update (name, sort_order, archived_at) on public.space_kinds to authenticated;

grant insert on public.spaces to authenticated;
grant update (space_kind_id, parent_space_id, name, description, capacity, sort_order, archived_at)
  on public.spaces to authenticated;

grant insert, delete on public.space_hours to authenticated;
grant update (day_of_week, opens_at, closes_at, effective_from, effective_to) on public.space_hours to authenticated;

grant insert, delete on public.space_closures to authenticated;
grant update (starts_at, ends_at, reason) on public.space_closures to authenticated;

grant insert on public.roles to authenticated;
grant update (name, description, rank, archived_at) on public.roles to authenticated;

grant insert, delete on public.role_default_permissions to authenticated;
grant update (level) on public.role_default_permissions to authenticated;

grant insert on public.people to authenticated;
grant update (first_name, last_name, preferred_name, email, phone, employee_number, archived_at)
  on public.people to authenticated;

grant delete on public.accounts to authenticated;
grant update (disabled_at) on public.accounts to authenticated;

grant insert, delete on public.role_assignments to authenticated;

grant insert, delete on public.user_permissions to authenticated;
grant update (level) on public.user_permissions to authenticated;

grant insert on public.job_titles to authenticated;
grant update (name, archived_at) on public.job_titles to authenticated;

grant insert, delete on public.person_job_titles to authenticated;
