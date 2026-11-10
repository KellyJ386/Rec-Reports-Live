-- Phase 1 (roadmap 1.4 follow-up): two people RPCs.
--
--   public.create_person_with_assignment(...)  onboard a person + first role
--     assignment in one transaction. Lets a location-scoped admin onboard
--     someone and read the row back (plain INSERT ... RETURNING on people fails
--     for them because the person is not visible until assigned).
--   public.update_own_profile(...)  a member edits harmless fields on their own
--     person row (the tier rule otherwise forbids any self-edit).
--
-- Both are security definer, so RLS does not apply to their writes: every rule
-- is checked in the body with the same private.can_* helpers the policies use.
-- Identity comes only from auth.uid(). The audit trigger still records the real
-- caller: it reads auth.uid() and the session's role setting, which a security
-- definer function does not change.

-- ---------------------------------------------------------------------------
-- create_person_with_assignment
-- ---------------------------------------------------------------------------
-- Rules (identical to the people / role_assignments policies):
--   * caller may create a person in the org: private.can_create_person(org)
--     (people_roles = admin at org scope or at any location; platform admin)
--   * caller may grant the role in that scope to the new person:
--     private.can_manage_role_assignment(org, person, role, location)
--     (people_roles = admin in exactly that scope, role's effective rank
--     strictly below the caller's rank in that scope)
--   * role validity (system or same-org custom, not super_admin, not archived,
--     only admin may be org scoped) is enforced by the role_assignments trigger
-- Any failure raises and rolls back both rows.
-- There is deliberately no service_role shortcut: the caller is always the
-- signed-in user (auth.uid()). Server code holding the service key does not
-- need this function; it can insert both rows directly (it bypasses RLS).
-- The session's `role` setting is not trusted for authorization, because the
-- API's login role (authenticator) is a member of service_role.
create function public.create_person_with_assignment(
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

  -- Checked after the person exists (it has no assignments yet, so rank 0),
  -- exactly as the role_assignments insert policy would check it.
  if not private.can_manage_role_assignment(p_organization_id, v_person_id, p_role_id, p_location_id) then
    raise exception 'not allowed to give that role in that scope' using errcode = 'insufficient_privilege';
  end if;

  insert into public.role_assignments (organization_id, person_id, role_id, location_id)
  values (p_organization_id, v_person_id, p_role_id, p_location_id);

  return v_person_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- update_own_profile
-- ---------------------------------------------------------------------------
-- The caller must be a member of the organization (active account, person not
-- archived, at least one active role assignment). Only preferred_name and
-- phone are editable; both are set exactly as given (null or blank clears).
-- Never: names of record, email (contact/invite address), employee_number,
-- archived_at, organization_id, or anything access related.
-- Returns the caller's person id.
create function public.update_own_profile(
  p_organization_id uuid,
  p_preferred_name text,
  p_phone text
)
returns uuid
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_person_id uuid;
begin
  if (select auth.uid()) is null then
    raise exception 'not signed in' using errcode = 'insufficient_privilege';
  end if;

  select m.person_id into v_person_id
  from private.my_assignments() m
  where m.organization_id = p_organization_id
  limit 1;

  if v_person_id is null then
    raise exception 'not a member of this organization' using errcode = 'insufficient_privilege';
  end if;

  update public.people
  set preferred_name = nullif(btrim(p_preferred_name), ''),
      phone = nullif(btrim(p_phone), '')
  where id = v_person_id
    and organization_id = p_organization_id;

  return v_person_id;
end;
$$;

revoke all on function public.create_person_with_assignment(uuid, text, text, uuid, uuid, text, text, text, text)
  from public, anon, authenticated;
revoke all on function public.update_own_profile(uuid, text, text)
  from public, anon, authenticated;
grant execute on function public.create_person_with_assignment(uuid, text, text, uuid, uuid, text, text, text, text)
  to authenticated, service_role;
grant execute on function public.update_own_profile(uuid, text, text)
  to authenticated, service_role;
