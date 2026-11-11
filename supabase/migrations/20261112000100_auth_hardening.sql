-- Phase 1 carry-overs (docs/SECURITY.md "Required controls"):
--   A1  MFA for the admin tier, enforced in the database
--   A2  public.consume_rate_limit (service_role only) + private cleanup
--   A3  public.can_manage_person_account (invite flow pre-check)
--
-- Earlier migrations are committed; functions are replaced in place with the
-- same signatures (existing grants are kept) or added.

-- ===========================================================================
-- A1: admin tier needs aal2
-- ===========================================================================
-- Rule: platform-admin status, and any role assignment whose EFFECTIVE rank is
-- >= 80 (admin at a location = 80, admin at organization scope = 90), count
-- only when the session JWT says aal = 'aal2' (Supabase Auth sets aal1 after
-- the first factor, aal2 after a verified MFA challenge; no claim = aal1).
-- At aal1 those grants are treated as if they did not exist. Everything else
-- (staff, manager, custom roles 1-79) is unaffected.
--
-- Applied in exactly two places, the two cores every helper, policy, trigger
-- and RPC is built on:
--   * private.my_assignments()              the caller's assignments
--   * private.person_effective_level(...)   when the person asked about is the
--                                           caller's own person
-- plus public.is_platform_admin(). private.person_max_rank (a TARGET's rank
-- for the tier rule) is deliberately unchanged: a target always counts at
-- their full rank, which is the conservative direction.

-- The single place the admin-tier threshold lives.
create function private.admin_tier_min_rank()
returns integer
language sql
immutable
set search_path = ''
as $$ select 80 $$;

-- Did this session pass the second factor?
create function private.session_is_aal2()
returns boolean
language sql
stable
set search_path = ''
as $$
  select coalesce((select auth.jwt()) ->> 'aal', '') = 'aal2'
$$;

revoke all on function private.admin_tier_min_rank() from public, anon, authenticated;
revoke all on function private.session_is_aal2() from public, anon, authenticated;

-- Same signature and columns as 000300. Admin-tier rows need aal2.
create or replace function private.my_assignments()
returns table (organization_id uuid, person_id uuid, location_id uuid, role_id uuid, role_key text, rank integer)
language sql
stable
security definer
set search_path = ''
as $$
  select x.organization_id, x.person_id, x.location_id, x.role_id, x.role_key, x.rank
  from (
    select ra.organization_id, ra.person_id, ra.location_id, r.id as role_id, r.key as role_key,
           r.rank + case when ra.location_id is null then 10 else 0 end as rank
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
  ) x
  where x.rank < private.admin_tier_min_rank() or private.session_is_aal2()
$$;

create or replace function public.is_platform_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.session_is_aal2()
     and exists (select 1 from public.platform_admins pa where pa.user_id = (select auth.uid()))
$$;

-- Same signature as 000600. When p_person_id is the caller's own person and
-- the session is not aal2, admin-tier assignments and the platform-admin
-- shortcut are ignored. For anyone else (person_effective_permission) the
-- person's full grants count.
create or replace function private.person_effective_level(
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
      and (r.rank + case when ra.location_id is null then 10 else 0 end < private.admin_tier_min_rank()
           or a.user_id is distinct from (select auth.uid())
           or private.session_is_aal2())
  )
  select case
    when p_person_id is null or not private.scope_exists(p_organization_id, p_location_id) then null
    when exists (
      select 1 from public.accounts a
      join public.platform_admins pa on pa.user_id = a.user_id
      where a.person_id = p_person_id and a.organization_id = p_organization_id
        and (a.user_id is distinct from (select auth.uid()) or private.session_is_aal2())
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

-- True when the caller holds admin-tier access that is suppressed right now
-- because the session is not aal2: the app sends them to the second-step
-- screen. False at aal2, for non-admins, and without a signed-in user.
create function public.session_needs_mfa()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select (select auth.uid()) is not null
     and not private.session_is_aal2()
     and (
       exists (select 1 from public.platform_admins pa where pa.user_id = (select auth.uid()))
       or exists (
         select 1
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
           and r.rank + case when ra.location_id is null then 10 else 0 end >= private.admin_tier_min_rank()))
$$;

revoke all on function public.session_needs_mfa() from public, anon, authenticated;
grant execute on function public.session_needs_mfa() to authenticated, service_role;

-- ===========================================================================
-- A2: rate limits (fixed window), service_role only
-- ===========================================================================
-- Lives in schema private: not exposed by the Data API, no tenant access at
-- all. Not audited (no tenant data; it would only copy hashes into audit_log).
-- Keys (an email or an IP) are stored only as HMAC-SHA256(secret, bucket ||
-- 0x00 || lower(trim(key))). The secret is random per database and never
-- leaves it, so a leaked table cannot be reversed with a dictionary of emails.
create extension if not exists pgcrypto with schema extensions;

create table private.rate_limit_secret (
  id boolean primary key default true check (id),
  secret bytea not null
);
insert into private.rate_limit_secret (secret) values (extensions.gen_random_bytes(32));

create table private.rate_limit_counters (
  bucket text not null,
  key_hash bytea not null,
  window_start timestamptz not null,
  window_end timestamptz not null,
  hits integer not null default 0,
  primary key (bucket, key_hash, window_start)
);
create index rate_limit_counters_window_end_idx on private.rate_limit_counters (window_end);

alter table private.rate_limit_secret enable row level security;
alter table private.rate_limit_counters enable row level security;
revoke all on table private.rate_limit_secret, private.rate_limit_counters
  from public, anon, authenticated, service_role;
-- No policies and no grants: only the definer functions below (owned by the
-- migration role) touch these tables.

-- Count one hit for (bucket, key) in the current fixed window. Returns true
-- while the count is within p_max (so the first p_max calls in a window are
-- allowed), false once it is over. Also drops this key's expired windows.
create function public.consume_rate_limit(p_bucket text, p_key text, p_max integer, p_window_seconds integer)
returns boolean
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_hash bytea;
  v_epoch double precision := extract(epoch from now());
  v_start timestamptz;
  v_hits integer;
begin
  if p_bucket is null or p_bucket !~ '^[a-z][a-z0-9_.:-]{0,62}$' then
    raise exception 'invalid bucket' using errcode = 'invalid_parameter_value';
  end if;
  if p_key is null or char_length(btrim(p_key)) not between 1 and 512 then
    raise exception 'invalid key' using errcode = 'invalid_parameter_value';
  end if;
  if p_max is null or p_max not between 1 and 1000000 then
    raise exception 'invalid max' using errcode = 'invalid_parameter_value';
  end if;
  if p_window_seconds is null or p_window_seconds not between 1 and 86400 then
    raise exception 'invalid window' using errcode = 'invalid_parameter_value';
  end if;

  v_hash := extensions.hmac(
    convert_to(p_bucket, 'UTF8') || '\x00'::bytea || convert_to(lower(btrim(p_key)), 'UTF8'),
    (select s.secret from private.rate_limit_secret s),
    'sha256');
  v_start := to_timestamp(floor(v_epoch / p_window_seconds) * p_window_seconds);

  delete from private.rate_limit_counters c
  where c.bucket = p_bucket and c.key_hash = v_hash and c.window_end <= now();

  insert into private.rate_limit_counters as c (bucket, key_hash, window_start, window_end, hits)
  values (p_bucket, v_hash, v_start, v_start + make_interval(secs => p_window_seconds), 1)
  on conflict (bucket, key_hash, window_start) do update set hits = c.hits + 1
  returning c.hits into v_hits;

  return v_hits <= p_max;
end;
$$;

revoke all on function public.consume_rate_limit(text, text, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_rate_limit(text, text, integer, integer) to service_role;

-- Cleanup: deletes every counter whose window has ended. Returns rows removed.
-- Private (not callable through the Data API); run it from a scheduled job on
-- a direct database connection, or from pg_cron.
create function private.purge_rate_limit_counters()
returns integer
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_n integer;
begin
  delete from private.rate_limit_counters c where c.window_end <= now();
  get diagnostics v_n = row_count;
  return v_n;
end;
$$;
revoke all on function private.purge_rate_limit_counters() from public, anon, authenticated;
grant execute on function private.purge_rate_limit_counters() to service_role;

-- ===========================================================================
-- A3: may the caller create a login for this person? (invite flow)
-- ===========================================================================
-- True only when: signed in; the person exists in that organization and is not
-- archived; has no account yet; is visible to the caller; and the tier rule
-- for people holds (private.can_manage_person: people_roles = admin in a
-- covering scope, caller's rank there strictly above the person's highest
-- rank, not themselves). Identity from auth.uid() only. False, never an error,
-- for anything else (so it reveals nothing about other organizations).
create function public.can_manage_person_account(p_organization_id uuid, p_person_id uuid)
returns boolean
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if (select auth.uid()) is null or p_organization_id is null or p_person_id is null then
    return false;
  end if;
  if not exists (select 1 from public.people p
                 where p.id = p_person_id and p.organization_id = p_organization_id and p.archived_at is null) then
    return false;
  end if;
  if not (public.is_platform_admin() or p_person_id in (select private.visible_person_ids())) then
    return false;
  end if;
  if exists (select 1 from public.accounts a where a.person_id = p_person_id) then
    return false;
  end if;
  return private.can_manage_person(p_organization_id, p_person_id);
end;
$$;

revoke all on function public.can_manage_person_account(uuid, uuid) from public, anon, authenticated;
grant execute on function public.can_manage_person_account(uuid, uuid) to authenticated, service_role;
