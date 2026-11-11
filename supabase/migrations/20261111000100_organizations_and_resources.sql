-- Phase 1 (roadmap 1.3): organizations, locations and the resources hierarchy.
--
-- Organization -> Location -> Space -> optional sub-space.
-- RLS is enabled here on every table; policies and grants live in
-- 20261111000300_rls_helpers_and_policies.sql. Until then authenticated/anon
-- have no table privileges at all (revoked at the bottom of this file).

-- ---------------------------------------------------------------------------
-- Privilege baseline
-- ---------------------------------------------------------------------------

-- Internal functions (trigger functions, RLS building blocks) live here. This
-- schema is NOT exposed through the Data API (supabase/config.toml exposes
-- only public and graphql_public), so nothing in it is callable as an RPC.
create schema if not exists private;
revoke all on schema private from public;
grant usage on schema private to authenticated, service_role;

-- Do not rely on Supabase's permissive default privileges. Objects created by
-- the migration role from now on are NOT granted to anon/authenticated
-- automatically; every grant is written explicitly in a migration.
alter default privileges in schema public revoke all on tables from public, anon, authenticated;
alter default privileges in schema public revoke all on sequences from public, anon, authenticated;
alter default privileges in schema public revoke all on functions from public, anon, authenticated;
alter default privileges in schema private revoke all on tables from public, anon, authenticated;
alter default privileges in schema private revoke all on functions from public, anon, authenticated;
-- Postgres grants EXECUTE to PUBLIC on every new function by default.
alter default privileges revoke execute on functions from public;
alter default privileges in schema public grant all on tables to service_role;
alter default privileges in schema public grant all on sequences to service_role;

-- ---------------------------------------------------------------------------
-- Generic trigger functions (reused by every later migration)
-- ---------------------------------------------------------------------------

-- created_at / updated_at are server-owned: a client can never backdate them.
create function private.tg_set_timestamps()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    new.created_at := now();
    new.updated_at := now();
  else
    new.created_at := old.created_at;
    new.updated_at := now();
  end if;
  return new;
end;
$$;

-- Usage: before update ... execute function private.tg_immutable_columns('id', 'organization_id')
-- Raises if any listed column changes. Applies to every role, service_role and
-- table owner included (column grants already stop authenticated).
create function private.tg_immutable_columns()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_old jsonb := to_jsonb(old);
  v_new jsonb := to_jsonb(new);
  v_col text;
begin
  foreach v_col in array tg_argv loop
    if (v_old -> v_col) is distinct from (v_new -> v_col) then
      raise exception '%.% cannot be changed', tg_table_name, v_col
        using errcode = 'check_violation';
    end if;
  end loop;
  return new;
end;
$$;

-- Usage: before insert or update ... execute function private.tg_validate_timezone('timezone')
-- Accepts only 'UTC' or an Area/Location name known to the server's IANA tz
-- database (pg_timezone_names). Rejects POSIX strings ('UTC+5'), and legacy
-- zone names without a slash ('EST', 'EST5EDT', 'posixrules', 'localtime').
create function private.tg_validate_timezone()
returns trigger
language plpgsql
set search_path = ''
as $$
declare
  v_tz text := to_jsonb(new) ->> tg_argv[0];
begin
  if v_tz is not null and v_tz <> 'UTC' and not (
    v_tz like '%/%' and exists (select 1 from pg_catalog.pg_timezone_names where name = v_tz)
  ) then
    raise exception 'invalid IANA time zone: %', v_tz using errcode = 'check_violation';
  end if;
  return new;
end;
$$;

revoke all on function private.tg_set_timestamps() from public, anon, authenticated;
revoke all on function private.tg_immutable_columns() from public, anon, authenticated;
revoke all on function private.tg_validate_timezone() from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- organizations (tenant root; created and deleted only by service_role)
-- ---------------------------------------------------------------------------
create table public.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(btrim(name)) between 1 and 200),
  slug text not null unique check (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$' and char_length(slug) <= 63),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger organizations_timestamps before insert or update on public.organizations
  for each row execute function private.tg_set_timestamps();
create trigger organizations_immutable before update on public.organizations
  for each row execute function private.tg_immutable_columns('id');

-- ---------------------------------------------------------------------------
-- organization_settings (exactly one row per organization, created by trigger)
-- ---------------------------------------------------------------------------
create table public.organization_settings (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null unique references public.organizations (id) on delete cascade,
  default_timezone text not null default 'America/New_York',
  week_starts_on smallint not null default 0 check (week_starts_on between 0 and 6), -- 0 = Sunday
  settings jsonb not null default '{}'::jsonb check (jsonb_typeof(settings) = 'object'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger organization_settings_timestamps before insert or update on public.organization_settings
  for each row execute function private.tg_set_timestamps();
create trigger organization_settings_immutable before update on public.organization_settings
  for each row execute function private.tg_immutable_columns('id', 'organization_id');
create trigger organization_settings_timezone before insert or update on public.organization_settings
  for each row execute function private.tg_validate_timezone('default_timezone');

-- ---------------------------------------------------------------------------
-- locations (a facility / site)
-- ---------------------------------------------------------------------------
create table public.locations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 200),
  code text check (code ~ '^[A-Za-z0-9_-]{1,20}$'),
  timezone text not null,
  address text check (char_length(address) <= 500),
  phone text check (char_length(phone) <= 40),
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id)
);

create index locations_organization_id_idx on public.locations (organization_id);
create unique index locations_org_name_active_key on public.locations (organization_id, lower(name))
  where archived_at is null;
create unique index locations_org_code_key on public.locations (organization_id, lower(code))
  where code is not null;

create trigger locations_timestamps before insert or update on public.locations
  for each row execute function private.tg_set_timestamps();
create trigger locations_immutable before update on public.locations
  for each row execute function private.tg_immutable_columns('id', 'organization_id');
create trigger locations_timezone before insert or update on public.locations
  for each row execute function private.tg_validate_timezone('timezone');

-- ---------------------------------------------------------------------------
-- space_kinds (per-organization lookup: pool, gym, court, studio, rink, room)
-- ---------------------------------------------------------------------------
create table public.space_kinds (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  key text not null check (key ~ '^[a-z][a-z0-9_]{0,62}$'),
  name text not null check (char_length(btrim(name)) between 1 and 100),
  sort_order integer not null default 0,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (organization_id, key),
  unique (id, organization_id)
);

create trigger space_kinds_timestamps before insert or update on public.space_kinds
  for each row execute function private.tg_set_timestamps();
create trigger space_kinds_immutable before update on public.space_kinds
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'key');

-- ---------------------------------------------------------------------------
-- spaces (a bookable / inspectable resource; one optional level of sub-space)
-- ---------------------------------------------------------------------------
create table public.spaces (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  space_kind_id uuid not null,
  parent_space_id uuid,
  name text not null check (char_length(btrim(name)) between 1 and 200),
  description text check (char_length(description) <= 2000),
  capacity integer check (capacity >= 0),
  sort_order integer not null default 0,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id),
  unique (id, organization_id, location_id),
  check (parent_space_id is null or parent_space_id <> id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id),
  foreign key (space_kind_id, organization_id) references public.space_kinds (id, organization_id),
  -- A sub-space must be in the same organization AND the same location as its parent.
  foreign key (parent_space_id, organization_id, location_id)
    references public.spaces (id, organization_id, location_id)
);

create index spaces_org_location_idx on public.spaces (organization_id, location_id);
create index spaces_org_kind_idx on public.spaces (organization_id, space_kind_id);
create index spaces_parent_idx on public.spaces (parent_space_id, organization_id, location_id)
  where parent_space_id is not null;
create unique index spaces_location_parent_name_active_key on public.spaces
  (location_id, coalesce(parent_space_id, '00000000-0000-0000-0000-000000000000'::uuid), lower(name))
  where archived_at is null;

-- Exactly one level of nesting: a parent must be top level, and a space that
-- has children cannot itself become a child. This also rules out cycles.
create function private.tg_spaces_hierarchy()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.parent_space_id is not null then
    if exists (select 1 from public.spaces s where s.id = new.parent_space_id and s.parent_space_id is not null) then
      raise exception 'a sub-space cannot have its own sub-spaces' using errcode = 'check_violation';
    end if;
    if exists (select 1 from public.spaces s where s.parent_space_id = new.id) then
      raise exception 'a space with sub-spaces cannot become a sub-space' using errcode = 'check_violation';
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.tg_spaces_hierarchy() from public, anon, authenticated;

create trigger spaces_timestamps before insert or update on public.spaces
  for each row execute function private.tg_set_timestamps();
create trigger spaces_immutable before update on public.spaces
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id');
create trigger spaces_hierarchy before insert or update of parent_space_id on public.spaces
  for each row execute function private.tg_spaces_hierarchy();

-- ---------------------------------------------------------------------------
-- space_hours (weekly opening hours, optionally date-bounded for seasons)
-- ---------------------------------------------------------------------------
create table public.space_hours (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  space_id uuid not null,
  day_of_week smallint not null check (day_of_week between 1 and 7), -- ISO: 1 = Monday, 7 = Sunday
  opens_at time not null,
  closes_at time not null, -- '24:00' allowed; overnight hours are two rows
  effective_from date,
  effective_to date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (closes_at > opens_at),
  check (effective_to is null or effective_from is null or effective_to >= effective_from),
  foreign key (space_id, organization_id, location_id)
    references public.spaces (id, organization_id, location_id) on delete cascade,
  foreign key (location_id, organization_id) references public.locations (id, organization_id)
);

create index space_hours_space_idx on public.space_hours (space_id, organization_id, location_id);
create index space_hours_org_location_idx on public.space_hours (organization_id, location_id);

create trigger space_hours_timestamps before insert or update on public.space_hours
  for each row execute function private.tg_set_timestamps();
create trigger space_hours_immutable before update on public.space_hours
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'space_id');

-- ---------------------------------------------------------------------------
-- space_closures (a space, or with space_id null the whole location, is closed)
-- ---------------------------------------------------------------------------
create table public.space_closures (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  location_id uuid not null,
  space_id uuid, -- null = the whole location is closed
  starts_at timestamptz not null,
  ends_at timestamptz not null,
  reason text check (char_length(reason) <= 500),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (ends_at > starts_at),
  foreign key (space_id, organization_id, location_id)
    references public.spaces (id, organization_id, location_id) on delete cascade,
  foreign key (location_id, organization_id) references public.locations (id, organization_id)
);

create index space_closures_space_idx on public.space_closures (space_id, organization_id, location_id)
  where space_id is not null;
create index space_closures_org_location_starts_idx on public.space_closures (organization_id, location_id, starts_at);

create trigger space_closures_timestamps before insert or update on public.space_closures
  for each row execute function private.tg_set_timestamps();
create trigger space_closures_immutable before update on public.space_closures
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'location_id', 'space_id');

-- ---------------------------------------------------------------------------
-- New organization bootstrap: settings row + default space kinds.
-- ---------------------------------------------------------------------------
create function private.tg_organization_bootstrap()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.organization_settings (organization_id) values (new.id);
  insert into public.space_kinds (organization_id, key, name, sort_order)
  values (new.id, 'pool', 'Pool', 10),
         (new.id, 'gym', 'Gym', 20),
         (new.id, 'court', 'Court', 30),
         (new.id, 'studio', 'Studio', 40),
         (new.id, 'rink', 'Rink', 50),
         (new.id, 'field', 'Field', 60),
         (new.id, 'room', 'Room', 70),
         (new.id, 'other', 'Other', 100);
  return null;
end;
$$;
revoke all on function private.tg_organization_bootstrap() from public, anon, authenticated;

create trigger organizations_bootstrap after insert on public.organizations
  for each row execute function private.tg_organization_bootstrap();

-- ---------------------------------------------------------------------------
-- RLS on, nothing granted yet.
-- ---------------------------------------------------------------------------
alter table public.organizations enable row level security;
alter table public.organization_settings enable row level security;
alter table public.locations enable row level security;
alter table public.space_kinds enable row level security;
alter table public.spaces enable row level security;
alter table public.space_hours enable row level security;
alter table public.space_closures enable row level security;

revoke all on table
  public.organizations, public.organization_settings, public.locations, public.space_kinds,
  public.spaces, public.space_hours, public.space_closures
from public, anon, authenticated;
grant all on table
  public.organizations, public.organization_settings, public.locations, public.space_kinds,
  public.spaces, public.space_hours, public.space_closures
to service_role;
