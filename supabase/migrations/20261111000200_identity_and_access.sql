-- Phase 1 (roadmap 1.3/1.4): people, accounts, roles, permissions, job titles,
-- platform admins. Policies and grants: 20261111000300_rls_helpers_and_policies.sql.

-- ---------------------------------------------------------------------------
-- platform_admins: Max Facility staff (the super_admin tier). Platform scope,
-- not a tenant role assignment. Written only by service_role / migrations.
-- ---------------------------------------------------------------------------
create table public.platform_admins (
  user_id uuid primary key references auth.users (id) on delete cascade,
  note text check (char_length(note) <= 500),
  created_at timestamptz not null default now()
);

-- ---------------------------------------------------------------------------
-- Permission levels, ordered: none < view < edit < admin (enum order is used
-- for comparisons, so never reorder; add new levels with BEFORE/AFTER).
-- ---------------------------------------------------------------------------
create type public.permission_level as enum ('none', 'view', 'edit', 'admin');

-- ---------------------------------------------------------------------------
-- modules: global lookup, one stable key per roadmap module. PK is the key.
-- ---------------------------------------------------------------------------
create table public.modules (
  key text primary key check (key ~ '^[a-z][a-z0-9_]{0,62}$'),
  name text not null,
  sort_order integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create trigger modules_timestamps before insert or update on public.modules
  for each row execute function private.tg_set_timestamps();
create trigger modules_immutable before update on public.modules
  for each row execute function private.tg_immutable_columns('key');

insert into public.modules (key, name, sort_order) values
  ('locations_spaces',      'Locations and spaces',    10),
  ('people_roles',          'People and roles',        20),
  ('audit_log',             'Audit log',               30),
  ('communications',        'Communications',          40),
  ('tasks',                 'Tasks',                   50),
  ('staff_schedule',        'Staff schedule',          60),
  ('availability_time_off', 'Availability and time off', 70),
  ('shift_swaps',           'Shift swaps',             80),
  ('time_clock',            'Time clock',              90),
  ('timesheets',            'Timesheets',             100),
  ('certifications',        'Certifications',         110),
  ('forms',                 'Forms',                  120),
  ('checklists',            'Checklists',             130),
  ('incidents',             'Incidents',              140),
  ('accidents',             'Accidents',              150),
  ('daily_log',             'Daily log',              160),
  ('headcounts',            'Headcounts',             170),
  ('facility_schedule',     'Facility schedule',      180),
  ('equipment',             'Equipment',              190),
  ('maintenance',           'Maintenance',            200),
  ('documents',             'Documents',              210),
  ('reports',               'Reports',                220);

-- ---------------------------------------------------------------------------
-- roles: system roles (organization_id null) + per-organization custom roles.
-- rank orders the tier rule. System ranks: super_admin 100, admin 80,
-- manager 50, staff 10. Custom roles: 1..79 (strictly below admin).
-- An organization-scope assignment counts 10 higher than the same role at a
-- location (see SECURITY.md "Effective rank"), so org admin = 90.
-- ---------------------------------------------------------------------------
create table public.roles (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references public.organizations (id) on delete cascade, -- null = system role
  key text not null check (key ~ '^[a-z][a-z0-9_]{1,62}$'),
  name text not null check (char_length(btrim(name)) between 1 and 100),
  description text check (char_length(description) <= 1000),
  rank integer not null,
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique nulls not distinct (organization_id, key),
  unique (id, organization_id),
  constraint roles_retired_keys check (key not in ('org_admin', 'facility_manager', 'gm', 'supervisor')),
  constraint roles_custom_key_not_system check (
    organization_id is null or key not in ('super_admin', 'admin', 'manager', 'staff')),
  constraint roles_rank_range check (
    (organization_id is null and rank between 1 and 100)
    or (organization_id is not null and rank between 1 and 79))
);

create index roles_organization_id_idx on public.roles (organization_id) where organization_id is not null;

create trigger roles_timestamps before insert or update on public.roles
  for each row execute function private.tg_set_timestamps();
create trigger roles_immutable before update on public.roles
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'key');

insert into public.roles (organization_id, key, name, rank, description) values
  (null, 'super_admin', 'Super admin', 100, 'Max Facility platform staff. Granted through platform_admins, never assigned in a tenant.'),
  (null, 'admin',       'Admin',        80, 'Users, roles, settings and everything in scope (organization or one location).'),
  (null, 'manager',     'Manager',      50, 'Runs a location: spaces, templates, forms, schedules, incident review.'),
  (null, 'staff',       'Staff',        10, 'Own shifts and tasks, checklists, filing incidents, reading notices.');

-- ---------------------------------------------------------------------------
-- role_default_permissions: module x level per role. organization_id is
-- derived from the role (null for system roles) by trigger.
-- ---------------------------------------------------------------------------
create table public.role_default_permissions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid references public.organizations (id) on delete cascade, -- = roles.organization_id
  role_id uuid not null references public.roles (id) on delete cascade,
  module_key text not null references public.modules (key),
  level public.permission_level not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (role_id, module_key)
);

create index role_default_permissions_module_idx on public.role_default_permissions (module_key);
create index role_default_permissions_org_idx on public.role_default_permissions (organization_id)
  where organization_id is not null;

create function private.tg_role_default_permissions_org()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  select r.organization_id into new.organization_id from public.roles r where r.id = new.role_id;
  return new;
end;
$$;
revoke all on function private.tg_role_default_permissions_org() from public, anon, authenticated;

create trigger role_default_permissions_org before insert or update on public.role_default_permissions
  for each row execute function private.tg_role_default_permissions_org();
create trigger role_default_permissions_timestamps before insert or update on public.role_default_permissions
  for each row execute function private.tg_set_timestamps();
create trigger role_default_permissions_immutable before update on public.role_default_permissions
  for each row execute function private.tg_immutable_columns('id', 'role_id', 'module_key');

-- Seed defaults for system roles.
-- admin: admin on everything. super_admin: same (informational; platform admins
-- bypass through is_platform_admin()).
insert into public.role_default_permissions (role_id, module_key, level)
select r.id, m.key, 'admin'::public.permission_level
from public.roles r cross join public.modules m
where r.organization_id is null and r.key in ('super_admin', 'admin');

insert into public.role_default_permissions (role_id, module_key, level)
select r.id, v.module_key, v.level::public.permission_level
from public.roles r
join (values
  -- manager: runs operations, no people/roles admin, no audit log, no
  -- accident (sensitive) access unless granted per person.
  ('manager', 'locations_spaces',      'edit'),
  ('manager', 'people_roles',          'edit'),  -- edit = assign job titles only
  ('manager', 'audit_log',             'none'),
  ('manager', 'communications',        'admin'),
  ('manager', 'tasks',                 'admin'),
  ('manager', 'staff_schedule',        'admin'),
  ('manager', 'availability_time_off', 'admin'),
  ('manager', 'shift_swaps',           'admin'),
  ('manager', 'time_clock',            'admin'),
  ('manager', 'timesheets',            'edit'),
  ('manager', 'certifications',        'admin'),
  ('manager', 'forms',                 'admin'),
  ('manager', 'checklists',            'admin'),
  ('manager', 'incidents',             'admin'),
  ('manager', 'accidents',             'none'),
  ('manager', 'daily_log',             'admin'),
  ('manager', 'headcounts',            'admin'),
  ('manager', 'facility_schedule',     'admin'),
  ('manager', 'equipment',             'admin'),
  ('manager', 'maintenance',           'admin'),
  ('manager', 'documents',             'edit'),
  ('manager', 'reports',               'view'),
  -- staff: front line.
  ('staff', 'locations_spaces',      'view'),
  ('staff', 'people_roles',          'none'),
  ('staff', 'audit_log',             'none'),
  ('staff', 'communications',        'edit'),
  ('staff', 'tasks',                 'edit'),
  ('staff', 'staff_schedule',        'view'),
  ('staff', 'availability_time_off', 'edit'),
  ('staff', 'shift_swaps',           'edit'),
  ('staff', 'time_clock',            'edit'),
  ('staff', 'timesheets',            'view'),
  ('staff', 'certifications',        'view'),
  ('staff', 'forms',                 'view'),
  ('staff', 'checklists',            'edit'),
  ('staff', 'incidents',             'edit'),
  ('staff', 'accidents',             'none'),
  ('staff', 'daily_log',             'edit'),
  ('staff', 'headcounts',            'edit'),
  ('staff', 'facility_schedule',     'view'),
  ('staff', 'equipment',             'view'),
  ('staff', 'maintenance',           'edit'),
  ('staff', 'documents',             'view'),
  ('staff', 'reports',               'none')
) as v (role_key, module_key, level) on v.role_key = r.key
where r.organization_id is null;

-- ---------------------------------------------------------------------------
-- people: business persons (staff today; customers/guardians later). A person
-- may have no account.
-- ---------------------------------------------------------------------------
create table public.people (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  first_name text not null check (char_length(btrim(first_name)) between 1 and 100),
  last_name text not null check (char_length(btrim(last_name)) between 1 and 100),
  preferred_name text check (char_length(preferred_name) <= 100),
  email text check (email ~ '^[^@\s]+@[^@\s]+$' and char_length(email) <= 320),
  phone text check (char_length(phone) <= 40),
  employee_number text check (char_length(employee_number) <= 50),
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id)
);

create index people_organization_id_idx on public.people (organization_id);
create index people_org_email_idx on public.people (organization_id, lower(email)) where email is not null;
create unique index people_org_employee_number_key on public.people (organization_id, employee_number)
  where employee_number is not null;

create trigger people_timestamps before insert or update on public.people
  for each row execute function private.tg_set_timestamps();
create trigger people_immutable before update on public.people
  for each row execute function private.tg_immutable_columns('id', 'organization_id');

-- ---------------------------------------------------------------------------
-- accounts: maps an auth.users row to a person. One auth user can have one
-- account per organization; one account per person.
-- ---------------------------------------------------------------------------
create table public.accounts (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null unique,
  user_id uuid not null references auth.users (id) on delete cascade,
  disabled_at timestamptz, -- set = signs in but is not a member of this organization
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, organization_id),
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade
);

create index accounts_organization_person_idx on public.accounts (organization_id, person_id);

create trigger accounts_timestamps before insert or update on public.accounts
  for each row execute function private.tg_set_timestamps();
create trigger accounts_immutable before update on public.accounts
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id', 'user_id');

-- ---------------------------------------------------------------------------
-- role_assignments: person holds role in scope. location_id null = whole
-- organization (only the admin role may be organization scoped).
-- role_id has a plain FK because system roles have organization_id null; the
-- trigger below enforces "system role or a custom role of the same org".
-- ---------------------------------------------------------------------------
create table public.role_assignments (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  role_id uuid not null references public.roles (id),
  location_id uuid,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique nulls not distinct (person_id, role_id, location_id),
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade,
  foreign key (location_id, organization_id) references public.locations (id, organization_id)
);

create index role_assignments_org_person_idx on public.role_assignments (organization_id, person_id);
create index role_assignments_role_idx on public.role_assignments (role_id);
create index role_assignments_org_location_idx on public.role_assignments (organization_id, location_id)
  where location_id is not null;

create function private.tg_role_assignments_validate()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_role public.roles%rowtype;
begin
  select * into v_role from public.roles r where r.id = new.role_id;
  if not found then
    raise exception 'role % does not exist', new.role_id using errcode = 'foreign_key_violation';
  end if;
  if v_role.organization_id is not null and v_role.organization_id <> new.organization_id then
    raise exception 'role belongs to another organization' using errcode = 'foreign_key_violation';
  end if;
  if v_role.key = 'super_admin' then
    raise exception 'super_admin is granted through platform_admins, not role_assignments'
      using errcode = 'check_violation';
  end if;
  if v_role.archived_at is not null then
    raise exception 'role is archived' using errcode = 'check_violation';
  end if;
  if new.location_id is null and (v_role.organization_id is not null or v_role.key <> 'admin') then
    raise exception 'only the admin role can be organization scoped; % needs a location', v_role.key
      using errcode = 'check_violation';
  end if;
  return new;
end;
$$;
revoke all on function private.tg_role_assignments_validate() from public, anon, authenticated;

create trigger role_assignments_validate before insert or update on public.role_assignments
  for each row execute function private.tg_role_assignments_validate();
create trigger role_assignments_timestamps before insert or update on public.role_assignments
  for each row execute function private.tg_set_timestamps();
create trigger role_assignments_immutable before update on public.role_assignments
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id');

-- ---------------------------------------------------------------------------
-- user_permissions: per-person OVERRIDE of the role default for one module,
-- organization wide (location_id null) or at one location. Grants nothing on
-- its own: the person must also hold a role assignment covering the scope.
-- ---------------------------------------------------------------------------
create table public.user_permissions (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  location_id uuid,
  module_key text not null references public.modules (key),
  level public.permission_level not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique nulls not distinct (person_id, module_key, location_id),
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade,
  foreign key (location_id, organization_id) references public.locations (id, organization_id)
);

create index user_permissions_org_person_idx on public.user_permissions (organization_id, person_id);
create index user_permissions_org_location_idx on public.user_permissions (organization_id, location_id)
  where location_id is not null;
create index user_permissions_module_idx on public.user_permissions (module_key);

create trigger user_permissions_timestamps before insert or update on public.user_permissions
  for each row execute function private.tg_set_timestamps();
create trigger user_permissions_immutable before update on public.user_permissions
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id', 'location_id', 'module_key');

-- ---------------------------------------------------------------------------
-- job_titles / person_job_titles: routing only ("Lifeguard", "Front Desk",
-- "Supervisor"). They grant NOTHING; no policy may read them for access.
-- ---------------------------------------------------------------------------
create table public.job_titles (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  name text not null check (char_length(btrim(name)) between 1 and 100),
  archived_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (id, organization_id)
);

create index job_titles_organization_id_idx on public.job_titles (organization_id);
create unique index job_titles_org_name_active_key on public.job_titles (organization_id, lower(name))
  where archived_at is null;

create trigger job_titles_timestamps before insert or update on public.job_titles
  for each row execute function private.tg_set_timestamps();
create trigger job_titles_immutable before update on public.job_titles
  for each row execute function private.tg_immutable_columns('id', 'organization_id');

create table public.person_job_titles (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references public.organizations (id) on delete cascade,
  person_id uuid not null,
  job_title_id uuid not null,
  location_id uuid, -- null = at every location the person works
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique nulls not distinct (person_id, job_title_id, location_id),
  foreign key (person_id, organization_id) references public.people (id, organization_id) on delete cascade,
  foreign key (job_title_id, organization_id) references public.job_titles (id, organization_id),
  foreign key (location_id, organization_id) references public.locations (id, organization_id)
);

create index person_job_titles_org_person_idx on public.person_job_titles (organization_id, person_id);
create index person_job_titles_org_title_idx on public.person_job_titles (organization_id, job_title_id);
create index person_job_titles_org_location_idx on public.person_job_titles (organization_id, location_id)
  where location_id is not null;

create trigger person_job_titles_timestamps before insert or update on public.person_job_titles
  for each row execute function private.tg_set_timestamps();
create trigger person_job_titles_immutable before update on public.person_job_titles
  for each row execute function private.tg_immutable_columns('id', 'organization_id', 'person_id');

-- ---------------------------------------------------------------------------
-- RLS on, nothing granted yet.
-- ---------------------------------------------------------------------------
alter table public.platform_admins enable row level security;
alter table public.modules enable row level security;
alter table public.roles enable row level security;
alter table public.role_default_permissions enable row level security;
alter table public.people enable row level security;
alter table public.accounts enable row level security;
alter table public.role_assignments enable row level security;
alter table public.user_permissions enable row level security;
alter table public.job_titles enable row level security;
alter table public.person_job_titles enable row level security;

revoke all on table
  public.platform_admins, public.modules, public.roles, public.role_default_permissions,
  public.people, public.accounts, public.role_assignments, public.user_permissions,
  public.job_titles, public.person_job_titles
from public, anon, authenticated;
grant all on table
  public.platform_admins, public.modules, public.roles, public.role_default_permissions,
  public.people, public.accounts, public.role_assignments, public.user_permissions,
  public.job_titles, public.person_job_titles
to service_role;
