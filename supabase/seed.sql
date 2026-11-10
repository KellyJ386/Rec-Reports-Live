-- Mock data for local development and the pilot test environments.
--
-- MOCK ONLY: no real facility, no real person, and every email uses example.com.
-- Runs as the database owner (psql / migration role), so it may create the
-- org-scope admin assignment that tenants cannot create themselves.
--
-- Idempotent: every row has a fixed UUID and is inserted with ON CONFLICT DO NOTHING,
-- and the rows that have no natural key (hours) are guarded with NOT EXISTS.
-- Does NOT touch auth.users, accounts or platform_admins (see scripts/seed-users.mjs
-- for auth users and accounts).
--
-- Fixed-ID scheme (all UUIDs are valid RFC 9562 version 4):
--   organizations 10000000-...-00000000000N   locations 20000000-...
--   spaces        30000000-...-0000000000NN   people    40000000-...
--   role_assignments 70000000-...             person_job_titles 80000000-...
--   job_titles    50000000-... (Lakeside), 51000000-... (Summit)
--   closures      90000000-...
-- (Each row's UUID is "<prefix>-0000-4000-8000-0000000000<NN>".)

-- ---------------------------------------------------------------------------
-- Organizations. The insert trigger creates organization_settings and the
-- default space_kinds (pool, gym, court, studio, rink, field, room, other).
-- ---------------------------------------------------------------------------
insert into public.organizations (id, name, slug) values
  ('10000000-0000-4000-8000-000000000001', 'Lakeside Parks & Recreation (Mock)', 'lakeside-parks-mock'),
  ('10000000-0000-4000-8000-000000000002', 'Summit Valley Recreation District (Mock)', 'summit-valley-mock')
on conflict do nothing;

update public.organization_settings
set default_timezone = 'America/Denver'
where organization_id = '10000000-0000-4000-8000-000000000002'
  and default_timezone <> 'America/Denver';

-- ---------------------------------------------------------------------------
-- Locations
-- ---------------------------------------------------------------------------
insert into public.locations (id, organization_id, name, code, timezone, address) values
  ('20000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001',
   'Lakeside Community Center', 'LCC', 'America/New_York', '100 Mock Lane (example)'),
  ('20000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001',
   'Riverbend Aquatic & Fitness Center', 'RAC', 'America/New_York', '200 Mock Road (example)'),
  ('20000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000002',
   'Summit Valley Fieldhouse', 'SVF', 'America/Denver', '300 Mock Trail (example)')
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Spaces. Top-level first, then sub-spaces (a sub-space must reference a parent
-- that is already inserted, and a parent cannot itself be a sub-space).
-- Kind subqueries look up the org's space_kinds by key.
-- ---------------------------------------------------------------------------
insert into public.spaces (id, organization_id, location_id, space_kind_id, parent_space_id, name, capacity, sort_order) values
  -- Lakeside Community Center
  ('30000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'gym'),
   null, 'Main Gym', 60, 10),
  ('30000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'studio'),
   null, 'Fitness Studio', 30, 20),
  ('30000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'pool'),
   null, 'Pool', 40, 30),
  ('30000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'court'),
   null, 'Basketball Court', 20, 40),
  ('30000000-0000-4000-8000-000000000007', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'room'),
   null, 'Meeting Room A', 16, 50),
  ('30000000-0000-4000-8000-000000000008', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'other'),
   null, 'Front Desk', null, 60),
  -- Riverbend Aquatic & Fitness Center
  ('30000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'pool'),
   null, 'Lap Pool', 50, 10),
  ('30000000-0000-4000-8000-000000000015', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'gym'),
   null, 'Fitness Room', 35, 20),
  ('30000000-0000-4000-8000-000000000016', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'studio'),
   null, 'Cardio Studio', 25, 30),
  ('30000000-0000-4000-8000-000000000017', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'court'),
   null, 'Racquetball Court', 2, 40),
  ('30000000-0000-4000-8000-000000000018', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'other'),
   null, 'Front Desk', null, 60),
  -- Summit Valley Fieldhouse (second organization; tenant isolation test data)
  ('30000000-0000-4000-8000-000000000021', '10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000003',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000002' and k.key = 'court'),
   null, 'Main Court', 30, 10),
  ('30000000-0000-4000-8000-000000000022', '10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000003',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000002' and k.key = 'field'),
   null, 'Turf Field', 80, 20),
  ('30000000-0000-4000-8000-000000000023', '10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000003',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000002' and k.key = 'room'),
   null, 'Multipurpose Room', 40, 30),
  ('30000000-0000-4000-8000-000000000024', '10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000003',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000002' and k.key = 'other'),
   null, 'Front Desk', null, 40)
on conflict do nothing;

insert into public.spaces (id, organization_id, location_id, space_kind_id, parent_space_id, name, capacity, sort_order) values
  -- Lanes of the Lakeside pool
  ('30000000-0000-4000-8000-000000000004', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'pool'),
   '30000000-0000-4000-8000-000000000003', 'Lane 1', 10, 10),
  ('30000000-0000-4000-8000-000000000005', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'pool'),
   '30000000-0000-4000-8000-000000000003', 'Lane 2', 10, 20),
  -- Lanes of the Riverbend lap pool
  ('30000000-0000-4000-8000-000000000012', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'pool'),
   '30000000-0000-4000-8000-000000000011', 'Lane 1', 12, 10),
  ('30000000-0000-4000-8000-000000000013', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'pool'),
   '30000000-0000-4000-8000-000000000011', 'Lane 2', 12, 20),
  ('30000000-0000-4000-8000-000000000014', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   (select k.id from public.space_kinds k where k.organization_id = '10000000-0000-4000-8000-000000000001' and k.key = 'pool'),
   '30000000-0000-4000-8000-000000000011', 'Lane 3', 12, 30)
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Weekly hours for top-level spaces (sub-spaces inherit their parent's hours).
-- ISO days: 1 = Monday .. 7 = Sunday. No natural key, so guard with NOT EXISTS.
-- ---------------------------------------------------------------------------
insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
select s.organization_id, s.location_id, s.id, d.day,
       case when d.day <= 5 then time '06:00' when d.day = 6 then time '08:00' else time '10:00' end,
       case when d.day <= 5 then time '21:00' when d.day = 6 then time '18:00' else time '17:00' end
from public.spaces s
cross join generate_series(1, 7) as d (day)
where s.organization_id in ('10000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002')
  and s.parent_space_id is null
  and s.name <> 'Front Desk'
  and not exists (
    select 1 from public.space_hours h
    where h.space_id = s.id and h.day_of_week = d.day and h.effective_from is null);

insert into public.space_hours (organization_id, location_id, space_id, day_of_week, opens_at, closes_at)
select s.organization_id, s.location_id, s.id, d.day, time '06:00', time '22:00'
from public.spaces s
cross join generate_series(1, 7) as d (day)
where s.organization_id in ('10000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002')
  and s.parent_space_id is null
  and s.name = 'Front Desk'
  and not exists (
    select 1 from public.space_hours h
    where h.space_id = s.id and h.day_of_week = d.day and h.effective_from is null);

-- ---------------------------------------------------------------------------
-- One closure per location (whole location closed, space_id null).
-- ---------------------------------------------------------------------------
insert into public.space_closures (id, organization_id, location_id, space_id, starts_at, ends_at, reason) values
  ('90000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001',
   null, '2027-01-01T00:00:00-05:00', '2027-01-02T00:00:00-05:00', 'New Year closure (mock)'),
  ('90000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002',
   null, '2027-01-01T00:00:00-05:00', '2027-01-02T00:00:00-05:00', 'New Year closure (mock)'),
  ('90000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000003',
   null, '2027-01-01T00:00:00-07:00', '2027-01-02T00:00:00-07:00', 'New Year closure (mock)')
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Job titles (routing only; they grant no permissions).
-- ---------------------------------------------------------------------------
insert into public.job_titles (id, organization_id, name) values
  ('50000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'Lifeguard'),
  ('50000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', 'Front Desk'),
  ('50000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000001', 'Building Supervisor'),
  ('50000000-0000-4000-8000-000000000004', '10000000-0000-4000-8000-000000000001', 'Facility Attendant'),
  ('50000000-0000-4000-8000-000000000005', '10000000-0000-4000-8000-000000000001', 'Aquatics Coordinator'),
  ('51000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000002', 'Front Desk'),
  ('51000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000002', 'Facility Attendant'),
  ('51000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000002', 'Building Supervisor')
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- People (no accounts here). Email domain is example.com only.
-- Lakeside: 1 org admin; per location 1 location admin, 2 managers, 5 staff.
-- Summit Valley: 1 org admin, 1 manager, 3 staff.
-- ---------------------------------------------------------------------------
insert into public.people (id, organization_id, first_name, last_name, email) values
  -- Lakeside organization admin
  ('40000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', 'Morgan', 'Mock', 'lakeside.org.admin@example.com'),
  -- Lakeside Community Center (LCC)
  ('40000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', 'Riley', 'Mock', 'lcc.admin@example.com'),
  ('40000000-0000-4000-8000-000000000004', '10000000-0000-4000-8000-000000000001', 'Jamie', 'Mock', 'lcc.manager1@example.com'),
  ('40000000-0000-4000-8000-000000000005', '10000000-0000-4000-8000-000000000001', 'Taylor', 'Mock', 'lcc.manager2@example.com'),
  ('40000000-0000-4000-8000-000000000008', '10000000-0000-4000-8000-000000000001', 'Casey', 'Mock', 'lcc.staff1@example.com'),
  ('40000000-0000-4000-8000-000000000009', '10000000-0000-4000-8000-000000000001', 'Drew', 'Mock', 'lcc.staff2@example.com'),
  ('40000000-0000-4000-8000-000000000010', '10000000-0000-4000-8000-000000000001', 'Quinn', 'Mock', 'lcc.staff3@example.com'),
  ('40000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000001', 'Avery', 'Mock', 'lcc.staff4@example.com'),
  ('40000000-0000-4000-8000-000000000012', '10000000-0000-4000-8000-000000000001', 'Sam', 'Mock', 'lcc.staff5@example.com'),
  -- Riverbend Aquatic & Fitness Center (RAC)
  ('40000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000001', 'Parker', 'Mock', 'rac.admin@example.com'),
  ('40000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000001', 'Reese', 'Mock', 'rac.manager1@example.com'),
  ('40000000-0000-4000-8000-000000000007', '10000000-0000-4000-8000-000000000001', 'Logan', 'Mock', 'rac.manager2@example.com'),
  ('40000000-0000-4000-8000-000000000013', '10000000-0000-4000-8000-000000000001', 'Harper', 'Mock', 'rac.staff1@example.com'),
  ('40000000-0000-4000-8000-000000000014', '10000000-0000-4000-8000-000000000001', 'Rowan', 'Mock', 'rac.staff2@example.com'),
  ('40000000-0000-4000-8000-000000000015', '10000000-0000-4000-8000-000000000001', 'Emery', 'Mock', 'rac.staff3@example.com'),
  ('40000000-0000-4000-8000-000000000016', '10000000-0000-4000-8000-000000000001', 'Skyler', 'Mock', 'rac.staff4@example.com'),
  ('40000000-0000-4000-8000-000000000017', '10000000-0000-4000-8000-000000000001', 'Finley', 'Mock', 'rac.staff5@example.com'),
  -- Summit Valley Recreation District
  ('40000000-0000-4000-8000-000000000021', '10000000-0000-4000-8000-000000000002', 'Dana', 'Mock', 'summit.org.admin@example.com'),
  ('40000000-0000-4000-8000-000000000022', '10000000-0000-4000-8000-000000000002', 'Blake', 'Mock', 'summit.manager@example.com'),
  ('40000000-0000-4000-8000-000000000023', '10000000-0000-4000-8000-000000000002', 'Robin', 'Mock', 'summit.staff1@example.com'),
  ('40000000-0000-4000-8000-000000000024', '10000000-0000-4000-8000-000000000002', 'Kendall', 'Mock', 'summit.staff2@example.com'),
  ('40000000-0000-4000-8000-000000000025', '10000000-0000-4000-8000-000000000002', 'Shay', 'Mock', 'summit.staff3@example.com')
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Role assignments. Role ids come from the system roles (organization_id null).
-- Org-scope assignments (location_id null) are allowed only for the admin role.
-- ---------------------------------------------------------------------------
insert into public.role_assignments (id, organization_id, person_id, role_id, location_id) values
  -- Lakeside
  ('70000000-0000-4000-8000-000000000001', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000001',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'admin'), null),
  ('70000000-0000-4000-8000-000000000002', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000002',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'admin'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000003', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000003',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'admin'), '20000000-0000-4000-8000-000000000002'),
  ('70000000-0000-4000-8000-000000000004', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000004',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'manager'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000005', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000005',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'manager'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000006',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'manager'), '20000000-0000-4000-8000-000000000002'),
  ('70000000-0000-4000-8000-000000000007', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000007',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'manager'), '20000000-0000-4000-8000-000000000002'),
  ('70000000-0000-4000-8000-000000000008', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000008',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000009', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000009',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000010', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000010',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000011',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000012', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000012',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000001'),
  ('70000000-0000-4000-8000-000000000013', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000013',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000002'),
  ('70000000-0000-4000-8000-000000000014', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000014',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000002'),
  ('70000000-0000-4000-8000-000000000015', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000015',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000002'),
  ('70000000-0000-4000-8000-000000000016', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000016',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000002'),
  ('70000000-0000-4000-8000-000000000017', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000017',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000002'),
  -- Summit Valley
  ('70000000-0000-4000-8000-000000000021', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000021',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'admin'), null),
  ('70000000-0000-4000-8000-000000000022', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000022',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'manager'), '20000000-0000-4000-8000-000000000003'),
  ('70000000-0000-4000-8000-000000000023', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000023',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000003'),
  ('70000000-0000-4000-8000-000000000024', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000024',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000003'),
  ('70000000-0000-4000-8000-000000000025', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000025',
   (select r.id from public.roles r where r.organization_id is null and r.key = 'staff'), '20000000-0000-4000-8000-000000000003')
on conflict do nothing;

-- ---------------------------------------------------------------------------
-- Job titles per person (routing only).
-- ---------------------------------------------------------------------------
insert into public.person_job_titles (id, organization_id, person_id, job_title_id, location_id) values
  ('80000000-0000-4000-8000-000000000004', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000004', '50000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000001'),
  ('80000000-0000-4000-8000-000000000005', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000005', '50000000-0000-4000-8000-000000000005', '20000000-0000-4000-8000-000000000001'),
  ('80000000-0000-4000-8000-000000000006', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000006', '50000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000002'),
  ('80000000-0000-4000-8000-000000000007', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000007', '50000000-0000-4000-8000-000000000005', '20000000-0000-4000-8000-000000000002'),
  ('80000000-0000-4000-8000-000000000008', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000008', '50000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001'),
  ('80000000-0000-4000-8000-000000000009', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000009', '50000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000001'),
  ('80000000-0000-4000-8000-000000000010', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000010', '50000000-0000-4000-8000-000000000004', '20000000-0000-4000-8000-000000000001'),
  ('80000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000011', '50000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000001'),
  ('80000000-0000-4000-8000-000000000012', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000012', '50000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000001'),
  ('80000000-0000-4000-8000-000000000013', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000013', '50000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002'),
  ('80000000-0000-4000-8000-000000000014', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000014', '50000000-0000-4000-8000-000000000004', '20000000-0000-4000-8000-000000000002'),
  ('80000000-0000-4000-8000-000000000015', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000015', '50000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000002'),
  ('80000000-0000-4000-8000-000000000016', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000016', '50000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000002'),
  ('80000000-0000-4000-8000-000000000017', '10000000-0000-4000-8000-000000000001', '40000000-0000-4000-8000-000000000017', '50000000-0000-4000-8000-000000000004', '20000000-0000-4000-8000-000000000002'),
  ('80000000-0000-4000-8000-000000000022', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000022', '51000000-0000-4000-8000-000000000003', '20000000-0000-4000-8000-000000000003'),
  ('80000000-0000-4000-8000-000000000023', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000023', '51000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000003'),
  ('80000000-0000-4000-8000-000000000024', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000024', '51000000-0000-4000-8000-000000000002', '20000000-0000-4000-8000-000000000003'),
  ('80000000-0000-4000-8000-000000000025', '10000000-0000-4000-8000-000000000002', '40000000-0000-4000-8000-000000000025', '51000000-0000-4000-8000-000000000001', '20000000-0000-4000-8000-000000000003')
on conflict do nothing;
