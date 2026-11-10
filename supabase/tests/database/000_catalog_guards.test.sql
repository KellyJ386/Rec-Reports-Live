-- Catalog guards (roadmap 1.6, "composite-key guard").
--
-- These read the system catalogs only, so they cover every table, foreign key
-- and function added by later migrations without being edited. A failure names
-- the offending objects. Allowlists below are deliberate and each carries its
-- reason; adding to one needs a reviewer to agree with that reason.
--
-- Notes for this directory (each *.test.sql runs on its own in one rolled-back
-- transaction, under `supabase test db` in CI and scripts/db/test-local.sh locally):
--   * pgTAP has no includes, so every file that needs data repeats the block between
--     "BEGIN SHARED FIXTURE" and "END SHARED FIXTURE". Edit one copy, then copy it to the rest.
--     Check they are in sync (prints one hash if they are):
--       for f in supabase/tests/database/*.test.sql; do
--         sed -n '/BEGIN SHARED FIXTURE/,/END SHARED FIXTURE/p' "$f"; done | grep -c . ;
--       for f in supabase/tests/database/*.test.sql; do sed -n '/BEGIN SHARED FIXTURE/,/END SHARED FIXTURE/p' "$f" | md5sum; done | sort | uniq -c
--     (files without a fixture, like this one, print the hash of empty input.)
--   * Test users are only ever inserted into auth.users (id, email). Identity is switched
--     with pg_temp.act_as('<user>') from the fixture, which sets role + request.jwt.claims.
begin;
-- Needed by `supabase test db` (a no-op if pgTAP is already there, as in scripts/db/test-local.sh).
create extension if not exists pgtap with schema extensions;
select plan(32);

-- Guarded objects: ordinary relations and functions in public/private that do
-- not belong to an extension.
create temp view gt as
  select c.oid, c.relname, c.relkind, n.nspname
  from pg_class c join pg_namespace n on n.oid = c.relnamespace
  where n.nspname in ('public', 'private')
    and c.relkind in ('r', 'p', 'v', 'm', 'f')
    and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e');
create temp view gtp as select * from gt where nspname = 'public' and relkind in ('r', 'p');
create temp view gf as
  select p.oid, p.proname, p.prosecdef, p.proconfig, n.nspname, p.oid::regprocedure::text as sig
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname in ('public', 'private')
    and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e');
create temp view gfk as
  select c.oid as conid, c.conname, c.conrelid, c.confrelid, c.conkey, c.confkey,
         cl.relname as child, pl.relname as parent,
         (select string_agg(a.attname, ',' order by k.i) from unnest(c.conkey) with ordinality k(attnum, i)
            join pg_attribute a on a.attrelid = c.conrelid and a.attnum = k.attnum) as child_cols
  from pg_constraint c
  join pg_class cl on cl.oid = c.conrelid and cl.relnamespace = 'public'::regnamespace
  join pg_class pl on pl.oid = c.confrelid and pl.relnamespace = 'public'::regnamespace
  where c.contype = 'f';
create function pg_temp.has_col(p_rel oid, p_col text) returns boolean language sql stable as $$
  select exists (select 1 from pg_attribute a where a.attrelid = p_rel and a.attname = p_col
                   and a.attnum > 0 and not a.attisdropped)
$$;
-- True when some column position pairs p_col on the child side with p_col on the parent side.
create function pg_temp.fk_pairs(p_conkey int2[], p_confkey int2[], p_child oid, p_parent oid, p_col text)
returns boolean language sql stable as $$
  select exists (
    select 1 from generate_subscripts(p_conkey, 1) i
    join pg_attribute a1 on a1.attrelid = p_child and a1.attnum = p_conkey[i]
    join pg_attribute a2 on a2.attrelid = p_parent and a2.attnum = p_confkey[i]
    where a1.attname = p_col and a2.attname = p_col)
$$;

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------
select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           join pg_class c on c.oid = t.oid where not c.relrowsecurity),
  '', 'every table in public has row level security enabled');

select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           where not exists (select 1 from pg_policy p where p.polrelid = t.oid)
             and t.relname not in ('platform_admins')),  -- platform_admins: service_role only, deliberately policy-less
  '', 'every table in public has at least one policy, except the policy-less allowlist (platform_admins)');

select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           where t.relname in ('platform_admins')
             and (exists (select 1 from pg_policy p where p.polrelid = t.oid)
                  or has_any_column_privilege('authenticated', t.oid, 'select,insert,update,references')
                  or has_table_privilege('authenticated', t.oid, 'delete,truncate,trigger'))),
  '', 'policy-less tables (platform_admins) have no policies and no privileges for authenticated');

select is((select coalesce(string_agg(x, ', '), '') from unnest(array['platform_admins']) x
           where x not in (select relname from gtp)),
  '', 'the policy-less allowlist has no stale entries');

select is((select coalesce(string_agg(t.relname || '.' || p.polname, ', ' order by t.relname, p.polname), '')
           from gtp t join pg_policy p on p.polrelid = t.oid
           where 0::oid = any (p.polroles) or (select oid from pg_roles where rolname = 'anon') = any (p.polroles)),
  '', 'no policy applies to anon or PUBLIC');

select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           where has_table_privilege('authenticated', t.oid, 'update,truncate,references,trigger')),
  '', 'authenticated has no table-level UPDATE, TRUNCATE, REFERENCES or TRIGGER in public (UPDATE is granted per column)');

select is((select coalesce(string_agg(g.nspname || '.' || g.relname, ', ' order by g.relname), '') from gt g
           join pg_class c on c.oid = g.oid
           where g.relkind in ('v', 'm') and not coalesce('security_invoker=true' = any (c.reloptions), false)),
  '', 'every view in public/private is security_invoker (a definer view bypasses RLS)');

-- ---------------------------------------------------------------------------
-- organization_id on every table
-- ---------------------------------------------------------------------------
-- organizations: the tenant root (its id is the organization). modules: global
-- lookup. platform_admins: platform scope (super_admin tier).
select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           where not pg_temp.has_col(t.oid, 'organization_id')
             and t.relname not in ('organizations', 'modules', 'platform_admins')),
  '', 'every table in public has organization_id, except organizations, modules and platform_admins');

select is((select coalesce(string_agg(x, ', '), '') from unnest(array['organizations', 'modules', 'platform_admins']) x
           where x not in (select relname from gtp)
              or pg_temp.has_col((select oid from gtp where relname = x), 'organization_id')),
  '', 'the no-organization_id allowlist has no stale entries');

-- roles / role_default_permissions: null = system (global) row. audit_log: null = platform row.
select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           join pg_attribute a on a.attrelid = t.oid and a.attname = 'organization_id' and not a.attisdropped
           where (a.atttypid <> 'uuid'::regtype or not a.attnotnull)
             and t.relname not in ('roles', 'role_default_permissions', 'audit_log')),
  '', 'organization_id is uuid NOT NULL on every table, except roles, role_default_permissions and audit_log (null = system/platform row)');

-- audit_log has no foreign keys on purpose: its rows outlive the rows and organizations they describe.
select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           where pg_temp.has_col(t.oid, 'organization_id') and t.relname <> 'audit_log'
             and not exists (select 1 from gfk f where f.conrelid = t.oid and f.parent = 'organizations'
                             and f.child_cols = 'organization_id')),
  '', 'every tenant table has a foreign key organization_id -> organizations(id), except audit_log');

select is((select coalesce(string_agg(f.child || '(' || f.child_cols || ')', ', ' order by f.child), '') from gfk f
           where f.parent = 'organizations' and f.child_cols <> 'organization_id'),
  '', 'foreign keys to organizations come only from organization_id');

-- organization_id is immutable, for every role (private.tg_immutable_columns). audit_log
-- is covered by the append-only trigger instead.
select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           where pg_temp.has_col(t.oid, 'organization_id') and t.relname <> 'audit_log'
             -- role_default_permissions: organization_id is derived from the immutable role_id by a trigger.
             and t.relname <> 'role_default_permissions'
             and not exists (
               select 1 from pg_trigger g
               where g.tgrelid = t.oid and not g.tgisinternal
                 and g.tgfoid = 'private.tg_immutable_columns'::regproc
                 and (g.tgtype & 2) <> 0 and (g.tgtype & 16) <> 0   -- BEFORE ... UPDATE
                 and 'organization_id' = any (regexp_split_to_array(encode(g.tgargs, 'escape'), '\\000')))),
  '', 'every tenant table has an immutable-organization_id trigger (before update), except audit_log and role_default_permissions (derived from role_id)');

select is((select coalesce(string_agg(t.relname, ', ' order by t.relname), '') from gtp t
           where t.relname <> 'audit_log'
             and not exists (select 1 from pg_trigger g where g.tgrelid = t.oid and g.tgname = 'zz_audit'
                             and g.tgfoid = 'private.tg_audit_row'::regproc and not g.tgisinternal)),
  '', 'every table in public except audit_log has the zz_audit trigger (private.enable_audit)');

-- ---------------------------------------------------------------------------
-- Composite foreign keys
-- ---------------------------------------------------------------------------
-- Allowlist, with reasons:
--   role_assignments.role_id, role_default_permissions.role_id -> roles(id): system
--   roles have organization_id null, so the pair cannot match. Triggers require
--   "system role or custom role of the same organization".
select is((select coalesce(string_agg(f.child || '(' || f.child_cols || ') -> ' || f.parent, ', ' order by f.child, f.child_cols), '')
           from gfk f
           where pg_temp.has_col(f.conrelid, 'organization_id') and pg_temp.has_col(f.confrelid, 'organization_id')
             and not pg_temp.fk_pairs(f.conkey, f.confkey, f.conrelid, f.confrelid, 'organization_id')
             and (f.child, f.child_cols) not in (('role_assignments', 'role_id'), ('role_default_permissions', 'role_id'))),
  '', 'every foreign key between two tenant tables includes organization_id on both sides');

select is((select coalesce(string_agg(x.c || '(' || x.k || ')', ', '), '') from (values
             ('role_assignments', 'role_id'), ('role_default_permissions', 'role_id')) x (c, k)
           where not exists (select 1 from gfk f where f.child = x.c and f.child_cols = x.k and f.parent = 'roles')),
  '', 'the composite-key exception allowlist (role_id -> roles) has no stale entries');

select is((select coalesce(string_agg(f.child || '(' || f.child_cols || ') -> ' || f.parent, ', ' order by f.child, f.child_cols), '')
           from gfk f
           where pg_temp.has_col(f.conrelid, 'location_id') and pg_temp.has_col(f.confrelid, 'location_id')
             and not pg_temp.fk_pairs(f.conkey, f.confkey, f.conrelid, f.confrelid, 'location_id')),
  '', 'a foreign key from a location-scoped table to a location-scoped parent also pairs location_id (a child stays in its parent''s location)');

-- ---------------------------------------------------------------------------
-- Every foreign key has an index whose leading columns cover it (partial indexes count).
-- ---------------------------------------------------------------------------
select is((select coalesce(string_agg(f.child || '(' || f.child_cols || ')', ', ' order by f.child, f.child_cols), '')
           from gfk f
           where not exists (
             select 1 from pg_index i
             where i.indrelid = f.conrelid and i.indisvalid
               and array_length(f.conkey, 1) <= i.indnkeyatts
               and (select array_agg(k order by k) from unnest((i.indkey::int2[])[0:array_length(f.conkey, 1) - 1]) k)
                   = (select array_agg(k order by k) from unnest(f.conkey) k))),
  '', 'every foreign key in public has a covering index (leading columns)');

-- ---------------------------------------------------------------------------
-- anon and PUBLIC hold nothing in public or private
-- ---------------------------------------------------------------------------
select is((select coalesce(string_agg(g.nspname || '.' || g.relname, ', ' order by g.relname), '') from gt g
           where has_table_privilege('anon', g.oid, 'select,insert,update,delete,truncate,references,trigger')),
  '', 'anon (and PUBLIC through it) has no table privilege in public or private');

select is((select coalesce(string_agg(g.nspname || '.' || g.relname, ', ' order by g.relname), '') from gt g
           where has_any_column_privilege('anon', g.oid, 'select,insert,update,references')),
  '', 'anon has no column privilege in public or private');

select is((select coalesce(string_agg(n.nspname || '.' || c.relname, ', ' order by c.relname), '')
           from pg_class c join pg_namespace n on n.oid = c.relnamespace
           where n.nspname in ('public', 'private') and c.relkind = 'S'
             and case when c.relkind = 'S' then has_sequence_privilege('anon', c.oid, 'usage,select,update') end),
  '', 'anon has no sequence privilege in public or private');

select is((select coalesce(string_agg(sig, ', ' order by sig), '') from gf where has_function_privilege('anon', oid, 'execute')),
  '', 'anon (and PUBLIC through it) cannot execute any function in public or private');

select is((select coalesce(string_agg(g.nspname || '.' || g.relname, ', ' order by g.relname), '') from gt g
           join pg_class c on c.oid = g.oid, aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a
           where a.grantee = 0),
  '', 'PUBLIC is granted nothing on any table in public or private');

select is((select coalesce(string_agg(g.nspname || '.' || g.relname || '.' || at.attname, ', ' order by g.relname), '') from gt g
           join pg_attribute at on at.attrelid = g.oid and at.attacl is not null, aclexplode(at.attacl) a
           where a.grantee = 0),
  '', 'PUBLIC is granted nothing on any column in public or private');

select is((select coalesce(string_agg(n.nspname || '.' || c.relname, ', ' order by c.relname), '')
           from pg_class c join pg_namespace n on n.oid = c.relnamespace,
                aclexplode(coalesce(c.relacl, acldefault('s', c.relowner))) a
           where n.nspname in ('public', 'private') and c.relkind = 'S' and a.grantee = 0),
  '', 'PUBLIC is granted nothing on any sequence in public or private');

-- A null proacl means the default ACL, which gives PUBLIC execute.
select is((select coalesce(string_agg(g.sig, ', ' order by g.sig), '') from gf g
           join pg_proc p on p.oid = g.oid, aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
           where a.grantee = 0),
  '', 'PUBLIC cannot execute any function in public or private (no function left on the default ACL)');

select is((select coalesce(string_agg(nspname, ', '), '') from pg_namespace
           where nspname = 'private' and (has_schema_privilege('anon', oid, 'usage,create')
             or exists (select 1 from aclexplode(coalesce(nspacl, acldefault('n', nspowner))) a where a.grantee = 0 and a.privilege_type in ('USAGE', 'CREATE')))),
  '', 'anon and PUBLIC have no access to schema private');

select is((select coalesce(string_agg(nspname, ', '), '') from pg_namespace
           where nspname in ('public', 'private')
             and (has_schema_privilege('anon', oid, 'create') or has_schema_privilege('authenticated', oid, 'create'))),
  '', 'neither anon nor authenticated can create objects in public or private');

-- ---------------------------------------------------------------------------
-- SECURITY DEFINER functions
-- ---------------------------------------------------------------------------
select is((select coalesce(string_agg(sig, ', ' order by sig), '') from gf
           where prosecdef and not exists (select 1 from unnest(coalesce(proconfig, '{}')) c where c like 'search_path=%')),
  '', 'every SECURITY DEFINER function in public/private has a fixed search_path');

select is((select coalesce(string_agg(sig, ', ' order by sig), '') from gf
           where prosecdef and exists (select 1 from unnest(coalesce(proconfig, '{}')) c
                                       where c like 'search_path=%' and (c ~ '(^|[=, "])public([, "]|$)' or c like '%$user%'))),
  '', 'no SECURITY DEFINER function has public or $user on its search_path');

select is((select coalesce(string_agg(sig, ', ' order by sig), '') from gf
           where prosecdef and nspname = 'public' and has_function_privilege('authenticated', oid, 'execute')
             and proname not in ('is_platform_admin', 'auth_org_ids', 'auth_location_ids', 'current_person_id', 'has_role',
                                 'actor_rank', 'effective_permission', 'has_permission',
                                 'create_person_with_assignment', 'update_own_profile')),
  '', 'only the reviewed SECURITY DEFINER functions in public are callable by authenticated through /rpc (add new ones here on purpose)');

select is((select coalesce(string_agg(x, ', '), '') from unnest(array[
             'is_platform_admin', 'auth_org_ids', 'auth_location_ids', 'current_person_id', 'has_role',
             'actor_rank', 'effective_permission', 'has_permission',
             'create_person_with_assignment', 'update_own_profile']) x
           where not exists (select 1 from gf where gf.nspname = 'public' and gf.proname = x and gf.prosecdef)),
  '', 'the /rpc allowlist has no stale entries');

select * from finish();
rollback;
