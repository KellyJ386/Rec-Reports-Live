-- Functions that Postgres creates by itself (the constructors of a range type
-- and of its multirange type) do not go through CREATE FUNCTION. On hosted
-- Supabase they came out executable by PUBLIC and anon, which the catalog
-- guard test caught on its first run against a real Supabase database.
--
-- Close it for every function in public and private, whatever created it, so
-- a later implicit function cannot reopen the gap unnoticed. Functions owned
-- by an extension are left alone. Grants to authenticated and service_role
-- are not touched.
do $$
declare
  r record;
begin
  for r in
    select p.oid::regprocedure as sig
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('public', 'private')
      and not exists (
        select 1 from pg_catalog.pg_depend d where d.objid = p.oid and d.deptype = 'e'
      )
      and (
        pg_catalog.has_function_privilege('anon', p.oid, 'execute')
        or exists (
          select 1
          from pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) a
          where a.grantee = 0
        )
      )
  loop
    execute pg_catalog.format('revoke all on function %s from public, anon', r.sig);
  end loop;
end
$$;
