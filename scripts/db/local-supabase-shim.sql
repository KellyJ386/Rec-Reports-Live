-- Minimal stand-in for the parts of a Supabase database that migrations and
-- pgTAP tests rely on. Used ONLY by scripts/db/test-local.sh on a plain
-- Postgres where the Supabase Docker stack is not available.
-- CI and real environments use the real Supabase stack, never this file.

create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role authenticator login noinherit;
grant anon, authenticated, service_role to authenticator;
create role supabase_auth_admin nologin noinherit;

create schema if not exists auth authorization supabase_auth_admin;
create schema if not exists extensions;

create extension if not exists pgcrypto with schema extensions;
create extension if not exists btree_gist with schema extensions;
create extension if not exists citext with schema extensions;

-- Only the columns tests are allowed to depend on.
create table auth.users (
  id uuid primary key default gen_random_uuid(),
  email text unique,
  raw_app_meta_data jsonb not null default '{}'::jsonb,
  raw_user_meta_data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create function auth.uid() returns uuid language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub'
  )::uuid
$$;

create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;

create function auth.role() returns text language sql stable as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role'
  )
$$;

grant usage on schema auth to anon, authenticated, service_role;
grant execute on all functions in schema auth to anon, authenticated, service_role;
grant all on all tables in schema auth to service_role;

grant usage on schema public, extensions to anon, authenticated, service_role;
grant execute on all functions in schema extensions to anon, authenticated, service_role;

-- Supabase's classic defaults: new objects in public are granted to the API
-- roles. Migrations must not rely on this and must stay safe in spite of it.
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;
