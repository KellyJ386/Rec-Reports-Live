# Security

Baseline: OWASP ASVS Level 2, with stricter controls on incident injury details.

## Roles (pilot)

Same model as RinkReports Pro (see `docs/REUSE_INVENTORY.md`):

| Role | Scope | Rank | Default use |
| --- | --- | --- | --- |
| `super_admin` | Platform | 100 | Max Facility staff only. A row in `platform_admins`, never a tenant role assignment. |
| `admin` | Organization or location | 80 (90 at org scope) | Users, roles, settings, everything in scope |
| `manager` | Location | 50 | Configure spaces, templates, forms, schedules; review incidents |
| `staff` | Location | 10 | Own shift, own tasks, checklists, file incidents, read notices |
| custom roles | Location (defined per organization) | 1-79 | Defined per organization by org-scope admins |

- Roles only seed defaults (`role_default_permissions`). What a person can do is their effective permission (module x level), see below.
- Job titles (`job_titles`) route tasks and messages ("Lifeguard", "Front Desk"). They grant no permissions, and no policy may read them to decide access.
- Do not use `org_admin`, `facility_manager`, `gm` or `supervisor` as role keys (a check constraint rejects them). "Supervisor" is a job title.

## Access model (built in Phase 1)

**Membership.** A user is a member of an organization when they have an `accounts` row there with `disabled_at` null, their `people` row is not archived, and they hold at least one `role_assignments` row on a non-archived role (at a non-archived location, if location scoped). A `user_permissions` row alone grants nothing. A non-member sees nothing at all, including modules and system roles.

**Effective rank.** `roles.rank`, plus 10 when the assignment is organization scoped. So: org admin 90, location admin 80, manager 50, staff 10, custom 1-79, platform admin 100. A person's rank in scope is the highest of their assignments at org scope or at that location.

**Effective permission** (`effective_permission(org, location, module)`), levels `none < view < edit < admin`:
1. No assignment covering the scope (org scope for `location` null; org scope or that location otherwise) → `none`.
2. Else a `user_permissions` row for that person, module and location → its level.
3. Else a `user_permissions` row for that person and module with `location_id` null → its level.
4. Else the highest `role_default_permissions` level among the roles covering the scope; else `none`.
Overrides can raise or lower. Platform admins always get `admin`.

`people_roles` levels: `admin` = manage people, accounts, role assignments and user permissions; `edit` = assign job titles only; `view` = nothing extra in Phase 1. Seeded defaults: admin = `admin` on every module; manager = no `people_roles` admin (`edit`), `audit_log` none, `accidents` none, mostly `admin` on operational modules; staff = `none` on `people_roles`, `audit_log`, `accidents`, `reports`, otherwise `view`/`edit`. Filing an accident by staff must come from the Phase 4 "filer" rule, not from the `accidents` level.

**Tier rule** (enforced by RLS, so it holds for any client using the user's JWT). A user can create or remove a role assignment, create/change/remove a `user_permissions` row, change or remove an account, or change a person only when:
- they hold `people_roles` = `admin` in that scope (a location-scoped admin has no org scope, so can never touch org-scope assignments or org-wide overrides, and acts only on people assigned at their location);
- the target's highest rank anywhere in the organization is strictly below the actor's rank in scope;
- any role being granted ranks (with its scope) strictly below the actor's rank;
- for `user_permissions`, the level granted is at most the actor's own effective level for that module in that scope;
- the target is not themselves. Nobody changes their own roles, permissions, account or person row (self-service profile edits need a later, narrower RPC).

Consequences: an org admin (90) can create and remove location admins (80) but not other org admins; creating or removing an org admin needs a platform admin or the service role. A location admin (80) can't create another admin.

**Reads.**

| Data | Who reads |
| --- | --- |
| `organizations`, `organization_settings`, `locations`, `space_kinds`, `spaces`, `space_hours`, `space_closures`, `job_titles`, custom `roles` and their defaults | Every member of the organization (data class Public) |
| `modules`, system `roles` and their defaults | Any member of any organization |
| `people`, `role_assignments`, `person_job_titles` | Org-scope assignment holders: everyone in the org. Location-scoped users: people holding an assignment at one of their own locations, plus themselves. People with no assignments are visible only to org-scope users. |
| `accounts`, `user_permissions` | Own rows, plus people with `people_roles` = `admin` in scope (org scope: all; location: people assigned there) |
| `audit_log` | `audit_log` >= `view`: at org scope every row of the org; at a location only rows whose `location_id` is that location |
| `platform_admins` | Nobody but service_role |

**Writes.**

| Table | Insert | Update | Delete |
| --- | --- | --- | --- |
| `organizations` | service_role | org-scope admin, `name` only | service_role |
| `organization_settings` | trigger | org-scope admin | no |
| `locations` | org-scope admin | admin of that location or org-scope admin | no (archive) |
| `space_kinds` | `locations_spaces` >= edit at org scope | same | no (archive) |
| `spaces` | `locations_spaces` >= edit at that location | same | no (archive) |
| `space_hours`, `space_closures` | `locations_spaces` >= edit at that location | same | same |
| `roles` (custom), `role_default_permissions` (custom roles only) | org-scope admin | same | defaults only |
| `job_titles` | org-scope admin | same | no (archive) |
| `person_job_titles` | `people_roles` >= edit in scope, person visible | no | same as insert |
| `people` | `people_roles` = admin at org scope or any location | tier rule | no (archive) |
| `accounts` | service_role (invite flow) | tier rule, `disabled_at` only | tier rule |
| `role_assignments` | tier rule | no (delete + insert) | tier rule |
| `user_permissions` | tier rule | tier rule, `level` only | tier rule |
| `audit_log`, `platform_admins`, `modules` | no | no | no |

Platform admins pass every policy through the helpers (support needs no service-role key). A location-scoped admin who creates a person can't read the row back until it holds an assignment at their location: generate the id client-side, insert without `RETURNING` (supabase-js: no `.select()`), then insert the role assignment.

**Grants.** `anon` and `PUBLIC` have no privileges on any table or function. `authenticated` has only the table operations listed above, with column-level UPDATE grants (never `id`, `organization_id`, `location_id`, `slug`, `key`). `service_role` has full access except `audit_log` (select, insert). Default privileges are revoked, so a new table or function is granted to nobody until a migration says so. Every new migration must: create the table, `enable row level security`, `revoke all ... from public, anon, authenticated`, grant exactly what its policies need, and attach the audit trigger.

### Helper functions

All are `security definer`, `stable`, `set search_path = ''`, take identity only from `auth.uid()`, and return false / 0 / `none` / empty for organizations the caller is not in. `public` ones are granted to `authenticated` and `service_role` (and so are callable via `/rpc`); `private` ones are usable in policies but not exposed by the API.

```sql
public.is_platform_admin() returns boolean
public.auth_org_ids() returns setof uuid                 -- member orgs (all for platform admin)
public.auth_location_ids() returns setof uuid            -- all locations of org-scope orgs + assigned locations
public.current_person_id(p_organization_id uuid) returns uuid   -- active account's person, or null
public.has_role(p_organization_id uuid, p_location_id uuid, p_role_key text) returns boolean
    -- location null: org-scope assignment only; else org scope or that location. True for platform admin.
public.actor_rank(p_organization_id uuid, p_location_id uuid) returns integer   -- 0 if none, 100 platform
public.effective_permission(p_organization_id uuid, p_location_id uuid, p_module_key text) returns permission_level
public.has_permission(p_organization_id uuid, p_location_id uuid, p_module_key text, p_min_level permission_level) returns boolean

private.permitted_org_ids(p_module_key text, p_min_level permission_level) returns setof uuid
private.permitted_location_ids(p_module_key text, p_min_level permission_level) returns setof uuid
private.visible_person_ids() returns setof uuid
private.my_person_ids() returns setof uuid
private.people_admin_person_ids() returns setof uuid
private.can_create_person(p_organization_id uuid) returns boolean
private.can_manage_person(p_organization_id uuid, p_person_id uuid) returns boolean
private.can_manage_role_assignment(p_organization_id uuid, p_person_id uuid, p_role_id uuid, p_location_id uuid) returns boolean
private.can_manage_user_permission(p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text, p_level permission_level) returns boolean
-- internal, not granted to anyone: private.my_assignments(), private.person_max_rank(uuid)
```

Policy style: wrap argument-free helpers in a subselect (`organization_id in (select public.auth_org_ids())`, `(select public.is_platform_admin())`) so Postgres evaluates them once per statement. Policies on identity tables only call these definer helpers, so they never recurse. RLS is enabled (not `force`d) on every table: the definer helpers rely on the table owner bypassing RLS.

### Audit log

Append-only, written by a trigger in the same transaction as every change to a Phase 1 table (details in `docs/DATA_MODEL.md`). UPDATE, DELETE and TRUNCATE raise for every role, including service_role and the owner. Only someone who owns the table (the migration role) could drop or disable that trigger, so a migration that touches `audit_log` triggers needs security review. Reads of Sensitive data are not captured by triggers; Phase 4 must write those audit rows explicitly.

## Data classes

| Class | Examples | Who can read |
| --- | --- | --- |
| Public | Facility name, space names | Anyone in the org |
| Internal | Schedules, tasks, notices, checklists | Org members in scope |
| Restricted | Incident narrative, witness names | `manager` and above in scope, plus the filer |
| Sensitive | Injury and medical details, accident photos, contact info of injured parties | `admin`, plus managers with the accident-reports grant; every read is audited |

## Required controls

- RLS enabled on every table, with no permissive default. Helper functions (see "Helper functions") are `security definer` with a fixed `search_path`.
- MFA for `admin` tier and above; admin idle sign-out after 30 minutes.
- Rate limits on auth endpoints.
- Server-side zod validation on every mutation.
- No sensitive fields in logs or error reports.
- Secrets live only in Vercel and Supabase settings, and gitleaks runs in CI.
- Signed URLs for incident attachments, using private buckets only.

## Required tests (CI-blocking)

- pgTAP: for every table, a user in org A can't read or write org B's rows.
- pgTAP: `staff` can't read `incident_sensitive_details`.
- pgTAP: a user can't reach a location they aren't assigned to.
- Integration: a retried outbox event creates no duplicate tasks or messages.
- Integration: two overlapping bookings on one space fail.
