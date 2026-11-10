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
0. The scope must exist: `location` null means the organization exists; otherwise the location must belong to that organization. A scope that doesn't exist gives `none` / false / rank 0, even for platform admins.
1. No assignment covering the scope (org scope for `location` null; org scope or that location otherwise) → `none`, and `has_permission` is **false at every level, `none` included** (it answers "is a member in this scope and has at least this level").
2. Else a `user_permissions` row for that person, module and location → its level.
3. Else a `user_permissions` row for that person and module with `location_id` null → its level.
4. Else the highest `role_default_permissions` level among the roles covering the scope; else `none`.
Overrides can raise or lower. Platform admins always get `admin`. One implementation, `private.person_effective_level(org, person, location, module)`, backs both `effective_permission` (the caller) and `person_effective_permission` (another person), so the two can't drift.

`people_roles` levels: `admin` = manage people, accounts, role assignments and user permissions; `edit` = assign job titles only; `view` = nothing extra in Phase 1. Seeded defaults: admin = `admin` on every module; manager = no `people_roles` admin (`edit`), `audit_log` none, `accidents` none, mostly `admin` on operational modules; staff = `none` on `people_roles`, `audit_log`, `accidents`, `reports`, otherwise `view`/`edit`. Filing an accident by staff must come from the Phase 4 "filer" rule, not from the `accidents` level.

**Tier rule** (enforced by RLS, so it holds for any client using the user's JWT). A user can create or remove a role assignment, create/change/remove a `user_permissions` row, change or remove an account, or change a person only when:
- they hold `people_roles` = `admin` in that scope (a location-scoped admin has no org scope, so can never touch org-scope assignments or org-wide overrides, and acts only on people assigned at their location);
- the target's highest rank anywhere in the organization is strictly below the actor's rank in scope;
- any role being granted ranks (with its scope) strictly below the actor's rank;
- **permission cap:** for `user_permissions`, the level granted is at most the actor's own effective level for that module in that scope. For a role assignment (grant or removal), every `role_default_permissions` row of that role must be at or below the actor's own effective level for its module in that scope. For custom role defaults, an org admin can set a level only up to their own organization-scope level for that module;
- **visibility:** the target must be visible to the actor (see Reads). The old "or has no assignments yet" exception is gone, so a location admin can't claim unassigned or offboarded people;
- **archived targets:** an archived person can be changed (assignments, overrides, account, person row, un-archiving) only by an organization-scope `people_roles` admin;
- **last assignment:** only an organization-scope `people_roles` admin (or a platform admin, or service code without a user JWT) can remove a person's last role assignment. It is checked at end of statement by the `role_assignments_keep_last` trigger. Location admins offboard someone by archiving them. This keeps every person visible to the location that manages them;
- the target is not themselves. Nobody changes their own roles, permissions, account or person row through the tables. The one exception is `update_own_profile` (below), which edits only `preferred_name` and `phone`.

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
| `locations` | org-scope admin | admin of that location or org-scope admin; changing `archived_at` (archive or restore) needs an org-scope admin (trigger) | no (archive) |
| `space_kinds` | `locations_spaces` >= edit at org scope | same | no (archive) |
| `spaces` | `locations_spaces` >= edit at that location | same | no (archive) |
| `space_hours`, `space_closures` | `locations_spaces` >= edit at that location | same | same |
| `roles` (custom), `role_default_permissions` (custom roles only) | org-scope admin; a default's level is capped at the admin's own org-scope level | same | defaults only |
| `job_titles` | org-scope admin | same | no (archive) |
| `person_job_titles` | `people_roles` >= edit in scope, person visible | no | same as insert |
| `people` | `people_roles` = admin at org scope (an unassigned person); everyone else onboards with `create_person_with_assignment` | tier rule | no (archive) |
| `accounts` | service_role (invite flow) | tier rule, `disabled_at` only | tier rule |
| `role_assignments` | tier rule | no; use `replace_role_assignment` | tier rule; last assignment only by org scope |
| `user_permissions` | tier rule | tier rule, `level` only | tier rule |
| `audit_log`, `platform_admins`, `modules` | no | no | no |

Platform admins pass every policy through the helpers (support needs no service-role key). A location-scoped admin can't insert into `people` directly. Onboarding goes through `create_person_with_assignment`, which is the only way to attach a first assignment to a person the caller can't already see, and only to the person that same call creates.

**Error messages.** BEFORE triggers run before RLS, so they must not describe rows the caller can't see. The role-assignment and space-hierarchy triggers first refuse a signed-in caller who is not a member of the row's organization with `42501 not allowed`. A role that doesn't exist and a role from another organization both give `42501 not allowed`. Own-org messages name no keys. The `space_hours` exclusion constraint includes `organization_id` and `location_id`, so its DETAIL (which prints the conflicting row) can only show a row of the caller's own tenant. Any new BEFORE trigger, or any constraint whose error echoes another row, must follow the same rule.

**Grants.** `anon` and `PUBLIC` have no privileges on any table or function. `authenticated` has only the table operations listed above, with column-level UPDATE grants (never `id`, `organization_id`, `location_id`, `slug`, `key`). `service_role` has select/insert/update/delete on Phase 1 tables but **no TRUNCATE, TRIGGER or REFERENCES** (also revoked in default privileges), and only SELECT on `audit_log`. Every audited table also has a `zz_audit_no_truncate` statement trigger that blocks TRUNCATE for every role, the owner included. Default privileges are revoked, so a new table or function is granted to nobody until a migration says so. Every new migration must: create the table, `enable row level security`, `revoke all ... from public, anon, authenticated`, grant exactly what its policies need, and attach the audit trigger.

### Helper functions

All are `security definer`, `stable`, `set search_path = ''`, take identity only from `auth.uid()`, and return false / 0 / `none` / empty for organizations the caller is not in. `public` ones are granted to `authenticated` and `service_role` (and so are callable via `/rpc`); `private` ones are usable in policies but not exposed by the API.

```sql
public.is_platform_admin() returns boolean
public.auth_org_ids() returns setof uuid                 -- member orgs (all for platform admin)
public.auth_location_ids() returns setof uuid            -- all locations of org-scope orgs + assigned locations
public.current_person_id(p_organization_id uuid) returns uuid   -- active account's person, or null
public.has_role(p_organization_id uuid, p_location_id uuid, p_role_key text) returns boolean
    -- location null: org-scope assignment only; else org scope or that location. True for platform admin.
    -- All four below return false / 0 / 'none' when the location is not in that organization.
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
-- internal, not granted to anyone: private.my_assignments(), private.person_max_rank(uuid),
--   private.scope_exists(uuid, uuid), private.person_effective_level(uuid, uuid, uuid, text),
--   private.can_grant_role(uuid, uuid, uuid, uuid)   -- the tier/cap rule without the visibility check
```

Policy style: wrap argument-free helpers in a subselect (`organization_id in (select public.auth_org_ids())`, `(select public.is_platform_admin())`) so Postgres evaluates them once per statement. Policies on identity tables only call these definer helpers, so they never recurse. RLS is enabled (not `force`d) on every table: the definer helpers rely on the table owner bypassing RLS.

### People RPCs (migration `20261111000500_people_rpcs`)

Both are `security definer`, `set search_path = ''`, take identity from `auth.uid()` only, raise `42501` (insufficient_privilege) when refused, and are granted to `authenticated` and `service_role` (not anon). Their writes go through the normal triggers, so the audit log records the real caller (`actor_role = authenticated`, the caller's user and person ids).

```sql
public.create_person_with_assignment(
  p_organization_id uuid, p_first_name text, p_last_name text,
  p_role_id uuid, p_location_id uuid,            -- p_location_id null = organization scope (admin role only)
  p_preferred_name text default null, p_email text default null,
  p_phone text default null, p_employee_number text default null
) returns uuid                                   -- the new person id
```
Creates the person and their first role assignment in one transaction. It checks `private.can_create_person(org)`, then `private.can_grant_role(org, new_person, role, location)`: the policy rule (tier rule, scope, rank, permission cap) minus the visibility check, which a person created moments ago can't pass. Then the `role_assignments` validation trigger runs. Any failure rolls back both rows. The caller can read both rows back afterwards. There is no service-role shortcut: without a user JWT it raises "not signed in". Server code holding the service key inserts the two rows directly. The session `role` setting is never trusted for authorization, because the API login role (`authenticator`) is a member of `service_role`.

```sql
public.update_own_profile(p_organization_id uuid, p_preferred_name text, p_phone text) returns uuid  -- caller's person id
```
For a member of the organization (active account, person not archived, at least one active assignment): sets exactly `preferred_name` and `phone` on the caller's own person row. A null or blank value clears the field. It can't change names of record, `email` (the contact/invite address), `employee_number`, `archived_at`, `organization_id`, or anything that affects access. Platform admins with no person in the org, disabled accounts, non-members and service_role without a JWT are refused.

### Admin RPCs (migration `20261111000600_security_review_fixes`)

Same standards as the people RPCs. Both refuse with `42501 not allowed`, without saying whether the row exists.

```sql
public.person_effective_permission(p_organization_id uuid, p_person_id uuid, p_location_id uuid, p_module_key text)
  returns permission_level
```
Another person's effective permission, computed exactly as `effective_permission` would for them: a disabled account, an archived person, an archived role or location, or a person with no account all give `none`. Callable by a platform admin, an org-scope `people_roles` admin, or a `people_roles` admin at a location where that person holds an assignment. It is read-only, so it writes no audit row.

```sql
public.replace_role_assignment(p_assignment_id uuid, p_role_id uuid, p_location_id uuid) returns uuid  -- new assignment id
```
Swaps one assignment for another for the same person in one transaction. Both the removal and the grant must pass `private.can_manage_role_assignment` (tier rule, scope, visibility, archived target, permission cap). It inserts the new row before deleting the old one, so the person never has zero assignments. If the person already holds the replacement, the old row is removed and the existing id is returned. The same role and scope raise `22023 nothing to change`. The insert and delete are audited normally.

### Audit log

Append-only, written by a trigger in the same transaction as every change to a Phase 1 table (details in `docs/DATA_MODEL.md`). UPDATE, DELETE and TRUNCATE raise for every role, including service_role and the owner. Only the trigger function inserts rows: neither `authenticated` nor `service_role` has INSERT, so no API key can forge an actor or timestamp. The Phase 4 "sensitive record viewed" rows will need a dedicated security-definer writer. Only someone who owns the table (the migration role) could drop or disable that trigger, so a migration that touches `audit_log` triggers needs security review. Reads of Sensitive data are not captured by triggers; Phase 4 must write those audit rows explicitly.

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
